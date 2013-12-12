/**
 * BTree implementation
 */ 
/* Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011, 2012 Palo Alto Research Center, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. You should have received
 * a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301 USA.
 */
 
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ndn/charbuf.h>
#include <ndn/hashtb.h>

#include <ndn/btree.h>

static void
ndn_btree_update_cached_parent(struct ndn_btree *btree,
                               struct ndn_btree_internal_payload *olink,
                               ndn_btnodeid parentid);

#ifndef MYFETCH
#define MYFETCH(p, f) ndn_btree_fetchval(&((p)->f[0]), sizeof((p)->f))
#endif
unsigned
ndn_btree_fetchval(const unsigned char *p, int size)
{
    int i;
    unsigned v;
    
    for (v = 0, i = 0; i < size; i++)
        v = (v << 8) + p[i];
    return(v);
}

#ifndef MYSTORE
#define MYSTORE(p, f, v) ndn_btree_storeval(&((p)->f[0]), sizeof((p)->f), (v))
#endif
void
ndn_btree_storeval(unsigned char *p, int size, unsigned v)
{
    int i;
    
    for (i = size; i > 0; i--, v >>= 8)
        p[i-1] = v;
}

/**
 *  Minimum size of a non-empty node
 */
#define MIN_NODE_BYTES (sizeof(struct ndn_btree_node_header) + sizeof(struct ndn_btree_entry_trailer))

/**
 * Find the entry trailer associated with entry i of the btree node.
 *
 * Sets node->corrupt if a problem with the node's structure is discovered.
 * @returns entry trailer pointer, or NULL if there is a problem.
 */
static struct ndn_btree_entry_trailer *
seek_trailer(struct ndn_btree_node *node, int i)
{
    struct ndn_btree_entry_trailer *t;
    unsigned last;
    unsigned ent;
    
    if (node->corrupt || node->buf->length < MIN_NODE_BYTES)
        return(NULL);
    t = (struct ndn_btree_entry_trailer *)(node->buf->buf +
        (node->buf->length - sizeof(struct ndn_btree_entry_trailer)));
    last = MYFETCH(t, entdx);
    ent = MYFETCH(t, entsz) * NDN_BT_SIZE_UNITS;
    if (ent < sizeof(struct ndn_btree_entry_trailer)) {
        node->corrupt = __LINE__;
        return(NULL);
    }
    if (ent * (last + 1) >= node->buf->length) {
        node->corrupt = __LINE__;
        return(NULL);
    }
    if ((unsigned)i > last)
        return(NULL);
    t = (struct ndn_btree_entry_trailer *)(node->buf->buf + node->buf->length
        - (ent * (last - i))
        - sizeof(struct ndn_btree_entry_trailer));
    if (MYFETCH(t, entdx) != i) {
        node->corrupt = __LINE__;
        return(NULL);
    }    
    return(t);
}

/**
 * Get the address of the indexed entry within the node.
 *
 * payload_bytes must be divisible by NDN_BT_SIZE_UNITS.
 *
 * @returns NULL in case of error.
 */
void *
ndn_btree_node_getentry(size_t payload_bytes, struct ndn_btree_node *node, int i)
{
    struct ndn_btree_entry_trailer *t;
    size_t entry_bytes;
    
    entry_bytes = payload_bytes + sizeof(struct ndn_btree_entry_trailer);
    t = seek_trailer(node, i);
    if (t == NULL)
        return(NULL);
    if (MYFETCH(t, entsz) * NDN_BT_SIZE_UNITS != entry_bytes) {
        node->corrupt = __LINE__;
        return(NULL);
    }
    return(((unsigned char *)t) + sizeof(*t) - entry_bytes);    
}

/**
 * Get the address of entry within an internal (non-leaf) node.
 */
static struct ndn_btree_internal_payload *
ndn_btree_node_internal_entry(struct ndn_btree_node *node, int i)
{
    struct ndn_btree_internal_payload *ans;
    
    ans = ndn_btree_node_getentry(sizeof(*ans), node, i);
    if (ans == NULL)
        return(NULL);
    if (MYFETCH(ans, magic) != NDN_BT_INTERNAL_MAGIC) {
        node->corrupt = __LINE__;
        return(NULL);
    }    
    return(ans);
}

/**
 * Number of entries within the btree node
 *
 * @returns number of entries, or -1 for error
 */
int
ndn_btree_node_nent(struct ndn_btree_node *node)
{
    struct ndn_btree_entry_trailer *t;

    if (node->corrupt)
        return(-1);
    if (node->buf->length < MIN_NODE_BYTES)
        return(0);
    t = (struct ndn_btree_entry_trailer *)(node->buf->buf +
        (node->buf->length - sizeof(struct ndn_btree_entry_trailer)));
    return(MYFETCH(t, entdx) + 1);
}

/**
 * Size, in bytes, of entries within the node
 *
 * If there are no entries, returns 0.
 * This size includes the entry trailer.
 *
 * @returns size, or -1 for error
 */
int
ndn_btree_node_getentrysize(struct ndn_btree_node *node)
{
    struct ndn_btree_entry_trailer *t;

    if (node->corrupt)
        return(-1);
    if (node->buf->length < MIN_NODE_BYTES)
        return(0);
    t = (struct ndn_btree_entry_trailer *)(node->buf->buf +
        (node->buf->length - sizeof(struct ndn_btree_entry_trailer)));
    return(MYFETCH(t, entsz) * NDN_BT_SIZE_UNITS);
}

/**
 * Size, in bytes, of payloads within the node
 *
 * If there are no entries, returns 0.
 * This does not include the entry trailer, but will include padding
 * to a multiple of NDN_BT_SIZE_UNITS.
 *
 * @returns size, or -1 for error
 */
int
ndn_btree_node_payloadsize(struct ndn_btree_node *node)
{
    int ans;
    
    ans = ndn_btree_node_getentrysize(node);
    if (ans >= sizeof(struct ndn_btree_entry_trailer))
        ans -= sizeof(struct ndn_btree_entry_trailer);
    return(ans);
}

/** 
 * Node level (leaves are at level 0)
 * @returns the node level, or -1 for error
 */
int ndn_btree_node_level(struct ndn_btree_node *node)
{
    struct ndn_btree_node_header *hdr = NULL;

    if (node->corrupt || node->buf->length < sizeof(struct ndn_btree_node_header))
        return(-1);
    hdr = (struct ndn_btree_node_header *)(node->buf->buf);
    return(MYFETCH(hdr, level));
}

/**
 * Fetch the key within the indexed entry of node
 * @returns -1 in case of error
 */
int
ndn_btree_key_fetch(struct ndn_charbuf *dst,
                    struct ndn_btree_node *node,
                    int i)
{
    dst->length = 0;
    return(ndn_btree_key_append(dst, node, i));
}

/**
 * Append the key within the indexed entry of node to dst
 * @returns -1 in case of error
 */
int
ndn_btree_key_append(struct ndn_charbuf *dst,
                     struct ndn_btree_node *node,
                     int i)
{
    struct ndn_btree_entry_trailer *p = NULL;
    unsigned koff = 0;
    unsigned ksiz = 0;

    p = seek_trailer(node, i);
    if (p == NULL)
        return(-1);
    koff = MYFETCH(p, koff0);
    ksiz = MYFETCH(p, ksiz0);
    if (koff > node->buf->length)
        return(node->corrupt = __LINE__, -1);
    if (ksiz > node->buf->length - koff)
        return(node->corrupt = __LINE__, -1);
    ndn_charbuf_append(dst, node->buf->buf + koff, ksiz);
    koff = MYFETCH(p, koff1);
    ksiz = MYFETCH(p, ksiz1);
    if (koff > node->buf->length)
        return(node->corrupt = __LINE__, -1);
    if (ksiz > node->buf->length - koff)
        return(node->corrupt = __LINE__, -1);
    ndn_charbuf_append(dst, node->buf->buf + koff, ksiz);
    return(0);
}

/**
 * Compare given key with the key in the indexed entry of the node
 *
 * The comparison is a standard lexicographic one on unsigned bytes; that is,
 * there is no assumption of what the bytes actually encode.
 *
 * The special return value -9999 indicates the key is a strict prefix.
 * This does not matter to the btree lookup, but is useful for higher levels.
 *
 * @returns negative, zero, or positive to indicate less, equal, or greater
 */
int
ndn_btree_compare(const unsigned char *key,
                  size_t size,
                  struct ndn_btree_node *node,
                  int i)
{
    struct ndn_btree_entry_trailer *p = NULL;
    size_t cmplen;
    unsigned koff = 0;
    unsigned ksiz = 0;
    int res;
    
    p = seek_trailer(node, i);
    if (p == NULL)
        return(i < 0 ? 999 : -999);
    koff = MYFETCH(p, koff0);
    ksiz = MYFETCH(p, ksiz0);
    if (koff > node->buf->length)
        return(node->corrupt = __LINE__, -1);
    if (ksiz > node->buf->length - koff)
        return(node->corrupt = __LINE__, -1);
    cmplen = size;
    if (cmplen > ksiz)
        cmplen = ksiz;
    res = memcmp(key, node->buf->buf + koff, cmplen);
    if (res != 0)
        return(res);
    if (size < ksiz)
        return(-9999); /* key is a strict prefix */
    /* Compare the other part of the key */
    key += cmplen;
    size -= cmplen;
    koff = MYFETCH(p, koff1);
    ksiz = MYFETCH(p, ksiz1);
    if (koff > node->buf->length)
        return(node->corrupt = __LINE__, -1);
    if (ksiz > node->buf->length - koff)
        return(node->corrupt = __LINE__, -1);
    cmplen = size;
    if (cmplen > ksiz)
        cmplen = ksiz;
    res = memcmp(key, node->buf->buf + koff, cmplen);
    if (res != 0)
        return(res);
    if (size < ksiz)
        return(-9999); /* key is a strict prefix */
    return(size > ksiz);
}

/**
 * Search the node for the given key
 *
 * The return value is encoded as 2 * index + (found ? 1 : 0); that is, a
 * successful search returns an odd number and an unsuccessful search returns
 * an even number.  In the case of an unsuccessful search, the index indicates
 * where the item would go if it were to be inserted.
 *
 * Uses a binary search, so the keys in the node must be sorted and unique.
 *
 * @returns NDN_BT_ENCRES(index, success) indication, or -1 for an error.
 */
int
ndn_btree_searchnode(const unsigned char *key,
                     size_t size,
                     struct ndn_btree_node *node)
{
    int i, j, mid, res;
    
    if (node->corrupt)
        return(-1);
    i = 0;
    j = ndn_btree_node_nent(node);
    while (i < j) {
        mid = (i + j) >> 1;
        res =  ndn_btree_compare(key, size, node, mid);
        // printf("node = %u, i = %d, j = %d, mid = %d, res = %d\n", (int)node->nodeid, i, j, mid, res);
        if (res == 0)
            return(NDN_BT_ENCRES(mid, 1));
        if (res < 0)
            j = mid;
        else
            i = mid + 1;
    }
    if (i != j) {
        abort();
    }
    return(NDN_BT_ENCRES(i, 0));
}

/**
 * Do a btree lookup, starting from the default root.
 *
 * In the absence of errors, if *leafp is not NULL the handle for the
 * appropriate leaf node will be stored.  See ndn_btree_getnode() for
 * warning about lifetime of the resulting pointer.
 *
 * The return value is encoded as for ndn_btree_searchnode().
 *
 * @returns NDN_BT_ENCRES(index, success) indication, or -1 for an error.
 */
int
ndn_btree_lookup(struct ndn_btree *btree,
                 const unsigned char *key, size_t size,
                 struct ndn_btree_node **leafp)
{
    struct ndn_btree_node *node = NULL;
    node = ndn_btree_getnode(btree, 1, 0);
    if (node == NULL || node->corrupt)
        return(-1);
    return(ndn_btree_lookup_internal(btree, node, 0, key, size, leafp));
}

/**
 * Do a btree lookup, starting from the provided root and stopping
 * at stoplevel.
 *
 * In the absence of errors, if *ansp is not NULL the handle for the
 * appropriate node will be stored.  See ndn_btree_getnode() for
 * warning about lifetime of the resulting pointer.
 *
 * The return value is encoded as for ndn_btree_searchnode().
 *
 * @returns NDN_BT_ENCRES(index, success) indication, or -1 for an error.
 */
int
ndn_btree_lookup_internal(struct ndn_btree *btree,
                          struct ndn_btree_node *root, int stoplevel,
                          const unsigned char *key, size_t size,
                          struct ndn_btree_node **ansp)
{
    struct ndn_btree_node *node = NULL;
    struct ndn_btree_node *child = NULL;
    struct ndn_btree_internal_payload *e = NULL;
    ndn_btnodeid childid;
    int entdx;
    int level;
    int newlevel;
    int srchres;
    
    node = root;
    if (node == NULL || node->corrupt)
        return(-1);
    level = ndn_btree_node_level(node);
    if (level < stoplevel)
        return(-1);
    srchres = ndn_btree_searchnode(key, size, node);
    if (srchres < 0)
        return(-1);
    while (level > stoplevel) {
        entdx = NDN_BT_SRCH_INDEX(srchres) + NDN_BT_SRCH_FOUND(srchres) - 1;
        if (entdx < 0)
            abort();
        e = ndn_btree_node_internal_entry(node, entdx);
        if (e == NULL)
            return(-1);
        childid = MYFETCH(e, child);
        child = ndn_btree_getnode(btree, childid, node->nodeid);
        if (child == NULL)
            return(-1);
        newlevel = ndn_btree_node_level(child);
        if (newlevel != level - 1) {
            ndn_btree_note_error(btree, __LINE__);
            node->corrupt = __LINE__;
            return(-1);
        }
        node = child;
        level = newlevel;
        srchres = ndn_btree_searchnode(key, size, node);
    }
    if (ansp != NULL)
        *ansp = node;
    return(srchres);
}

/**
 * Extracts the smallest key under the node.
 *
 * @returns -1 for an error.
 */
static int
ndn_btree_smallest_key_under(struct ndn_btree *btree,
                             struct ndn_btree_node *node,
                             struct ndn_charbuf *result)
{
    struct ndn_btree_node *leaf = NULL;
    int res;
    
    res = ndn_btree_lookup_internal(btree, node, 0, NULL, 0, &leaf);
    if (res < 0 || leaf == NULL)
        return(-1);
    res = ndn_btree_key_fetch(result, leaf, 0);
    return(res);
}



/* See if we can reuse a leading portion of the key */
static void
scan_reusable(const unsigned char *key, size_t keysize,
             struct ndn_btree_node *node, int ndx, unsigned reuse[2])
{
    /* this is an optimization - leave out for now */
    /* but this is a good place to do this check... */
    if (ndx == 0 && keysize > 0 && ndn_btree_node_level(node) != 0) {
        abort();
    }
}

/**
 *  Insert a new entry into a node
 *
 * The caller is responsible for providing the correct index i, which
 * will become the index of the new entry.
 *
 * The caller is also responsible for triggering a split.
 *
 * @returns the new entry count, or -1 in case of error.
 */
int
ndn_btree_insert_entry(struct ndn_btree_node *node, int i,
                       const unsigned char *key, size_t keysize,
                       void *payload, size_t payload_bytes)
{
    size_t k, grow, minnewsize, pb, pre, post, org;
    unsigned char *to = NULL;
    unsigned char *from = NULL;
    struct ndn_btree_entry_trailer space = { { 0 } };
    struct ndn_btree_entry_trailer *t = &space;
    unsigned reuse[2] = {0, 0};
    int j, n;
    
    if (node->freelow == 0)
        ndn_btree_chknode(node);
    if (node->corrupt)
        return(-1);
    if (keysize > NDN_BT_MAX_KEY_SIZE)
        return(-1);
    pb = (payload_bytes + NDN_BT_SIZE_UNITS - 1)
         / NDN_BT_SIZE_UNITS
         * NDN_BT_SIZE_UNITS;
    n = ndn_btree_node_nent(node);
    if (i > n)
        return(-1);
    if (n == 0) {
        org = node->buf->length;
        k = pb + sizeof(struct ndn_btree_entry_trailer);
    }
    else {
        unsigned char *x = ndn_btree_node_getentry(pb, node, 0);
        if (x == NULL) return(-1);
        org = x - node->buf->buf;
        k = ndn_btree_node_getentrysize(node);
    }
    if (k != pb + sizeof(struct ndn_btree_entry_trailer))
        return(-1);
    scan_reusable(key, keysize, node, i, reuse);
    if (reuse[1] != 0) {
        MYSTORE(t, koff0, reuse[0]);
        MYSTORE(t, ksiz0, reuse[1]);
        MYSTORE(t, koff1, node->freelow);
        MYSTORE(t, ksiz1, keysize - reuse[1]);
    }
    else {
        MYSTORE(t, koff0, node->freelow);
        MYSTORE(t, ksiz0, keysize);
    }
    MYSTORE(t, level, ndn_btree_node_level(node));
    MYSTORE(t, entsz, k / NDN_BT_SIZE_UNITS);
    if (keysize != reuse[1] && node->clean > node->freelow)
        node->clean = node->freelow;
    minnewsize = (n + 1) * k + node->freelow + keysize - reuse[1];
    minnewsize = (minnewsize + NDN_BT_SIZE_UNITS - 1)
                 / NDN_BT_SIZE_UNITS
                 * NDN_BT_SIZE_UNITS;
    pre = i * k;        /* # bytes of entries before the new one */
    post = (n - i) * k; /* # bytes of entries after the new one */
    if (minnewsize <= node->buf->length) {
        /* no expansion needed, but need to slide pre bytes down */
        to = node->buf->buf + org - k;
        if (node->clean > org - k)
            node->clean = org - k;
        memmove(to, to + k, pre);
        /* Set pointer to empty space for new entry */
        to += pre;
    }
    else {
        /* Need to expand */
        grow = minnewsize - node->buf->length;
        if (NULL == ndn_charbuf_reserve(node->buf, grow))
            return(-1);
        to = node->buf->buf + minnewsize - (pre + k + post);
        from = node->buf->buf + org;
        if (node->clean > org)
            node->clean = org;
        node->buf->length = minnewsize;
        memmove(to + pre + k, from + pre, post);
        memmove(to, from, pre);
        /* Rarely, we move pre down and post up - skip this fill if so. */
        if (to > from)
            memset(from, 0x33, to - from);
        to = to + pre;
    }
    /* Copy in bits of new entry */
    memset(to, 0, k);
    memmove(to, payload, payload_bytes);
    memmove(to + pb, t, sizeof(*t));
    /* Fix up the entdx in the relocated entries */
    for (j = i, to = to + pb; j <= n; j++, to += k) {
        t = (void*)to;
        MYSTORE(t, entdx, j);
    }
    /* Finally, copy the (non-shared portion of the) key */
    to = node->buf->buf + node->freelow;
    memmove(to, key + reuse[0], keysize - reuse[1]);
    node->freelow += keysize - reuse[1];
    return(n + 1);
}

/**
 *  Remove an entry from a btree node
 *
 * The caller is responsible for triggering a merge.
 *
 * @returns the new entry count, or -1 in case of error.
 */
int
ndn_btree_delete_entry(struct ndn_btree_node *node, int i)
{
    struct ndn_btree_entry_trailer *t;
    unsigned char *to;
    size_t k, off;
    int j;
    int n;
    
    if (node->corrupt)
        return(-1);
    n = ndn_btree_node_nent(node);
    if (i >= n)
        return(-1);
    if (n == 1) {
        /* Removing the last entry */
        struct ndn_btree_node_header *hdr;
        hdr = (void*)node->buf->buf;
        k = sizeof(*hdr) + MYFETCH(hdr, extsz) * NDN_BT_SIZE_UNITS;
        node->buf->length = node->freelow = k;
        if (k < node->clean)
           node->clean = k;
        return(0);
    }
    k = ndn_btree_node_getentrysize(node);
    off = node->buf->length - k * (n - i);
    to = node->buf->buf + off;
    memmove(to, to + k, k * (n - i - 1));
    node->buf->length -= k;
    n -= 1;
    if (off < node->clean)
        node->clean = off;
    /* Fix up the entdx in the relocated entries */
    for (j = i; j < n; j++, to += k) {
        t = (void*)(to + k - sizeof(*t));
        MYSTORE(t, entdx, j);
    }
    return(n);
}

#if 0
#define MSG(fmt, ...) fprintf(stderr, fmt "\n", __VA_ARGS__)
#else
#define MSG(fmt, ...) ((void)0)
#endif

/**
 *  Given an old root, add a level to the tree to prepare for a split.
 *
 *  @returns node with a new nodeid, new singleton root, and the old contents.
 */
static struct ndn_btree_node *
ndn_btree_grow_a_level(struct ndn_btree *btree, struct ndn_btree_node *node)
{
    struct ndn_btree_internal_payload link = {{NDN_BT_INTERNAL_MAGIC}};
    struct ndn_btree_node *child = NULL;
    struct ndn_charbuf *t = NULL;
    int level;
    int res;
    
    level = ndn_btree_node_level(node);
    if (level < 0)
        return(NULL);
    child = ndn_btree_getnode(btree, btree->nextnodeid++, node->nodeid);
    if (child == NULL)
        return(NULL);
    res = ndn_btree_prepare_for_update(btree, child);
    if (res < 0)
        ndn_btree_note_error(btree, __LINE__);
    res = ndn_btree_prepare_for_update(btree, node);
    if (res < 0)
        ndn_btree_note_error(btree, __LINE__);
    child->clean = 0;
    node->clean = 0;
    t = child->buf;
    child->buf = node->buf;
    node->buf = t;
    res = ndn_btree_init_node(node, level + 1, 'R', 0); // XXX - arbitrary extsz
    if (res < 0)
        ndn_btree_note_error(btree, __LINE__);
    MYSTORE(&link, child, child->nodeid);
    res = ndn_btree_insert_entry(node, 0, NULL, 0, &link, sizeof(link));
    if (res < 0)
        ndn_btree_note_error(btree, __LINE__);
    child->parent = node->nodeid;
    MSG("New root %u at level %d over node %u (%d errors)",
        (unsigned)node->nodeid, level + 1,
        (unsigned)child->nodeid, btree->errors);
    return(child);
}

/**
 *  If the root is a singleton and not a leaf, remove a level.
 *
 *  @return 0 if nothing done, 1 if the root changed, or -1 for error.
 */
static int
ndn_btree_shrink_a_level(struct ndn_btree *btree)
{
    struct ndn_btree_internal_payload *olink = NULL;
    struct ndn_btree_node *child = NULL;
    struct ndn_btree_node *root = NULL;
    struct ndn_charbuf *key = NULL;
    void *payload = NULL;
    int level;
    int i, n;
    int pb;
    int res;
    
    root = ndn_btree_getnode(btree, 1, 0);
    if (root == NULL)
        return(-1);
    level = ndn_btree_node_level(root);
    if (level == 0)
        return(0);
    n = ndn_btree_node_nent(root);
    if (n != 1)
        return(0);
    olink = ndn_btree_node_internal_entry(root, 0);
    if (olink == NULL) goto Bail;
    child = ndn_btree_getnode(btree, MYFETCH(olink, child), root->parent);
    if (child == NULL) goto Bail;
    pb = ndn_btree_node_payloadsize(child);
    n = ndn_btree_node_nent(child);
    level = ndn_btree_node_level(child);
    res = ndn_btree_prepare_for_update(btree, root);
    if (res < 0) goto Bail;
    res = ndn_btree_prepare_for_update(btree, child);
    if (res < 0) goto Bail;
    res = ndn_btree_init_node(root, level, 'R', 0); // XXX - arbitrary extsz
    if (res < 0) goto Bail;
    key = ndn_charbuf_create();
    for (i = 0; i < n; i++) {
        res = ndn_btree_key_fetch(key, child, i);
        payload = ndn_btree_node_getentry(pb, child, i);
        if (res < 0 || payload == NULL) goto Bail;
        res = ndn_btree_insert_entry(root, i, key->buf, key->length, payload, pb);
        if (res < 0) goto Bail;
        if (level > 0)
            ndn_btree_update_cached_parent(btree, payload, root->nodeid);
    }
    ndn_charbuf_destroy(&key);
    child->parent = 0;
    child->clean = 0;
    child->freelow = 0;
    ndn_charbuf_reset(child->buf);
    return(1);
Bail:
    ndn_charbuf_destroy(&key);
    ndn_btree_note_error(btree, __LINE__);
    return(-1);
}

/**
 * Test for an oversize node
 *
 * This takes into account both the size of a node and the count of
 * entries.
 *
 * @returns a boolean result.
 */
int
ndn_btree_oversize(struct ndn_btree *btree, struct ndn_btree_node *node)
{
    return(ndn_btree_unbalance(btree, node) > 0);
}

/**
 * Test for an unbalanced node
 *
 * This takes into account both the size of a node and the count of
 * entries.
 *
 * @returns 1 if node is too big, -1 if too small, 0 if just right.
 */
int
ndn_btree_unbalance(struct ndn_btree *btree, struct ndn_btree_node *node)
{
    int n;
    
    n = ndn_btree_node_nent(node);
    if (n > 4 && btree->nodebytes != 0 && node->buf->length > btree->nodebytes)
        return(1);
    if (ndn_btree_node_level(node) == 0 && btree->full0 > 0) {
        if (n > btree->full0)
            return(1);
        if (2 * n < btree->full0)
            return(-1);
    }
    if (n > btree->full)
        return(1);
    if (2 * n < btree->full)
        return(-1);
    return(0);
}

/**
 * Update the cached parent pointer if necessary
 */
static void
ndn_btree_update_cached_parent(struct ndn_btree *btree,
                               struct ndn_btree_internal_payload *olink,
                               ndn_btnodeid parentid)
{
    struct ndn_btree_node *chld = NULL;
    
    if (MYFETCH(olink, magic) == NDN_BT_INTERNAL_MAGIC)
        chld = ndn_btree_rnode(btree, MYFETCH(olink, child));
    if (chld != NULL) {
        if (chld->parent != parentid) {
            MSG("Parent of %u changed from %u to %u",
                (unsigned)chld->nodeid,
                (unsigned)chld->parent,
                (unsigned)parentid);
        }
        chld->parent = parentid;
    }
}

/**
 * Split a btree node
 *
 * This creates a new sibling, and distributes the entries of node
 * between the two.
 *
 * The node's parent gains a child; if in doing so, it grows too large,
 * the parent will be noted in btree->nextsplit for the caller to deal with.
 *
 * @returns 0 for success, -1 in case of error.
 */
int
ndn_btree_split(struct ndn_btree *btree, struct ndn_btree_node *node)
{
    int i, j, k, n, pb, res;
    struct ndn_btree_node newnode = { 0 };
    struct ndn_btree_node *a[2] = {NULL, NULL};
    struct ndn_btree_node *parent = NULL;
    void *payload = NULL;
    struct ndn_charbuf *key = NULL;
    struct ndn_btree_internal_payload link = {{NDN_BT_INTERNAL_MAGIC}};
    struct ndn_btree_internal_payload *olink = NULL;
    int level;
    
    if (btree->nextsplit == node->nodeid)
        btree->nextsplit = 0;
    n = ndn_btree_node_nent(node);
    if (n < 4)
        return(-1);
    res = ndn_btree_prepare_for_update(btree, node);
    if (res < 0)
        return(-1);
    if (node->nodeid == 1) {
        node = ndn_btree_grow_a_level(btree, node);
        if (node == NULL)
            abort();
        if (node->nodeid == 1 || node->parent != 1 || ndn_btree_node_nent(node) != n)
            abort();
    }
    parent = ndn_btree_getnode(btree, node->parent, 0);
    if (parent == NULL || ndn_btree_node_nent(parent) < 1)
        return(node->corrupt = __LINE__, -1); /* Must have a parent to split. */
    if (ndn_btree_node_payloadsize(parent) != sizeof(link))
        return(node->corrupt = __LINE__, -1);
    res = ndn_btree_prepare_for_update(btree, parent);
    if (res < 0)
        return(-1);
    pb = ndn_btree_node_payloadsize(node);
    level = ndn_btree_node_level(node);
    MSG("Splitting %d entries of node %u, child of %u", n,
        (unsigned)node->nodeid, (unsigned)node->parent);
    /* Create two new nodes to hold the split-up content */
    /* One of these is temporary, and will get swapped in for original node */
    newnode.buf = ndn_charbuf_create();
    if (newnode.buf == NULL)
        goto Bail;
    newnode.nodeid = node->nodeid;
    a[0] = &newnode;
    /* The other new node is created anew */
    a[1] = ndn_btree_getnode(btree, btree->nextnodeid++, 0);
    if (a[1] == NULL)
        goto Bail;
    res = ndn_btree_prepare_for_update(btree, a[1]);
    if (res < 0)
        return(-1);
    for (k = 0; k < 2; k++) {
        if (ndn_btree_node_nent(a[k]) != 0)
            goto Bail;
        res = ndn_btree_init_node(a[k], ndn_btree_node_level(node), 0, 0);
        if (res < 0)
            goto Bail;
        a[k]->parent = node->parent;
    }
    /* Distribute the entries into the two new nodes */
    key = ndn_charbuf_create();
    if (key == NULL) goto Bail;
    for (i = 0, j = 0, k = 0, res = 0; i < n; i++, j++) {
        res = ndn_btree_key_fetch(key, node, i);
        if (i == n / 2) {
            k = 1; j = 0; /* switch to second half */
            if (level > 0)
                key->length = 0; /* internal nodes need one fewer key */
        }
        payload = ndn_btree_node_getentry(pb, node, i);
        if (res < 0 || payload == NULL)
            goto Bail;
        res = ndn_btree_insert_entry(a[k], j, key->buf, key->length, payload, pb);
        MSG("Splitting [%u %d] into [%u %d] (res = %d)",
            (unsigned)node->nodeid, i, (unsigned)a[k]->nodeid, j, res);
        if (res < 0)
            goto Bail;
        if (level > 0) {
            /* Fix up the cached parent pointer if necessary */
            ndn_btree_update_cached_parent(btree, payload, a[k]->nodeid);
        }
    }
    /* Link the new node into the parent */
    res = ndn_btree_key_fetch(key, node, n / 2); /* Splitting key. */
    if (res < 0)
        goto Bail;
    /*
     * Note - we could abbreviate the splitting key to something less than
     * the first key of the subtree under a[1] and greater than
     * the last key of the subtree under a[0].  But we don't do that yet.
     */
    MYSTORE(&link, child, a[1]->nodeid);
    res = ndn_btree_searchnode(key->buf, key->length, parent);
    if (res < 0)
        goto Bail;
    if (NDN_BT_SRCH_FOUND(res) && key->length != 0)
        goto Bail;
    i = NDN_BT_SRCH_INDEX(res);
    olink = ndn_btree_node_internal_entry(parent, i - 1);
    if (olink == NULL || MYFETCH(olink, child) != a[0]->nodeid) {
        node->corrupt = __LINE__;
        parent->corrupt = __LINE__;
        goto Bail;
    }
    /* It look like we are in good shape to commit the changes */
    res = ndn_btree_insert_entry(parent, i,
                                 key->buf, key->length,
                                 &link, sizeof(link));
    if (res < 0) {
        parent->corrupt = __LINE__;
        goto Bail;
    }
    else if (ndn_btree_oversize(btree, parent)) {
        btree->missedsplit = btree->nextsplit;
        btree->nextsplit = parent->nodeid;
    }
    node->clean = 0;
    ndn_charbuf_destroy(&node->buf);
    node->buf = newnode.buf;
    newnode.buf = NULL;
    res = ndn_btree_chknode(node); /* Update freelow */
    if (res < 0)
        goto Bail;
    ndn_charbuf_destroy(&key);
    return(0);
Bail:
    ndn_charbuf_destroy(&newnode.buf);
    ndn_charbuf_destroy(&key);
    ndn_btree_note_error(btree, __LINE__);
    return(-1);
}

/**
 * Search for nodeid in parent
 *
 * This does not rely on the keys, but just scans the entries.
 *
 * @returns the index within parent, or -1 if there is an error.
 */
int
ndn_btree_index_in_parent(struct ndn_btree_node *parent, ndn_btnodeid nodeid)
{
    struct ndn_btree_internal_payload *e = NULL;
    int i, n;
    
    n = ndn_btree_node_nent(parent);
    for (i = n - 1; i >= 0; i--) {
        e = ndn_btree_node_internal_entry(parent, i);
        if (e == NULL)
            break;
        if (MYFETCH(e, child) == nodeid)
            return(i);
    }
    return(-1);
} 

/**
 * Eliminate a node by combining it with a sibling
 *
 * In success case, the node will be emptied out completely, and
 * The parent node will have one fewer child.
 * It is possible for a sibling to need splitting; in this case
 * btree->nextsplit will be set accordingly.
 *
 * btree->nextspill will be set if there are more nodes to spill.
 *
 * @returns 0 for success, 1 if deferred to left, -1 if error.
 */
int
ndn_btree_spill(struct ndn_btree *btree, struct ndn_btree_node *node)
{
    struct ndn_btree_internal_payload *e = NULL;
    struct ndn_btree_node *parent = NULL;
    struct ndn_btree_node *s = NULL;
    void *payload = NULL;
    struct ndn_charbuf *key = NULL;
    int i, j, n, pb, ndx, res;
    int level;
    
    if (btree->nextspill == node->nodeid)
        btree->nextspill = 0;
    n = ndn_btree_node_nent(node);
    if (node->nodeid == 1) {
        /* We may be able to eliminate a level */
        res = ndn_btree_shrink_a_level(btree);
        if (res == 1)
            res = 0;
        return(res);
    }
    res = ndn_btree_prepare_for_update(btree, node);
    if (res < 0)
        return(-1);
    parent = ndn_btree_getnode(btree, node->parent, 0);
    if (parent == NULL)
        return(-1); /* only the root has no parent */
    res = ndn_btree_prepare_for_update(btree, parent);
    if (res < 0)
        return(-1);
    pb = ndn_btree_node_payloadsize(node);
    ndx = ndn_btree_index_in_parent(parent, node->nodeid);
    MSG("Spilling %d entries of node %u, child %d of %u", n,
        (unsigned)node->nodeid, ndx, (unsigned)node->parent);
    if (ndx == 0) {
        /* No place to spill to the left; shift attention to right sibling */
        e = ndn_btree_node_internal_entry(parent, ndx + 1);
        if (e != NULL) {
            btree->nextspill = MYFETCH(e, child);
            return(1);
        }
        return(-1);
    }
    e = ndn_btree_node_internal_entry(parent, ndx - 1);
    if (e == NULL)
        return(-1);
    s = ndn_btree_getnode(btree, MYFETCH(e, child), 0);
    if (s == NULL)
        return(-1);
    res = ndn_btree_prepare_for_update(btree, s);
    if (res < 0)
        return(-1);
    level = ndn_btree_node_level(node);
    key = ndn_charbuf_create();
    for (i = 0, j = ndn_btree_node_nent(s); i < n; i++, j++) {
        if (i == 0 && level > 0)
            res = ndn_btree_smallest_key_under(btree, node, key);
        else
            res = ndn_btree_key_fetch(key, node, i);
        payload = ndn_btree_node_getentry(pb, node, i);
        if (res < 0 || payload == NULL)
            goto Bail;
        res = ndn_btree_insert_entry(s, j, key->buf, key->length, payload, pb);
        if (res < 0)
            goto Bail;
        if (level > 0)
            ndn_btree_update_cached_parent(btree, payload, s->nodeid);
    }
    res = ndn_btree_delete_entry(parent, ndx);
    if (res < 0)
        goto Bail;
    node->parent = 0;
    node->clean = 0;
    node->freelow = 0;
    ndn_charbuf_reset(node->buf);
    ndn_charbuf_destroy(&key);
    res = ndn_btree_unbalance(btree, s);
    if (res > 0) {
        btree->missedsplit = btree->nextsplit;
        btree->nextsplit = s->nodeid;
        /* Do not spill parent, since sibling split will fix it up. */
        return(0);
    }
    res = ndn_btree_unbalance(btree, parent);
    if (res < 0)
        btree->nextspill = parent->nodeid;
    return(0);
Bail:
    ndn_charbuf_destroy(&key);
    ndn_btree_note_error(btree, __LINE__);
    return(-1);
}

#undef MSG

/**
 * Find the leaf that comes after the given node
 *
 * This may be used to walk though the leaf nodes in order.
 * If success, sets *ansp to a leaf pointer or NULL
 * @returns 0 if at end, 1 if *ansp is not NULL, -1 if error.
 */
int
ndn_btree_next_leaf(struct ndn_btree *btree,
                    struct ndn_btree_node *node,
                    struct ndn_btree_node **ansp)
{
    struct ndn_btree_internal_payload *e = NULL;
    struct ndn_btree_node *p = NULL;
    struct ndn_btree_node *q = NULL;
    struct ndn_btree_node *parent = NULL;
    int i;
    int n;
    int ans;
    int res;
    struct ndn_charbuf *key = NULL;
    
    ans = -1;
    key = ndn_charbuf_create();
    p = node;
    n = ndn_btree_node_nent(p);
    if (n < 1 && p->parent != 0)
        goto Bail;
    while (p->parent != 0) {
        res = ndn_btree_key_fetch(key, p, n - 1);
        if (res < 0)
            goto Bail;
        parent = ndn_btree_getnode(btree, p->parent, 0);
        if (parent == NULL)
            goto Bail;
        res = ndn_btree_searchnode(key->buf, key->length, parent);
        if (res < 0)
            goto Bail;
        n = ndn_btree_node_nent(parent);
        if (n < 1)
            goto Bail;
        i = NDN_BT_SRCH_INDEX(res) + NDN_BT_SRCH_FOUND(res) - 1;
        if (i < n - 1) {
            /* We have found the ancestor that has the leaf we are after. */
            q = NULL;
            e = ndn_btree_node_internal_entry(parent, i + 1);
            q = ndn_btree_getnode(btree, MYFETCH(e, child), parent->nodeid);
            if (q == NULL)
                goto Bail;
            res = ndn_btree_lookup_internal(btree, q, 0, key->buf, 0, ansp);
            if (res < 0)
                goto Bail;
            ans = 1;
            break;
        }
        p = parent;
        /* n is aleady set to ndn_btree_node_nent(p) */
    }
    if (ans != 1) {
        *ansp = NULL;
        ans = 0;
    }
Bail:
    ndn_charbuf_destroy(&key);
    return(ans);
}

/**
 * Find the leaf that comes before the given node
 *
 * This may be used to walk though the leaf nodes in reverse order.
 * If success, sets *ansp to a leaf pointer or NULL
 * @returns 0 if at beginning, 1 if *ansp is not NULL, -1 if error.
 */
int
ndn_btree_prev_leaf(struct ndn_btree *btree,
                    struct ndn_btree_node *node,
                    struct ndn_btree_node **ansp)
{
    struct ndn_btree_internal_payload *e = NULL;
    struct ndn_btree_node *p = NULL;
    struct ndn_btree_node *q = NULL;
    struct ndn_btree_node *parent = NULL;
    int ans;
    int i;
    
    ans = -1;
    p = node;
    while (p->parent != 0) {
        parent = ndn_btree_getnode(btree, p->parent, 0);
        if (parent == NULL)
            goto Bail;
        i = ndn_btree_index_in_parent(parent, p->nodeid);
        if (i < 0) goto Bail;
        if (i > 0) {
            /* we can stop walking up the tree now, and walk down instead */
            for (q = parent; ndn_btree_node_level(q) != 0;) {
                e = ndn_btree_node_internal_entry(q, i - 1);
                q = ndn_btree_getnode(btree, MYFETCH(e, child), q->nodeid);
                if (q == NULL)
                    goto Bail;
                i = ndn_btree_node_nent(q);
            }
            *ansp = q;
            ans = 1;
            break;
        }
        p = parent;
    }
    if (ans != 1) {
        *ansp = NULL;
        ans = 0;
    }
Bail:
    return(ans);
}

#define NDN_BTREE_MAGIC 0x53ade78
#define NDN_BTREE_VERSION 1

/**
 *  Write out any pending changes, mark the node clean, and release node iodata
 *
 * Retains the cached node data in memory.
 *
 * @returns 0 for success or -1 for error.
 */
int
ndn_btree_close_node(struct ndn_btree *btree, struct ndn_btree_node *node)
{
    int res = 0;
    struct ndn_btree_io *io = btree->io;
    
    if (node->corrupt)
        res = -1;
    else if (node->iodata != NULL && io != NULL) {
        res = io->btwrite(io, node);
        if (res < 0)
            ndn_btree_note_error(btree, __LINE__);
        else
            node->clean = node->buf->length;
        res |= io->btclose(io, node);
        if (res < 0)
            ndn_btree_note_error(btree, __LINE__);
    }
    else if (io != NULL && node->clean != node->buf->length) {
        res = -1;
        ndn_btree_note_error(btree, __LINE__);
    }
    return(res);
}

static void
finalize_node(struct hashtb_enumerator *e)
{
    struct ndn_btree *btree = hashtb_get_param(e->ht, NULL);
    struct ndn_btree_node *node = e->data;
    
    if (btree->magic != NDN_BTREE_MAGIC)
        abort();
    ndn_btree_close_node(btree, node);
    ndn_charbuf_destroy(&node->buf);
}

/**
 * Keep count of noticed errors
 *
 * Do this in one place so it is easy to set a breakpoint.
 */
void
ndn_btree_note_error(struct ndn_btree *bt, int info)
{
    bt->errors++;
}

/**
 * Create a new btree handle, not attached to any external files
 * @returns new handle, or NULL in case of error.
 */
struct ndn_btree *
ndn_btree_create(void)
{
    struct ndn_btree *ans;
    struct hashtb_param param = {0};
    
    ans = calloc(1, sizeof(*ans));
    if (ans != NULL) {
        ans->magic = NDN_BTREE_MAGIC;
        param.finalize_data = ans;
        param.finalize = &finalize_node;
        ans->resident = hashtb_create(sizeof(struct ndn_btree_node), &param);
        if (ans->resident == NULL) {
            free(ans);
            return(NULL);
        }
        ans->errors = 0;
        ans->io = NULL;
        ans->nextnodeid = 1;  /* This will be the root */
        ans->full = ans->full0 = 19;
    }
    return(ans);
}

/**
 * Destroys a btree handle, shutting things down cleanly.
 * @returns a negative value in case of error.
 */
int
ndn_btree_destroy(struct ndn_btree **pbt)
{
    struct ndn_btree *bt = *pbt;
    int res = 0;
    
    if (bt == NULL)
        return(0);
    *pbt = NULL;
    if (bt->magic != NDN_BTREE_MAGIC)
        abort();
    hashtb_destroy(&bt->resident);
    if (bt->errors != 0)
        res = -(bt->errors & 1023);
    if (bt->io != NULL)
        res |= bt->io->btdestroy(&bt->io);
    free(bt);
    return(res);
}

/**
 *  Initialize the btree node
 *
 * It is the caller's responsibility to be sure that the node does not
 * contain any useful information.
 * 
 * Leaves alone nodeid, iodata, and activity fields.
 *
 * @returns -1 for error, 0 for success
 */
int
ndn_btree_init_node(struct ndn_btree_node *node,
                    int level, unsigned char nodetype, unsigned char extsz)
{
    struct ndn_btree_node_header *hdr = NULL;
    size_t bytes;
    
    if (node->corrupt)
        return(-1);
    bytes = sizeof(*hdr) + extsz * NDN_BT_SIZE_UNITS;
    node->clean = 0;
    node->buf->length = 0;
    hdr = (struct ndn_btree_node_header *)ndn_charbuf_reserve(node->buf, bytes);
    if (hdr == NULL) return(-1);
    memset(hdr, 0, bytes);
    MYSTORE(hdr, magic, NDN_BTREE_MAGIC);
    MYSTORE(hdr, version, NDN_BTREE_VERSION);
    MYSTORE(hdr, nodetype, nodetype);
    MYSTORE(hdr, level, level);
    MYSTORE(hdr, extsz, extsz);
    node->buf->length = bytes;
    node->freelow = bytes;
    node->parent = 0;
    return(0);
}

#define NDN_BTREE_MAX_NODE_BYTES (8U<<20)

/**
 * Access a btree node, creating or reading it if necessary
 *
 * Care should be taken to not store the node handle in data structures,
 * since it will become invalid when the node gets flushed from the
 * resident cache.
 *
 * @returns node handle
 */
struct ndn_btree_node *
ndn_btree_getnode(struct ndn_btree *bt,
                  ndn_btnodeid nodeid,
                  ndn_btnodeid parentid)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_btree_node *node = NULL;
    int res;

    if (bt->magic != NDN_BTREE_MAGIC)
        abort();
    hashtb_start(bt->resident, e);
    res = hashtb_seek(e, &nodeid, sizeof(nodeid), 0);
    node = e->data;
    if (res == HT_NEW_ENTRY) {
        node->nodeid = nodeid;
        node->buf = ndn_charbuf_create();
        bt->cleanreq++;
        if (node->buf == NULL) {
            ndn_btree_note_error(bt, __LINE__);
            node->corrupt = __LINE__;
        }
        if (bt->io != NULL) {
            res = bt->io->btopen(bt->io, node);
            if (res < 0) {
                ndn_btree_note_error(bt, __LINE__);
                node->corrupt = __LINE__;
            }
            else {
                res = bt->io->btread(bt->io, node, NDN_BTREE_MAX_NODE_BYTES);
                if (res < 0)
                    ndn_btree_note_error(bt, __LINE__);
                else {
                    node->clean = node->buf->length;
                    if (-1 == ndn_btree_chknode(node))
                        ndn_btree_note_error(bt, __LINE__);
                    node->activity = NDN_BT_ACTIVITY_READ_BUMP;
                    if (bt->io->openfds >= NDN_BT_OPEN_NODES_LIMIT) {
                        /* having read in the node, it is safe to close it */
                        res = bt->io->btclose(bt->io, node);
                         if (res < 0)
                            ndn_btree_note_error(bt, __LINE__);
                    }
                }
            }
        }
    }
    if (node != NULL && node->nodeid != nodeid)
        abort();
    hashtb_end(e);
    if (node != NULL && node->parent == 0)
        node->parent = parentid;
    node->activity += NDN_BT_ACTIVITY_REFERENCE_BUMP;
    return(node);
}

/**
 * Access a btree node that is already resident
 *
 * Care should be taken to not store the node handle in data structures,
 * since it will become invalid when the node gets flushed from the
 * resident cache.
 *
 * This call does not bump the activity counter.
 *
 * @returns node handle, or NULL if the node is not currently resident.
 */
struct ndn_btree_node *
ndn_btree_rnode(struct ndn_btree *bt, ndn_btnodeid nodeid)
{
    return(hashtb_lookup(bt->resident, &nodeid, sizeof(nodeid)));
}

/**
 * Check a node for internal consistency
 *
 * Sets or clears node->corrupt as appropriate.
 * In case of success, sets the correct value for node->freelow
 *
 * @returns old value of node->corrupt if the node looks OK, otherwise -1
 */
int
ndn_btree_chknode(struct ndn_btree_node *node)
{
    unsigned freelow = 0;
    unsigned freemax = 0;
    unsigned strbase = sizeof(struct ndn_btree_node_header);
    struct ndn_btree_node_header *hdr = NULL;
    unsigned lev = 0;
    unsigned entsz = 0;
    unsigned saved_corrupt;
    struct ndn_btree_entry_trailer *p = NULL;
    int i;
    int nent;
    unsigned koff;
    unsigned ksiz;
    
    if (node == NULL)
        return(-1);
    saved_corrupt = node->corrupt;
    node->corrupt = 0;
    if (node->buf == NULL)
        return(node->corrupt = __LINE__, -1);
    if (node->buf->length == 0)
        return(node->freelow = 0, node->corrupt = 0, 0);
    if (node->buf->length < sizeof(struct ndn_btree_node_header))
        return(node->corrupt = __LINE__, -1);
    hdr = (struct ndn_btree_node_header *)node->buf->buf;
    if (MYFETCH(hdr, magic) != NDN_BTREE_MAGIC)
        return(node->corrupt = __LINE__, -1);
    if (MYFETCH(hdr, version) != NDN_BTREE_VERSION)
        return(node->corrupt = __LINE__, -1);
    /* nodetype values are not checked at present */
    lev = MYFETCH(hdr, level);
    strbase += MYFETCH(hdr, extsz) * NDN_BT_SIZE_UNITS;
    if (strbase > node->buf->length)
        return(node->corrupt = __LINE__, -1);
    if (strbase == node->buf->length)
        return(node->freelow = strbase, saved_corrupt); /* no entries */
    nent = ndn_btree_node_nent(node);
    for (i = 0; i < nent; i++) {
        unsigned e;
        p = seek_trailer(node, i);
        if (p == NULL)
            return(-1);
        e = MYFETCH(p, entsz);
        if (i == 0) {
            freemax = ((unsigned char *)p) - node->buf->buf;
            entsz = e;
        }
        if (e != entsz)
            return(node->corrupt = __LINE__, -1);
        if (MYFETCH(p, level) != lev)
            return(node->corrupt = __LINE__, -1);
        koff = MYFETCH(p, koff0);
        ksiz = MYFETCH(p, ksiz0);
        if (koff < strbase && ksiz != 0)
            return(node->corrupt = __LINE__, -1);
        if (koff > freemax)
            return(node->corrupt = __LINE__, -1);
        if (ksiz > freemax - koff)
            return(node->corrupt = __LINE__, -1);
        if (koff + ksiz > freelow)
            freelow = koff + ksiz;
        koff = MYFETCH(p, koff1);
        ksiz = MYFETCH(p, ksiz1);
        if (koff < strbase && ksiz != 0)
            return(node->corrupt = __LINE__, -1);
        if (koff > freemax)
            return(node->corrupt = __LINE__, -1);
        if (ksiz > freemax - koff)
            return(node->corrupt = __LINE__, -1);
        if (koff + ksiz > freelow)
            freelow = koff + ksiz;
    }
    if (node->freelow != freelow)
        node->freelow = freelow; /* set a break here to check for fixups */
    return(saved_corrupt);
}

/**
 *  Get ready to update a btree node
 *
 * If applicable, open the node so that it will be
 * in a good state to write later on.
 *
 * @returns 0 if OK, -1 for error.
 */
int
ndn_btree_prepare_for_update(struct ndn_btree *bt, struct ndn_btree_node *node)
{
    int res = 0;
    
    if (node->freelow == 0)
        ndn_btree_chknode(node);
    if (node->corrupt)
        return(-1);
    if (bt->io != NULL && node->iodata == NULL) {
        bt->cleanreq++;
        res = bt->io->btopen(bt->io, node);
        if (res < 0) {
            ndn_btree_note_error(bt, __LINE__);
            node->corrupt = __LINE__;
        }
    }
    node->activity += NDN_BT_ACTIVITY_UPDATE_BUMP;
    return(res);
}

static int
compare_lexical(struct ndn_charbuf *a, struct ndn_charbuf *b)
{
    int al, bl; /* won't work for huge keys, but OK for here */
    int res;
    
    al = a->length;
    bl = b->length;
    res = memcmp(a->buf, b->buf, al < bl ? al : bl);
    if (res == 0)
        res = (al - bl);
    return(res);
}

static void
ndn_charbuf_append_escaped(struct ndn_charbuf *dst, struct ndn_charbuf *src)
{
    size_t i, n;
    int c;
    
    n = src->length;
    ndn_charbuf_reserve(dst, n);
    for (i = 0; i < n; i++) {
        c = src->buf[i];
        if (c < ' ' || c > '~' || c == '\\' || c == '(' || c == ')' || c == '"')
            ndn_charbuf_putf(dst, "\\%03o", c);
        else
            ndn_charbuf_append_value(dst, c, 1);
    }
}

#define MSG(fmt, ...) if (outfp != NULL) fprintf(outfp, fmt "\n", __VA_ARGS__)

/**
 *  Check the structure of the btree for consistency.
 *
 * If outfp is not NULL, information about structure will be written.
 * @returns -1 if an error was found.
 */
int
ndn_btree_check(struct ndn_btree *btree, FILE *outfp) {
    struct ndn_btree_node *node;
    struct ndn_btree_node *child;
    ndn_btnodeid stack[40] = { 0 };
    int kstk[40] = { 0 };
    int sp = 0;
    struct ndn_charbuf *buf[3];
    struct ndn_charbuf *q;
    int pp = 0;  /* for ping-pong buffers */
    int res;
    int i, k;
    struct ndn_btree_internal_payload *e = NULL;
    const char *indent = "\t\t\t\t\t\t\t\t"; /* 8 tabs for indentation */
    
    //unsigned long nodecount = 0;
    if (0) return(0);
    
    for (i = 0; i < 3; i++)
        buf[i] = ndn_charbuf_create();
    q = buf[2]; /* Scratch buffer for quoting */
    MSG("%%I start ndn_btree_check %d %u %u %d",
        hashtb_n(btree->resident),
        (unsigned)btree->nextsplit,
        (unsigned)btree->missedsplit,
        btree->errors);
    if (btree->missedsplit != 0 || btree->errors != 0) {
        MSG("%%W %s", "reset error indications");
        btree->missedsplit = 0;
        btree->errors = 0;
    }
    node = ndn_btree_getnode(btree, 1, 0);
    if (node == NULL) {
        MSG("%%E %s", "no root node!");
        goto Bail;
    }
    k = 0;
    res = 0;
    while (node != NULL && res >= 0) {
        int l = ndn_btree_node_level(node);
        int n = ndn_btree_node_nent(node);
        if (k == 0) {
            res = ndn_btree_chknode(node);
            if (res < 0) {
                MSG("%%E ndn_btree_chknode(%u) error (%d)",
                    (unsigned)node->nodeid, node->corrupt);
                ndn_btree_note_error(btree, __LINE__);
            }
            else if (res != 0) {
                MSG("%%W ndn_btree_chknode(%u) returned %d",
                    (unsigned)node->nodeid, node->corrupt);
            }
        }
        if (k == n) {
            /* Done with this node, release scarce resources */
            res = ndn_btree_close_node(btree, node);
            if (res < 0)
                MSG("%%W close of node %u failed", (unsigned)node->nodeid);
            /* Pop our stack to continue processing our parent */
            if (sp == 0) (k = 0, node = NULL);
            else (sp--, k = kstk[sp], node = ndn_btree_getnode(btree, stack[sp], 0));
        }
        else {
            if (k == 0 && l > 0) {
                /* Key 0 of a non-leaf should be empty */
                if (ndn_btree_compare(NULL, 0, node, k) != 0) {
                    ndn_btree_key_fetch(q, node, k);
                    i = q->length;
                    ndn_charbuf_append_escaped(q, q);
                    MSG("%%E Key [%u 0] %d not empty: (%s)",
                        (unsigned)node->nodeid, l, ndn_charbuf_as_string(q) + i);
                    ndn_btree_note_error(btree, __LINE__);
                }
            }
            else {
                pp ^= 1; /* swap ping-pong buffers */
                res = ndn_btree_key_fetch(buf[pp], node, k);
                if (res < 0) {
                    MSG("%%E could not fetch key %d of node %u",
                        k, (unsigned)node->nodeid);
                }
                else {
                    res = compare_lexical(buf[pp ^ 1], buf[pp]);
                    if (res < 0 || (res == 0 && k == 0 && l == 0)) {
                        /* Keys are in correct order */
                        res = 0;
                    }
                    else {
                        MSG("%%E Keys are out of order! [%u %d]",
                            (unsigned)node->nodeid, k);
                        ndn_btree_note_error(btree, __LINE__);
                        res = -(btree->errors > 10);
                    }
                    q->length = 0;
                    ndn_charbuf_append_escaped(q, buf[pp]);
                    MSG("%s(%s) [%u %d] %d %s", indent + 8 - sp % 8,
                        ndn_charbuf_as_string(q), (unsigned)node->nodeid, k, l,
                        l == 0 ? "leaf" : "node");
                }
            }
            if (l == 0)
                k++;
            else {
                stack[sp] = node->nodeid;
                kstk[sp] = k + 1;
                sp++;
                if (sp == 40) goto Bail;
                e = ndn_btree_node_internal_entry(node, k);
                if (e == NULL) goto Bail;
                child = ndn_btree_getnode(btree, MYFETCH(e, child), node->nodeid);
                if (child == NULL) goto Bail;
                if (child->parent != node->nodeid) {
                    /* This is an error, but we can repair it */
                    MSG("%%E child->parent != node->nodeid (%u!=%u)",
                        (unsigned)child->parent, (unsigned)node->nodeid);
                    ndn_btree_note_error(btree, __LINE__);
                    child->parent = node->nodeid;
                }
                node = child;
                k = 0;            
            }
        }
    }
    if (res <= 0 && btree->errors == 0) {
        for (i = 0; i < 3; i++)
            ndn_charbuf_destroy(&buf[i]);
        return(0);
    }
Bail:
    ndn_btree_note_error(btree, __LINE__);
    MSG("%%W finish ndn_btree_check %d %u %u %d",
        hashtb_n(btree->resident),
        (unsigned)btree->nextsplit,
        (unsigned)btree->missedsplit,
        btree->errors);
    for (i = 0; i < 3; i++)
        ndn_charbuf_destroy(&buf[i]);
    return(-1);
}
#undef MSG
