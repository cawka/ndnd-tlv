/**
 * @file ndn_name_util.c
 * @brief Support for manipulating ndnb-encoded Names.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2010 Palo Alto Research Center, Inc.
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
#include <string.h>
#include <stdlib.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>
#include <ndn/indexbuf.h>
#include <ndn/random.h>

/**
 * Reset charbuf to represent an empty Name in binary format.
 * @returns 0, or -1 for error.
 */
int
ndn_name_init(struct ndn_charbuf *c)
{
    int res;
    c->length = 0;
    res = ndn_charbuf_append_tt(c, NDN_DTAG_Name, NDN_DTAG);
    if (res == -1) return(res);
    res = ndn_charbuf_append_closer(c);
    return(res);
}

/**
 * Add a Component to a Name.
 *
 * The component is an arbitrary string of n octets, no escaping required.
 * @returns 0, or -1 for error.
 */
int
ndn_name_append(struct ndn_charbuf *c, const void *component, size_t n)
{
    int res;
    const unsigned char closer[2] = {NDN_CLOSE, NDN_CLOSE};
    if (c->length < 2 || c->buf[c->length-1] != closer[1])
        return(-1);
    c->length -= 1;
    ndn_charbuf_reserve(c, n + 8);
    res = ndn_charbuf_append_tt(c, NDN_DTAG_Component, NDN_DTAG);
    if (res == -1) return(res);
    res = ndn_charbuf_append_tt(c, n, NDN_BLOB);
    if (res == -1) return(res);
    res = ndn_charbuf_append(c, component, n);
    if (res == -1) return(res);
    res = ndn_charbuf_append(c, closer, sizeof(closer));
    return(res);
}

/**
 * Add a Component that is a NUL-terminated string.
 *
 * The component added consists of the bytes of the string without the NUL.
 * This function is convenient for those applications that construct 
 * component names from simple strings.
 * @returns 0, or -1 for error.
 */
int 
ndn_name_append_str(struct ndn_charbuf *c, const char *s)
{
    return(ndn_name_append(c, s, strlen(s)));
}

/**
 * Add a binary Component to a ndnb-encoded Name
 *
 * These are special components used for marking versions, fragments, etc.
 * @returns 0, or -1 for error
 * see doc/technical/NameConventions.html
 */
int
ndn_name_append_numeric(struct ndn_charbuf *c,
                        enum ndn_marker marker, uintmax_t value)
{
    uintmax_t v;
    int i;
    char b[32];
    
    for (v = value, i = sizeof(b); v != 0 && i > 0; i--, v >>= 8)
        b[i-1] = v & 0xff;
    if (i < 1)
        return(-1);
    if (marker >= 0)
        b[--i] = marker;
    return(ndn_name_append(c, b + i, sizeof(b) - i));
}

/**
 * Add nonce Component to ndnb-encoded Name
 *
 * Uses %C1.N namespace.
 * @returns 0, or -1 for error
 * see doc/technical/NameConventions.html
 */
int
ndn_name_append_nonce(struct ndn_charbuf *c)
{
    const unsigned char pre[4] = { NDN_MARKER_CONTROL, '.', 'N', 0 };
    unsigned char b[15];
    
    memcpy(b, pre, sizeof(pre));
    ndn_random_bytes(b + sizeof(pre), sizeof(b) - sizeof(pre));
    return(ndn_name_append(c, b, sizeof(b)));
}

/**
 * Add sequence of ndnb-encoded Components to a ndnb-encoded Name.
 *
 * start and stop are offsets from ndnb
 * @returns 0, or -1 for obvious error
 */
int
ndn_name_append_components(struct ndn_charbuf *c,
                           const unsigned char *ndnb,
                           size_t start, size_t stop)
{
    int res;
    if (c->length < 2 || start > stop)
        return(-1);
    c->length -= 1;
    ndn_charbuf_reserve(c, stop - start + 1);
    res = ndn_charbuf_append(c, ndnb + start, stop - start);
    if (res == -1) return(res);
    res = ndn_charbuf_append_closer(c);
    return(res);
}

/**
 * Extract a pointer to and size of component at
 * given index i.  The first component is index 0.
 * @returns 0, or -1 for error.
 */
int
ndn_name_comp_get(const unsigned char *data,
                  const struct ndn_indexbuf *indexbuf,
                  unsigned int i,
                  const unsigned char **comp, size_t *size)
{
    int len;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    /* indexbuf should have an extra value marking end of last component,
       so we need to use last 2 values */
    if (indexbuf->n < 2 || i > indexbuf->n - 2) {
	/* There isn't a component at this index */
	return(-1);
    }
    len = indexbuf->buf[i + 1]-indexbuf->buf[i];
    d = ndn_buf_decoder_start(&decoder, data + indexbuf->buf[i], len);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
	ndn_buf_advance(d);
	if (ndn_buf_match_blob(d, comp, size))
	    return(0);
	*comp = d->buf + d->decoder.index;
        *size = 0;
        ndn_buf_check_close(d);
        if (d->decoder.state >= 0)
            return(0);
    }
    return(-1);
}

int
ndn_name_comp_strcmp(const unsigned char *data,
                     const struct ndn_indexbuf *indexbuf,
                     unsigned int i, const char *val)
{
    const unsigned char *comp_ptr;
    size_t comp_size;

    // XXX - We probably want somewhat different semantics in the API -
    // comparing a string against a longer string with a 0 byte should
    // not claim equality.
    if (ndn_name_comp_get(data, indexbuf, i, &comp_ptr, &comp_size) == 0)
	return(strncmp(val, (const char *)comp_ptr, comp_size));
    /* Probably no such component, say query is greater-than */
    return(1);
}

/**
 * Find Component boundaries in a ndnb-encoded Name.
 *
 * Thin veneer over ndn_parse_Name().
 * components arg may be NULL to just do a validity check
 *
 * @returns -1 for error, otherwise the number of Components.
 */
int
ndn_name_split(const struct ndn_charbuf *c, struct ndn_indexbuf *components)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    d = ndn_buf_decoder_start(&decoder, c->buf, c->length);
    return(ndn_parse_Name(d, components));
}

/**
 * Chop the name down to n components.
 * @param c contains a ndnb-encoded Name
 * @param components may be NULL; if provided it must be consistent with
 *        some prefix of the name, and is updated accordingly.
 * @param n is the number or components to leave, or, if negative, specifies
 *        how many components to remove,
          e.g. -1 will remove just the last component.
 * @returns -1 for error, otherwise the new number of Components
 */
int
ndn_name_chop(struct ndn_charbuf *c, struct ndn_indexbuf *components, int n)
{
    if (components == NULL) {
        int res;
        components = ndn_indexbuf_create();
        if (components == NULL)
            return(-1);
        res = ndn_name_split(c, components);
        if (res >= 0)
            res = ndn_name_chop(c, components, n);
        ndn_indexbuf_destroy(&components);
        return(res);
    }
    /* Fix up components if needed. We could be a little smarter about this. */
    if (components->n == 0 || components->buf[components->n-1] + 1 != c->length)
        if (ndn_name_split(c, components) < 0)
            return(-1);
    if (n < 0)
        n += (components->n - 1); /* APL-style indexing */
    if (n < 0)
        return(-1);
    if (n < components->n) {
        c->length = components->buf[n];
        ndn_charbuf_append_value(c, NDN_CLOSE, 1);
        components->n = n + 1;
        return(n);
    }
    return(-1);
}

/**
 * Advance the last Component of a Name to the next possible value.
 * @param c contains a ndnb-encoded Name to be updated.
 * @returns -1 for error, otherwise the number of Components
 */
int
ndn_name_next_sibling(struct ndn_charbuf *c)
{
    int res = -1;
    struct ndn_indexbuf *ndx;
    unsigned char *lastcomp = NULL;
    size_t lastcompsize = 0;
    size_t i;
    int carry;
    struct ndn_charbuf *newcomp;

    ndx = ndn_indexbuf_create();
    if (ndx == NULL) goto Finish;
    res = ndn_name_split(c, ndx);
    if (res <= 0) {
        res = -1;
        goto Finish;
    }
    res = ndn_ref_tagged_BLOB(NDN_DTAG_Component, c->buf,
        ndx->buf[res-1], ndx->buf[res],
        (const unsigned char **)&lastcomp,
        &lastcompsize);
    if (res < 0) goto Finish;
    for (carry = 1, i = lastcompsize; carry && i > 0; i--) {
        carry = (((++lastcomp[i-1]) & 0xFF) == 0x00);
    }
    if (carry) {
        newcomp = ndn_charbuf_create();
        res |= ndn_charbuf_append_value(newcomp, 0, 1);
        res |= ndn_charbuf_append(newcomp, lastcomp, lastcompsize);
        res |= ndn_name_chop(c, ndx, ndx->n - 2);
        res |= ndn_name_append(c, newcomp->buf, newcomp->length);
        ndn_charbuf_destroy(&newcomp);
        if (res < 0) goto Finish;
    }
    res = ndx->n - 1;
Finish:
    ndn_indexbuf_destroy(&ndx);
    return(res);
}
