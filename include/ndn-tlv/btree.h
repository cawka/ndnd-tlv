/**
 * @file ndn-tlv/btree.h
 * BTree
 */
/* Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011-12 Palo Alto Research Center, Inc.
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
 
#ifndef NDN_BTREE_DEFINED
#define NDN_BTREE_DEFINED

#include <stdio.h>
#include <sys/types.h>
#include <ndn-tlv/charbuf.h>
#include <ndn-tlv/hashtb.h>

struct ndn_btree_io;
struct ndn_btree_node;

/**
 * Methods for external I/O of btree nodes.
 *
 * These are supplied by the client, and provide an abstraction
 * to hold the persistent representation of the btree.
 *
 * Each node has a nodeid that serves as its filename.  These start as 1 and
 * are assigned consecutively. The node may correspond to a file in a file
 * system, or to some other abstraction as appropriate.
 *
 * Open should prepare for I/O to a node.  It may use the iodata slot to
 * keep track of its state, and should set iodata to a non-NULL value.
 * It should update the count of openfds as appropriate.
 *
 * Read gets bytes from the file and places it into the buffer at the
 * corresponding position.  The parameter is a limit for the max buffer size.
 * Bytes prior to the clean mark do not need to be read.
 * The buffer should be extended, if necessary, to hold the data.
 * Read is not responsible for updating the clean mark.
 * 
 * Write puts bytes from the buffer into the file, and truncates the file
 * according to the buffer length.  Bytes prior to the clean mork do not
 * need to be written, since they should be the same in the buffer and the
 * file.  Write is not responsible for updating the clean mark.
 *
 * Close is called at the obvious time.  It should free any node io state and
 * set iodata to NULL, updating openfds as appropriate.  It should not change
 * the other parts of the node.
 *
 * Negative return values indicate errors.
 */
typedef int (*ndn_btree_io_openfn)
    (struct ndn_btree_io *, struct ndn_btree_node *);
typedef int (*ndn_btree_io_readfn)
    (struct ndn_btree_io *, struct ndn_btree_node *, unsigned);
typedef int (*ndn_btree_io_writefn)
    (struct ndn_btree_io *, struct ndn_btree_node *);
typedef int (*ndn_btree_io_closefn)
    (struct ndn_btree_io *, struct ndn_btree_node *);
typedef int (*ndn_btree_io_destroyfn)
    (struct ndn_btree_io **);

/* This serves as the external name of a btree node. */
typedef unsigned ndn_btnodeid;

/**
 * Holds the methods and the associated common data.
 */
struct ndn_btree_io {
    char clue[16]; /* unused except for debugging/logging */
    ndn_btree_io_openfn btopen;
    ndn_btree_io_readfn btread;
    ndn_btree_io_writefn btwrite;
    ndn_btree_io_closefn btclose;
    ndn_btree_io_destroyfn btdestroy;
    ndn_btnodeid maxnodeid;    /**< Largest assigned nodeid */
    int openfds;               /**< Number of open files */
    void *data;
};
/**
 * State associated with a btree node
 *
 * These usually live in the resident hashtb of a ndn_btree, but might be
 * elsewhere (such as stack-allocated) in some cases.
 */
struct ndn_btree_node {
    ndn_btnodeid nodeid;        /**< Identity of node */
    struct ndn_charbuf *buf;    /**< The internal buffer */
    void *iodata;               /**< Private use by ndn_btree_io methods */
    ndn_btnodeid parent;        /**< Parent node id; 0 if unknown */
    unsigned clean;             /**< Number of stable buffered bytes at front */
    unsigned freelow;           /**< Index of first unused byte of free space */
    unsigned corrupt;           /**< Structure is not to be trusted */
    unsigned activity;          /**< Meters use of the node */
};

/** Increment to node->activity when node is referenced but not changed */
#define NDN_BT_ACTIVITY_REFERENCE_BUMP 1
/** Increment to node->activity when node is read from disk */
#define NDN_BT_ACTIVITY_READ_BUMP 8
/** Increment to node->activity when node is modified */
#define NDN_BT_ACTIVITY_UPDATE_BUMP 16

/** Limit to the number of btree nodes kept open when idle */
#define NDN_BT_OPEN_NODES_IDLE 5
/** Limit to the number of file descriptors the btree should use at a time */
#define NDN_BT_OPEN_NODES_LIMIT 13


/**
 * State associated with a btree as a whole
 */
struct ndn_btree {
    unsigned magic;             /**< for making sure we point to a btree */
    ndn_btnodeid nextnodeid;    /**< for allocating new btree nodes */
    struct ndn_btree_io *io;    /**< storage layer */
    struct hashtb *resident;    /**< of ndn_btree_node, by nodeid */
    ndn_btnodeid nextspill;     /**< undersize node that needs spilling */
    ndn_btnodeid nextsplit;     /**< oversize node that needs splitting */
    ndn_btnodeid missedsplit;   /**< should stay zero */
    int errors;                 /**< counter for detected errors */
    int cleanreq;               /**< if nonzero, cleaning might be needed */
    /* tunables */
    int full;                   /**< split internal nodes bigger than this */
    int full0;                  /**< split leaf nodes bigger than this */
    int nodebytes;              /**< limit size of node */
    int nodepool;               /**< limit resident size */
};

/**
 *  Structure of a node.
 *  
 *  These are as they appear on external storage, so we stick to 
 *  single-byte types to keep it portable between machines.
 *  Multi-byte numeric fields are always in big-endian format.
 *
 *  Within a node, the entries are fixed size.
 *  The entries are packed together at the end of the node's storage,
 *  so that by examining the last entry the location of the other entries
 *  can be determined directly.  The entsz field includes the whole entry,
 *  which consists of a payload followed by a trailer.
 *
 *  The keys are stored in the first portion of the node.  They may be
 *  in multiple pieces, and the pieces may overlap arbitrarily.  This offers
 *  a very simple form of compression, since the keys within a node are
 *  very likely to have a lot in common with each other.
 *
 *  A few bytes at the very beginning serve as a header.
 *
 * This is the overall structure of a node:
 *
 *  +---+-----------------------+--------------+----+----+-- --+----+
 *  |hdr|..string......space....| (free space) | E0 | E1 | ... | En |
 *  +---+-----------------------+--------------+----+----+-- --+----+
 *
 * It is designed so that new entries can be added without having to
 * rewrite all of the string space.  Thus the header should not contain
 * things that we expect to change often.
 */
struct ndn_btree_node_header {
    unsigned char magic[4];     /**< File magic */
    unsigned char version[1];   /**< Format version */
    unsigned char nodetype[1];  /**< Indicates root node, backup root, etc. */
    unsigned char level[1];     /**< Level within the tree */
    unsigned char extsz[1];     /**< Header extension size (NDN_BT_SIZE_UNITS)*/
};

/**
 *  Structure of a node entry trailer.
 *
 * This is how the last few bytes of each entry within a node are arranged.
 *
 */
struct ndn_btree_entry_trailer {
    unsigned char koff0[4];     /**< offset of piece 0 of the key */
    unsigned char ksiz0[2];     /**< size of piece 0 of the key */
    unsigned char koff1[4];     /**< offset of piece 1 */
    unsigned char ksiz1[2];     /**< size of piece 1 */
    unsigned char entdx[2];     /**< index of this entry within the node */
    unsigned char level[1];     /**< leaf nodes are at level 0 */
    unsigned char entsz[1];     /**< entry size in NDN_BT_SIZE_UNITS */
};
#define NDN_BT_SIZE_UNITS 8
/** Maximum key size, dictated by size of above size fields */
#define NDN_BT_MAX_KEY_SIZE 65535

/**
 *  Structure of the entry payload within an internal (non-leaf) node.
 */
struct ndn_btree_internal_payload {
    unsigned char magic[1];     /**< NDN_BT_INTERNAL_MAGIC */
    unsigned char pad[3];       /**< must be zero */
    unsigned char child[4];     /**< nodeid of a child */
};
#define NDN_BT_INTERNAL_MAGIC 0xCC
/**
 *  Logical structure of the entry within an internal (non-leaf) node.
 */
struct ndn_btree_internal_entry {
    struct ndn_btree_internal_payload ie;
    struct ndn_btree_entry_trailer trailer;
};

/* More extensive function descriptions are provided in the code. */

/* Number of entries within the node */
int ndn_btree_node_nent(struct ndn_btree_node *node);

/* Node level (leaves are at level 0) */
int ndn_btree_node_level(struct ndn_btree_node *node);

/* Node entry size */
int ndn_btree_node_getentrysize(struct ndn_btree_node *node);

/* Node payload size */
int ndn_btree_node_payloadsize(struct ndn_btree_node *node);

/* Get address of the indexed entry within node */
void *ndn_btree_node_getentry(size_t payload_bytes,
                              struct ndn_btree_node *node, int i);

/* Fetch the indexed key and place it into dst */
int ndn_btree_key_fetch(struct ndn_charbuf *dst,
                        struct ndn_btree_node *node, int i);

/* Append the indexed key to dst */
int ndn_btree_key_append(struct ndn_charbuf *dst,
                         struct ndn_btree_node *node, int i);

/* Compare given key with the key in the indexed entry of the node */
int ndn_btree_compare(const unsigned char *key, size_t size,
                      struct ndn_btree_node *node, int i);

#define NDN_BT_ENCRES(ndx, success) (2 * (ndx) + ((success) || 0))
#define NDN_BT_SRCH_FOUND(res) ((res) & 1)
#define NDN_BT_SRCH_INDEX(res) ((res) >> 1)
/* Search within the node for the key, or something near it */
int ndn_btree_searchnode(const unsigned char *key, size_t size,
                         struct ndn_btree_node *node);

/* Insert a new entry at slot i of node */
int ndn_btree_insert_entry(struct ndn_btree_node *node, int i,
                           const unsigned char *key, size_t keysize,
                           void *payload, size_t payload_bytes);

/* Delete the entry at slot i of node */
int ndn_btree_delete_entry(struct ndn_btree_node *node, int i);

/* Initialize a btree node */
int ndn_btree_init_node(struct ndn_btree_node *node,
                        int level, unsigned char nodetype, unsigned char extsz);

/* Test for an oversize node */
int ndn_btree_oversize(struct ndn_btree *btree, struct ndn_btree_node *node);

/* Test for unbalance */
int ndn_btree_unbalance(struct ndn_btree *btree, struct ndn_btree_node *node);

/* Check a node for internal consistency */
int ndn_btree_chknode(struct ndn_btree_node *node);

/*
 * Overall btree operations
 */

/* Handle creation and destruction */
struct ndn_btree *ndn_btree_create(void);
int ndn_btree_destroy(struct ndn_btree **);

/* Record an error */
void ndn_btree_note_error(struct ndn_btree *bt, int info);

/* Access a node, creating or reading it if necessary */
struct ndn_btree_node *ndn_btree_getnode(struct ndn_btree *bt,
                                         ndn_btnodeid nodeid,
                                         ndn_btnodeid parentid);

/* Get a node handle if it is already resident */
struct ndn_btree_node *ndn_btree_rnode(struct ndn_btree *bt,
                                       ndn_btnodeid nodeid);

/* Clean a node and release io resources, retaining cached node in memory */
int ndn_btree_close_node(struct ndn_btree *btree, struct ndn_btree_node *node);

/* Do a lookup, starting from the default root */
int ndn_btree_lookup(struct ndn_btree *btree,
                     const unsigned char *key, size_t size,
                     struct ndn_btree_node **leafp);

/* Do a lookup, starting from the provided root and stopping at stoplevel */
int ndn_btree_lookup_internal(struct ndn_btree *btree,
                     struct ndn_btree_node *root, int stoplevel,
                     const unsigned char *key, size_t size,
                     struct ndn_btree_node **ansp);

/* Search for nodeid in parent */ 
int ndn_btree_index_in_parent(struct ndn_btree_node *parent,
                              ndn_btnodeid nodeid);

/* Find the leaf that comes after the given node */
int ndn_btree_next_leaf(struct ndn_btree *btree,
                        struct ndn_btree_node *node,
                        struct ndn_btree_node **ansp);

/* Find the leaf that comes before the given node */
int ndn_btree_prev_leaf(struct ndn_btree *btree,
                        struct ndn_btree_node *node,
                        struct ndn_btree_node **ansp);

/* Split a node into two */
int ndn_btree_split(struct ndn_btree *btree, struct ndn_btree_node *node);

/* Spill a node over into sibling */
int ndn_btree_spill(struct ndn_btree *btree, struct ndn_btree_node *node);

/* Prepare to update a node */
int ndn_btree_prepare_for_update(struct ndn_btree *bt,
                                 struct ndn_btree_node *node);

/* Check the whole btree carefully */
int ndn_btree_check(struct ndn_btree *btree, FILE *outfp);

/*
 * Storage layer - client can provide other options
 */

/* For btree node storage in files */
struct ndn_btree_io *ndn_btree_io_from_directory(const char *path,
                                                 struct ndn_charbuf *msgs);

/* Low-level field access */
unsigned ndn_btree_fetchval(const unsigned char *p, int size);
void ndn_btree_storeval(unsigned char *p, int size, unsigned v);

#endif
