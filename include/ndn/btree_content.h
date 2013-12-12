/**
 * @file ndn/btree_content.h
 *
 * Storage of a content index in a btree
 */
/*
 * (Someday) Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011 Palo Alto Research Center, Inc.
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
 
 
#ifndef NDN_BTREE_CONTENT_DEFINED
#define NDN_BTREE_CONTENT_DEFINED

#include <sys/types.h>
#include <ndn/btree.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>

/**
 *  Structure of the entry payload within a leaf node.
 */
struct ndn_btree_content_payload {
    unsigned char magic[1];     /**< NDN_BT_CONTENT_MAGIC */
    unsigned char ctype[3];     /**< Type */
    unsigned char cobsz[4];     /**< Size in bytes of ContentObject */
    unsigned char ncomp[2];     /**< number of name components */
    unsigned char flags[1];     /**< NDN_RCFLAG_* */
    unsigned char ttpad[1];     /**< Reserved until 20 Aug 4147 07:32:16 GMT */
    unsigned char timex[6];     /**< Timestamp from content object */
    unsigned char actim[6];     /**< Accession time, Timestamp format */
    unsigned char cobid[8];     /**< Where the actual ContentObject is */
    unsigned char ppkdg[32];    /**< PublisherPublicKeyDigest */
};
#define NDN_BT_CONTENT_MAGIC    0xC0
#define NDN_RCFLAG_LASTBLOCK    0x80
#define NDN_RCFLAG_STALE        0x01

/**
 *  Logical structure of the entry within a leaf node.
 */
struct ndn_btree_content_entry {
    struct ndn_btree_content_payload ce;
    struct ndn_btree_entry_trailer trailer;
};

/* Match an interest against a btree entry, assuming a prefix match. */
int ndn_btree_match_interest(struct ndn_btree_node *node, int ndx,
                             const unsigned char *interest_msg,
                             const struct ndn_parsed_interest *pi,
                             struct ndn_charbuf *scratch);

/* Insert a ContentObject into a btree node */
int ndn_btree_insert_content(struct ndn_btree_node *node, int ndx,
                             uint_least64_t cobid,
                             const unsigned char *content_object,
                             struct ndn_parsed_ContentObject *pc,
                             struct ndn_charbuf *flatname);

/* cobid accessor */
uint_least64_t ndn_btree_content_cobid(struct ndn_btree_node *node, int ndx);
int ndn_btree_content_set_cobid(struct ndn_btree_node *node, int ndx,
                                uint_least64_t cobid);
/* cobsz accessor */
int ndn_btree_content_cobsz(struct ndn_btree_node *node, int ndx);


/**
 * Flat name representation
 *
 * Within the btree-based index, the name is stored in a representation
 * different than the ndnb encoding that is used on the wire.
 * This encoding is designed so that simple lexical ordering on
 * flatname byte arrays corresponds precisely with ndn's CanonicalOrdering
 * of Names.
 *
 * In the flatname representation, the bytes that constitute each
 * Component are prepended by a length indicator that occupies one or
 * more bytes.  The high-order bit is used to mark the end of the length
 * indicator, with 0 marking the last byte. The low order 7 bits of each
 * of these bytes are concatenated together, in big endian order, to form
 * the length.
 *
 * For example:
 * 0x00                => the zero-length component
 * 0x01 0x41           => the component "A"
 * 0x7F 0xC1 ...       => a component 127 bytes long that starts with "%C1"
 * 0x81 0x00 0x39 ...  => a component 128 bytes long that starts with "9"
 * 0xff 0x3F 0x30 ...  => a component 16383 bytes long that starts with "0"
 *
 * Length indicators larger than this are possible in theory, but unlikely
 * to come up in practice. Nonetheless, we do allow 3-byte length indicators.
 */

/* Name flattening */
int ndn_flatname_append_component(struct ndn_charbuf *dst,
                                  const unsigned char *comp, size_t size);
int ndn_flatname_append_from_ndnb(struct ndn_charbuf *dst,
                                  const unsigned char *ndnb, size_t size,
                                  int skip, int count);
int ndn_flatname_from_ndnb(struct ndn_charbuf *dst,
                           const unsigned char *ndnb, size_t size);

/* Name unflattening */
int ndn_name_append_flatname(struct ndn_charbuf *dst,
                             const unsigned char *flatname, size_t size,
                             int skip, int count);
int ndn_uri_append_flatname(struct ndn_charbuf *uri,
                             const unsigned char *flatname, size_t size,
                             int includescheme);
/* Flatname accessors */
int ndn_flatname_ncomps(const unsigned char *flatname, size_t size);

/* Flatname comparison */
int ndn_flatname_charbuf_compare(struct ndn_charbuf *a, struct ndn_charbuf *b);
int ndn_flatname_compare(const unsigned char *a, size_t al,
                         const unsigned char *b, size_t bl);

/*
 * Parse the component delimiter from the start of a flatname
 * Returns -1 for error, 0 nothing left, or compsize * 4 + delimsize
 */
int ndn_flatname_next_comp(const unsigned char *flatname, size_t size);
/** Get delimiter size from return value of ndn_flatname_next_comp */
#define NDNFLATDELIMSZ(rnc) ((rnc) & 3)
/** Get data size from return value of ndn_flatname_next_comp */
#define NDNFLATDATASZ(rnc) ((rnc) >> 2)
/** Get total delimited size from return value of ndn_flatname_next_comp */
#define NDNFLATSKIP(rnc) (NDNFLATDELIMSZ(rnc) + NDNFLATDATASZ(rnc))

#endif
