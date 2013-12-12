/**
 * @file sync.h
 * 
 * Sync library interface.
 * Defines a library interface to the Sync protocol facilities implemented
 * by the Repository
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2012 Palo Alto Research Center, Inc.
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

#ifndef NDNS_DEFINED
#define NDNS_DEFINED

#include <stddef.h>
#include <ndn/charbuf.h>

#define SLICE_VERSION 20110614

struct ndns_slice;
struct ndns_handle;

/**
 * ndns_name_closure is a closure used to notify the client
 * as each new name is added to the collection by calling the callback
 * procedure.  The data field refers to client data.
 * The ndns field is filled in by ndns_open.  The count field is for client use.
 * The storage for the closure belongs to the client at all times.
 */

struct ndns_name_closure;

typedef int (*ndns_callback)(struct ndns_name_closure *nc,
                             struct ndn_charbuf *lhash,
                             struct ndn_charbuf *rhash,
                             struct ndn_charbuf *pname);

struct ndns_name_closure {
    ndns_callback callback;
    struct ndns_handle *ndns;
    void *data;
    uint64_t count;
};

/**
 * Allocate a ndns_slice structure
 * @returns a pointer to a new ndns_slice structure
 */
struct ndns_slice *ndns_slice_create(void);

/**
 * Deallocate a ndns_slice structure
 * @param sp is a pointer to a pointer to a ndns_slice structure.  The pointer will
 *  be set to NULL on return.
 */
void ndns_slice_destroy(struct ndns_slice **sp);

/*
 * Set the topo and prefix fields of a slice
 * @param slice is the slice to be modified
 * @param t is a charbuf containing the topo prefix (used to route Sync commands)
 * @param p is a charbuf containing the prefix
 * @returns 0 on success, -1 otherwise.
 */
int ndns_slice_set_topo_prefix(struct ndns_slice *slice, struct ndn_charbuf *t,
                               struct ndn_charbuf *p);

/**
 * Add a (filter) clause to a ndns_slice structure
 * @param s is the slice to be modified
 * @param f is a filter clause ndnb-encoded as a Name
 * @returns 0 on success, -1 otherwise.
 */
int ndns_slice_add_clause(struct ndns_slice *s, struct ndn_charbuf *f);

/**
 * Construct the name of a Sync configuration slice.
 * @param nm is a ndn_charbuf into which will be stored the slice name
 * @param s is the slice structure for which the name is required.
 * @returns 0 on success, -1 otherwise.
 */
int ndns_slice_name(struct ndn_charbuf *nm, struct ndns_slice *s);

/**
 * Read a slice given the name.
 * @param h is the ndn_handle on which to read.
 * @param name is the charbuf containing the name of the sync slice to be read.
 * @param slice is a pointer to a ndns_slice object which will be filled in
 *  on successful return.
 * @returns 0 on success, -1 otherwise.
 * XXX: should name be permitted to have trailing segment?
 */
int ndns_read_slice(struct ndn *h, struct ndn_charbuf *name,
                    struct ndns_slice *slice);

/**
 * Write a ndns_slice object to a repository.
 * @param h is the ndn_handle on which to write.
 * @param slice is a pointer to a ndns_slice object to be written.
 * @param name if non-NULL, is a pointer to a charbuf which will be filled
 *  in with the name of the slice that was written.
 * @returns 0 on success, -1 otherwise.
 */
int ndns_write_slice(struct ndn *h, struct ndns_slice *slice,
                     struct ndn_charbuf *name);

/**
 * Delete a ndns_slice object from a repository.
 * @param h is the ndn_handle on which to write.
 * @param name is a pointer to a charbuf naming the slice to be deleted.
 * @returns 0 on success, -1 otherwise.
 */
int ndns_delete_slice(struct ndn *h, struct ndn_charbuf *name);

/**
 * Start notification of addition of names to a sync slice.
 * @param h is the ndn_handle on which to communicate.
 * @param slice is the slice to be opened.
 * @param nc is the closure which will be called for each new name,
 *  and returns 0 to continue enumeration, -1 to stop further enumeration.
 *  NOTE: It is not safe to call ndns_close from within the callback.
 * @param rhash
 *      If NULL, indicates that the enumeration should start from the empty set.
 *      If non-NULL but empty, indicates that the enumeration should start from
 *      the current root.
 *      If non-NULL, and not empty, indicates that the enumeration should start
 *      from the specified root hash
 * @param pname if non-NULL represents the starting name for enumeration within
 *  the sync tree represented by the root hash rhash.
 * @returns a pointer to a new sync handle, which will be freed at close.
 */
struct ndns_handle *ndns_open(struct ndn *h,
                              struct ndns_slice *slice,
                              struct ndns_name_closure *nc,
                              struct ndn_charbuf *rhash,
                              struct ndn_charbuf *pname);

/**
 * Stop notification of changes of names in a sync slice and free the handle.
 * @param sh is a pointer (to a pointer) to the sync handle returned
 *  by ndns_open, which will be freed and set to NULL.
 * @param rhash if non-NULL will be filled in with the current root hash.
 * @param pname if non-NULL will be filled in with the starting name
 *  for enumeration within the sync tree represented by the root hash rhash.
 */
void ndns_close(struct ndns_handle **sh,
                struct ndn_charbuf *rhash,
                struct ndn_charbuf *pname);

#endif

