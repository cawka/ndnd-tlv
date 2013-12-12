/**
 * @file ndn/indexbuf.h
 * 
 * Expandable buffer of non-negative values.
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008, 2009 Palo Alto Research Center, Inc.
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

#ifndef NDN_INDEXBUF_DEFINED
#define NDN_INDEXBUF_DEFINED

#include <stddef.h>

struct ndn_indexbuf {
    size_t n;
    size_t limit;
    size_t *buf;
};

struct ndn_indexbuf *ndn_indexbuf_create(void);
void ndn_indexbuf_destroy(struct ndn_indexbuf **cbp);
size_t *ndn_indexbuf_reserve(struct ndn_indexbuf *c, size_t n);
int ndn_indexbuf_append(struct ndn_indexbuf *c, const size_t *p, size_t n);
int ndn_indexbuf_append_element(struct ndn_indexbuf *c, size_t v);
int ndn_indexbuf_member(struct ndn_indexbuf *x, size_t val);
void ndn_indexbuf_remove_element(struct ndn_indexbuf *x, size_t val);
int ndn_indexbuf_set_insert(struct ndn_indexbuf *x, size_t val);
int ndn_indexbuf_remove_first_match(struct ndn_indexbuf *x, size_t val);
void ndn_indexbuf_move_to_end(struct ndn_indexbuf *x, size_t val);
void ndn_indexbuf_move_to_front(struct ndn_indexbuf *x, size_t val);

#endif
