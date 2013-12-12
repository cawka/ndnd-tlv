/**
 * @file ndn/seqwriter.h
 * @brief
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2010 Palo Alto Research Center, Inc.
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
 
#ifndef NDN_SEQWRITER_DEFINED
#define NDN_SEQWRITER_DEFINED

#include <stddef.h>
struct ndn_seqwriter;
struct ndn;
struct ndn_charbuf;

struct ndn_seqwriter *ndn_seqw_create(struct ndn *h, struct ndn_charbuf *name);
int ndn_seqw_possible_interest(struct ndn_seqwriter *w);
int ndn_seqw_batch_start(struct ndn_seqwriter *w);
int ndn_seqw_get_name(struct ndn_seqwriter *w, struct ndn_charbuf *nv);
int ndn_seqw_write(struct ndn_seqwriter *w, const void *buf, size_t size);
int ndn_seqw_batch_end(struct ndn_seqwriter *w);
int ndn_seqw_set_block_limits(struct ndn_seqwriter *w, int l, int h);
int ndn_seqw_set_freshness(struct ndn_seqwriter *w, int freshness);
int ndn_seqw_close(struct ndn_seqwriter *w);

#endif
