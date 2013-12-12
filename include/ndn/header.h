/**
 * @file ndn/header.h
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009 Palo Alto Research Center, Inc.
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

#ifndef NDN_HEADER_DEFINED
#define NDN_HEADER_DEFINED

#include <stddef.h>
#include <ndn/charbuf.h>

struct ndn_header {
    uintmax_t start;
    uintmax_t count;
    uintmax_t block_size;
    uintmax_t length;
    struct ndn_charbuf *root_digest;
    struct ndn_charbuf *content_digest;
};

struct ndn_header *ndn_header_parse(const unsigned char *, size_t);

void ndn_header_destroy(struct ndn_header **);

int ndnb_append_header(struct ndn_charbuf *, const struct ndn_header *);

struct ndn_header *ndn_get_header(struct ndn *, struct ndn_charbuf *, int);

#endif
