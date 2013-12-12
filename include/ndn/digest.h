/**
 * @file ndn/digest.h
 * 
 * Message digest interface.
 *
 * This is a veneer so that the ndn code can use various underlying
 * implementations of the message digest functions without muss and fuss.
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

#ifndef NDN_DIGEST_DEFINED
#define NDN_DIGEST_DEFINED

#include <stddef.h>

struct ndn_digest;

/* These ids are not meant to be stable across versions */
enum ndn_digest_id {
    NDN_DIGEST_DEFAULT,
    NDN_DIGEST_SHA1,
    NDN_DIGEST_SHA224,
    NDN_DIGEST_SHA256, /* This is our current favorite */
    NDN_DIGEST_SHA384,
    NDN_DIGEST_SHA512
};

struct ndn_digest *ndn_digest_create(enum ndn_digest_id);
void ndn_digest_destroy(struct ndn_digest **);
enum ndn_digest_id ndn_digest_getid(struct ndn_digest *);
size_t ndn_digest_size(struct ndn_digest *);
void ndn_digest_init(struct ndn_digest *);
/* return codes are negative for errors */
int ndn_digest_update(struct ndn_digest *, const void *, size_t);
int ndn_digest_final(struct ndn_digest *, unsigned char *, size_t);

#endif
