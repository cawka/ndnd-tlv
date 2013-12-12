/**
 * @file ndn/signing.h
 * 
 * Message signing interface.
 * This is a veneer so that the ndn code can use various underlying
 * implementations of the signature functions without muss and fuss.
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

#ifndef NDN_SIGNING_DEFINED
#define NDN_SIGNING_DEFINED

#include <stddef.h>
#include <ndn/charbuf.h>

/*
 * opaque type for signing context
 */
struct ndn_sigc;

/*
 * opaque type for public and private keys
 */
struct ndn_pkey;

/*
 * opaque type for signature
 */
struct ndn_signature;

/*
 * see ndn/ndn.h
 */
struct ndn_parsed_ContentObject;

struct ndn_sigc *ndn_sigc_create(void);
int ndn_sigc_init(struct ndn_sigc *ctx, const char *digest, const struct ndn_pkey *priv_key);
void ndn_sigc_destroy(struct ndn_sigc **);
int ndn_sigc_update(struct ndn_sigc *ctx, const void *data, size_t size);
int ndn_sigc_final(struct ndn_sigc *ctx, struct ndn_signature *signature, size_t *size, const struct ndn_pkey *priv_key);
size_t ndn_sigc_signature_max_size(struct ndn_sigc *ctx, const struct ndn_pkey *priv_key);
int ndn_verify_signature(const unsigned char *msg, size_t size, const struct ndn_parsed_ContentObject *co,
                         const struct ndn_pkey *verification_pubkey);
struct ndn_pkey *ndn_d2i_pubkey(const unsigned char *p, size_t size);
void ndn_pubkey_free(struct ndn_pkey *i_pubkey); /* use for result of ndn_d2i_pubkey */
size_t ndn_pubkey_size(const struct ndn_pkey *i_pubkey);

/*
 * ndn_append_pubkey_blob: append a ndnb-encoded blob of the external
 * public key, given the internal form
 * Returns -1 for error
 */
int ndn_append_pubkey_blob(struct ndn_charbuf *c, const struct ndn_pkey *i_pubkey);

#endif
