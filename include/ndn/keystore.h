/**
 * @file ndn/keystore.h
 *
 * KEYSTORE interface.
 *
 * This is a veneer so that the ndn code can avoid exposure to the
 * underlying keystore implementation types.
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009 Palo Alto Research Center, Inc.
 *           (c) 2013 University of California, Los Angeles
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

#ifndef NDN_KEYSTORE_DEFINED
#define NDN_KEYSTORE_DEFINED

#include <stddef.h>
#include <ndn/charbuf.h>

/*
 * opaque type for key storage
 */
struct ndn_keystore;

/*
 * opaque type for public and private keys
 */
struct ndn_pkey;

/*
 * opaque type for (X509) certificates
 */
struct ndn_certificate;

struct ndn_keystore *ndn_keystore_create(void);
void ndn_keystore_destroy(struct ndn_keystore **p);
int ndn_keystore_init(struct ndn_keystore *p, char *name, char *password);
const struct ndn_pkey *ndn_keystore_private_key(struct ndn_keystore *p);
const struct ndn_pkey *ndn_keystore_public_key(struct ndn_keystore *p);
const char *ndn_keystore_digest_algorithm(struct ndn_keystore *p);
ssize_t ndn_keystore_public_key_digest_length(struct ndn_keystore *p);
const unsigned char *ndn_keystore_public_key_digest(struct ndn_keystore *p);
const struct ndn_certificate *ndn_keystore_certificate(struct ndn_keystore *p);
int ndn_keystore_file_init(char *filename, char *password, char *subject, int keylength, int validity_days);

/**
 * @brief Get name of the public key (from .pubcert file)
 * @param keystore pointer to initialized keystore object
 * @returns const pointer to fully formatted public key name in ndnb format or NULL if .pubcert is missing or invalid
 */
const struct ndn_charbuf *
ndn_keystore_get_pubkey_name (struct ndn_keystore *keystore);

/**
 * @brief Get raw content object of the public key (from .pubcert file)
 * @param keystore pointer to initialized keystore object
 * @returns const pointer to raw public key content object or NULL if .pubcert is missing or invalid
 */
const struct ndn_charbuf *
ndn_keystore_get_pubkey_content_object (struct ndn_keystore *keystore);

/**
 * @brief Get raw content object of the meta information of the public key (from .pubcert file)
 * @param keystore pointer to initialized keystore object
 * @returns const pointer to raw public key meta info content object or NULL if .pubcert is missing or invalid
 */
const struct ndn_charbuf *
ndn_keystore_get_pubkey_meta_content_object (struct ndn_keystore *keystore);

#endif
