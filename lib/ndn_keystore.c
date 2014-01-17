/**
 * @file ndn_keystore.c
 * @brief Support for keystore access.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <ndn-tlv/keystore.h>
#include <ndn-tlv/charbuf.h>
#include <ndn-tlv/ndn.h>
#include <ndn-tlv/signing.h>
#include <ndn-tlv/uri.h>

struct ndn_keystore {
    int initialized;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    X509 *certificate;
    char *digest_algorithm;
    ssize_t pubkey_digest_length;
    unsigned char pubkey_digest[SHA256_DIGEST_LENGTH];
    struct ndn_charbuf *pubkey_content_object;
    struct ndn_charbuf *pubkey_meta_content_object;
    struct ndn_charbuf *pubkey_name;
};

struct ndn_keystore *
ndn_keystore_create(void)
{
    struct ndn_keystore *res = calloc(1, sizeof(*res));
    return (res);
}

void
ndn_keystore_destroy(struct ndn_keystore **p)
{
    if (*p != NULL) {
        if ((*p)->private_key != NULL)
            EVP_PKEY_free((*p)->private_key);
        if ((*p)->public_key != NULL)
            EVP_PKEY_free((*p)->public_key);
        if ((*p)->certificate != NULL)
            X509_free((*p)->certificate);
        if ((*p)->digest_algorithm != NULL)
            free((*p)->digest_algorithm);
        if ((*p)->pubkey_content_object != NULL)
            ndn_charbuf_destroy (&(*p)->pubkey_content_object);
        if ((*p)->pubkey_meta_content_object != NULL)
            ndn_charbuf_destroy (&(*p)->pubkey_meta_content_object);
        if ((*p)->pubkey_name != NULL)
            ndn_charbuf_destroy (&(*p)->pubkey_name);
        free(*p);
        *p = NULL;
    }
}

/**
 * @brief Get .pubcert file from keystore filename
 *
 * .pubcert file is constructed by appending .pubcert suffix to the keystore filename
 *
 * Note that the caller is reponsible to clean up returned value
 */
static char *
ndn_keystore_pubcert_from_keystore_file (const char *keystoreFilename)
{
    char *pubcert;
#define PUBCERT_SUFFIX ".pubcert"
#define PUBCERT_SUFFIX_LEN 8

    int len;

    if(keystoreFilename == NULL)
        return NULL;

    len = strlen(keystoreFilename);
    if (len == 0)
        return NULL;

    pubcert = (char*)malloc(len + PUBCERT_SUFFIX_LEN + 1);
    memcpy(pubcert, keystoreFilename, len);
    memcpy(pubcert + len, PUBCERT_SUFFIX, PUBCERT_SUFFIX_LEN + 1);

    return pubcert;
}

/* returns
 *  res >= 0    res characters remaining to be processed from data
 *  decoder state will be set appropriately
 */
static size_t
process_ndnb_data_once(struct ndn_skeleton_decoder *d, unsigned char *data, size_t n, struct ndn_charbuf *output)
{
    size_t s;

    s = ndn_skeleton_decode(d, data, n);
    if (!NDN_FINAL_DSTATE(d->state))
        return (0);
    ndn_charbuf_append (output, data, s);
    return s;
}


static int
ndn_keystore_init_pubcert(struct ndn_keystore *p, const char *keystoreFilename)
{
    int fd;
    char *pubcert_file;
    struct ndn_skeleton_decoder skel_decoder = {0};
    struct ndn_skeleton_decoder *d = &skel_decoder;

    const int MAX_SIZE_PUBCERT = 8192;
    unsigned char buf[MAX_SIZE_PUBCERT];
    ssize_t len;
    int state;
    int res;

    pubcert_file = ndn_keystore_pubcert_from_keystore_file(keystoreFilename);

    if(pubcert_file != NULL) {
        fd = open(pubcert_file, O_RDONLY);
        if (-1 != fd) {
            // do magic

            state = 0;
            len = read(fd, buf, MAX_SIZE_PUBCERT);
            if(len > 0) {
                p->pubkey_content_object = ndn_charbuf_create();
                p->pubkey_meta_content_object = ndn_charbuf_create();

                res = process_ndnb_data_once (d, buf, len, p->pubkey_content_object);
                if (res > 0) {
                    res = process_ndnb_data_once(d, buf+res, len-res, p->pubkey_meta_content_object);
                }

                if (res <= 0 || d->state < 0) {
                    fprintf (stderr, "WARNING: [%s] file exists, but does not contain valid certification of the public key or key meta info\n",
                             pubcert_file);

                    ndn_charbuf_destroy(&p->pubkey_content_object);
                    ndn_charbuf_destroy(&p->pubkey_meta_content_object);
                }
                else {
                    struct ndn_indexbuf *comps;
                    struct ndn_parsed_ContentObject pco;
                    int valid_name = 0;

                    comps = ndn_indexbuf_create ();
                    p->pubkey_name = ndn_charbuf_create();
                    ndn_name_init(p->pubkey_name);

                    res = ndn_parse_ContentObject(p->pubkey_content_object->buf, p->pubkey_content_object->length, &pco, comps);

                    if (res >= 0) {
                        if (pco.type == NDN_CONTENT_KEY) {
                            const unsigned char *content;
                            size_t len;

                            res = ndn_content_get_value (p->pubkey_content_object->buf, pco.offset[NDN_PCO_E], &pco, &content, &len);
                            if (res >= 0) {
                                struct ndn_pkey *pubkey = 0;

                                pubkey = ndn_d2i_pubkey (content, len);
                                if (EVP_PKEY_cmp (p->public_key, (const EVP_PKEY *)pubkey) == 1) {
                                    res = 1;
                                }
                                else {
                                    fprintf (stderr, "WARNING: [%s] contains a valid key object, but it does not match used private/public key\n",
                                             pubcert_file);
                                    res = -1;
                                }
                                ndn_pubkey_free(pubkey);

                                if (res >= 0) {
                                    for (unsigned int i = 0; i < comps->n - 1; i++) {
                                        const unsigned char *compPtr;
                                        const char KEY_ID_PREFIX [] = { 0xc1, '.', 'M', '.', 'K', 0x00 };
                                        size_t size;

                                        res = ndn_name_comp_get (p->pubkey_content_object->buf, comps, i, &compPtr, &size);
                                        if (res < 0)
                                            break;

                                        res = ndn_name_append (p->pubkey_name, compPtr, size);
                                        if (res < 0)
                                            break;

                                        // check for pubkey ID component: %C1.M.K%00F%8D%E9%C3%EE4%7F%C1Mjqro%C6L%8DGV%91%90%03%24%ECt%95n%F3%9E%A6i%F1%C9
                                        if(size > sizeof(KEY_ID_PREFIX) &&
                                           memcmp(compPtr, KEY_ID_PREFIX, sizeof(KEY_ID_PREFIX)) == 0) {
                                            valid_name = 1;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            res = -1;
                            fprintf (stderr, "WARNING: [%s] contains a valid ContentObject, but it is not a KEY object\n",
                                     pubcert_file);
                        }
                    }

                    if (res >= 0 && !valid_name) {
                        fprintf (stderr, "WARNING: [%s] contains a valid ContentObject, but its name does not conform to NDN key naming\n",
                                 pubcert_file);
                        fprintf (stderr, "       Allow to proceed, but public key name's correctness is not guaranteed\n");
                    }

                    if (res < 0) {
                        ndn_charbuf_destroy (&p->pubkey_name);
                    }

                    ndn_indexbuf_destroy (&comps);
                }
            }

            free(pubcert_file);
            close(fd);

            /* if (!NDN_FINAL_DSTATE(d->state)) { */
            /*     fprintf(stderr, "%s state %d\n", */
            /*             (d->state < 0) ? "error" : "incomplete", d->state); */
            /*     return 1; */
            /* } */
            return 0;
        }
        else { 
            //perror(pubcert_file);
            return 1;
        }
        free(pubcert_file);
    }
    return 1;
}

int
ndn_keystore_init(struct ndn_keystore *p, char *filename, char *password)
{
    FILE *fp;
    PKCS12 *keystore;
    ASN1_OBJECT *digest_obj;
    int digest_size;
    int res;

    OpenSSL_add_all_algorithms();
    fp = fopen(filename, "rb");
    if (fp == NULL)
        return (-1);

    keystore = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (keystore == NULL)
        return (-1);

    res = PKCS12_parse(keystore, password, &(p->private_key), &(p->certificate), NULL);
    PKCS12_free(keystore);
    if (res == 0) {
        return (-1);
    }
    p->public_key = X509_get_pubkey(p->certificate);
    /* cache the public key digest to avoid work later */
    if (1 != ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(),
                              X509_get_X509_PUBKEY(p->certificate),
                              p->pubkey_digest, NULL)) return (-1);
    p->pubkey_digest_length = SHA256_DIGEST_LENGTH;

    /* check if the key-pair requires a particular digest algorithm.
     * ECDSA keys from 160 through 383 bits are OK with SHA-256 (n.b. RFC5480)
     */
    
    switch (EVP_PKEY_type(p->private_key->type)) {
        case EVP_PKEY_DSA:
            digest_obj = OBJ_nid2obj(NID_sha1);
            break;
        default:
            digest_obj = NULL;
    }
    if (digest_obj) {
        digest_size = 1 + OBJ_obj2txt(NULL, 0, digest_obj, 1);
        p->digest_algorithm = calloc(1, digest_size);
        OBJ_obj2txt(p->digest_algorithm, digest_size, digest_obj, 1);
    } else {
        p->digest_algorithm = NULL;
    }

    /**
     * Last step: load (if it exists) public key certificate and meta information
     */
    ndn_keystore_init_pubcert(p, filename);

    p->initialized = 1;
    return (0);
}

const struct ndn_pkey *
ndn_keystore_private_key(struct ndn_keystore *p)
{
    if (0 == p->initialized)
        return (NULL);

    return ((const struct ndn_pkey *)(p->private_key));
}

const struct ndn_pkey *
ndn_keystore_public_key(struct ndn_keystore *p)
{
    if (0 == p->initialized)
        return (NULL);

    return ((const struct ndn_pkey *)(p->public_key));
}

const char *
ndn_keystore_digest_algorithm(struct ndn_keystore *p)
{
    if (0 == p->initialized)
        return (NULL);
    return (p->digest_algorithm);
}

ssize_t
ndn_keystore_public_key_digest_length(struct ndn_keystore *p)
{
    return ((0 == p->initialized) ? -1 : p->pubkey_digest_length);
}

const unsigned char *
ndn_keystore_public_key_digest(struct ndn_keystore *p)
{
    if (0 == p->initialized)
        return (NULL);
    return (p->pubkey_digest);
}

const struct ndn_certificate *
ndn_keystore_certificate(struct ndn_keystore *p)
{
    if (0 == p->initialized)
        return (NULL);

    return ((const void *)(p->certificate));
}

static int
add_cert_extension_with_context(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *extension;
    X509V3_CTX context;
    
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, cert, cert, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, value);
    if (extension == NULL)
        return(0);
    X509_add_ext(cert, extension, -1);
    X509_EXTENSION_free(extension);
    return(1);
}

static int
add_cert_extension(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *extension;
    extension = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (extension == NULL)
        return(0);
    X509_add_ext(cert, extension, -1);
    X509_EXTENSION_free(extension);
    return(1);
}
/**
 * Create a PKCS12 keystore file
 * @param filename  the name of the keystore file to be created.
 * @param password  the import/export password for the keystore.
 * @param subject   the subject (and issuer) name in the certificate.
 * @param keylength the number of bits in the RSA key to be generated.
 *                  A value <= 0 will result in the default (1024) being used.
 * @param validity_days the number of days the certificate in the keystore will
 *                  be valid.  A value <= 0 will result in the default (30) being used.
 * @returns 0 on success, -1 on failure
 */
int
ndn_keystore_file_init(char *filename, char *password,
                       char *subject, int keylength, int validity_days)
{
	RSA *rsa = RSA_new();
    BIGNUM *pub_exp = BN_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    X509 *cert = X509_new();
    X509_NAME *name = NULL;
    PKCS12 *pkcs12 = NULL;
    unsigned char spkid[SHA256_DIGEST_LENGTH];
    char spkid_hex[1 + 2 * SHA256_DIGEST_LENGTH];
    unsigned long serial = 0;
    unsigned char serial_bytes[sizeof(serial)];
    FILE *fp = NULL;
    int fd = -1;
    int res;
    int i;
    int ans = -1;
    
    // Check whether initial allocations succeeded.
    if (rsa == NULL || pub_exp == NULL || pkey == NULL || cert == NULL)
        goto Bail;
    
    // Set up default values for keylength and expiration.
    if (keylength <= 0)
        keylength = 1024;
    if (validity_days <= 0)
        validity_days = 30;
    
    OpenSSL_add_all_algorithms();
    
    BN_set_word(pub_exp, RSA_F4);
    res = 1;
    res &= RSA_generate_key_ex(rsa, keylength, pub_exp, NULL);
    res &= EVP_PKEY_set1_RSA(pkey, rsa);
    res &= X509_set_version(cert, 2);       // 2 => X509v3
	if (res == 0)
        goto Bail;
    
    // Construct random positive serial number.
    RAND_bytes(serial_bytes, sizeof(serial_bytes));
    serial_bytes[0] &= 0x7F;
    serial = 0;
    for (i=0; i < sizeof(serial_bytes); i++) {
        serial = (256 * serial) + serial_bytes[i];
    }
	ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    
    // Set the validity from now for the specified number of days.
    X509_gmtime_adj(X509_get_notBefore(cert), (long)0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)(60 * 60 * 24 * validity_days));
    X509_set_pubkey(cert, pkey);
    
    // Set up the simple subject name and issuer name for the certificate.
    name = X509_get_subject_name(cert);
    if (name == NULL)
        goto Bail;
    res = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)subject, -1, -1, 0);
	res &= X509_set_issuer_name(cert, name);
    
    // Add the necessary extensions.
    res &= add_cert_extension(cert, NID_basic_constraints, "critical,CA:FALSE");
    res &= add_cert_extension(cert, NID_key_usage, "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement");
    res &= add_cert_extension(cert, NID_ext_key_usage, "clientAuth");
    
    if (res == 0)
        goto Bail;
    
    /* Generate a KeyID which is the SHA256 digest of the DER encoding
	 * of a SubjectPublicKeyInfo.  Note that this is slightly uncommon,
	 * but it is more general and complete than digesting the BIT STRING
	 * component of the SubjectPublicKeyInfo itself (and no standard dictates
	 * how you must generate a key ID).  This code must produce the same result
     * as the Java version applied to the same SubjectPublicKeyInfo.
     */
    
    res = ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(),
                           X509_get_X509_PUBKEY(cert),
                           spkid, NULL);
    
    for (i = 0; i < 32; i++) snprintf(&spkid_hex[2 * i], 3, "%02X", (unsigned)spkid[i]);
    res &= add_cert_extension(cert, NID_subject_key_identifier, spkid_hex);
    res &= add_cert_extension_with_context(cert, NID_authority_key_identifier, "keyid:always");
    if (res == 0)
        goto Bail;
    
    // The certificate is complete, sign it.
    res = X509_sign(cert, pkey, EVP_sha1());
    if (res == 0)
        goto Bail;

    // construct the full PKCS12 keystore to hold the certificate and private key
    pkcs12 = PKCS12_create(password,  "ndnxuser", pkey, cert, NULL, 0, 0,
                           0 /*default iter*/, PKCS12_DEFAULT_ITER /*mac_iter*/, 0);
    if (pkcs12 == NULL)
        goto Bail;
    
    fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd == -1)
        goto Bail;
    fp = fdopen(fd, "wb");
    if (fp == NULL)
        goto Bail;
    i2d_PKCS12_fp(fp, pkcs12);
    fclose(fp);
    fd = -1;
    
    ans = 0;
    
    // For debugging, the following may be helpful:
    // RSA_print_fp(stderr, pkey->pkey.rsa, 0); */
    // X509_print_fp(stderr, cert);
	// PEM_write_PrivateKey(stderr, pkey, NULL, NULL, 0, NULL, NULL); */
	// PEM_write_X509(stderr, cert);
    
    
Bail:
    if (fd != -1)
        close(fd);
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (rsa != NULL) {
        RSA_free(rsa);
        rsa = NULL;
    }
    if (pub_exp != NULL){
        BN_free(pub_exp);
        pub_exp = NULL;
    }
    if (cert != NULL) {
        X509_free(cert);
        cert = NULL;
    }
    if (pkcs12 != NULL) {
        PKCS12_free(pkcs12);
        pkcs12 = NULL;
    }
    return (ans);
}

const struct ndn_charbuf *
ndn_keystore_get_pubkey_name (struct ndn_keystore *keystore)
{
  return keystore->pubkey_name;
}

const struct ndn_charbuf *
ndn_keystore_get_pubkey_content_object (struct ndn_keystore *keystore)
{
  return keystore->pubkey_content_object;
}

const struct ndn_charbuf *
ndn_keystore_get_pubkey_meta_content_object (struct ndn_keystore *keystore)
{
  return keystore->pubkey_meta_content_object;
}
