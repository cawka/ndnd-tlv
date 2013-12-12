/**
 * @file ndn_buf_encoder.c
 * @brief Support for constructing various ndnb-encoded objects.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2013 Palo Alto Research Center, Inc.
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
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>
#include <ndn/indexbuf.h>
#include <ndn/signing.h>
#include <ndn/ndn_private.h>

/**
 * Create SignedInfo.
 *
 *
 * @param c is used to hold the result.
 * @param publisher_key_id points to the digest of the publisher key id.
 * @param publisher_key_id_size is the size in bytes(32) of the pub key digest
 * @param timestamp holds the timestamp, as a ndnb-encoded blob, or is NULL
          to use the current time.
 * @param type indicates the Type of the ContentObject.
 * @param freshness is the FreshnessSeconds value, or -1 to omit.
 * @param finalblockid holds the FinalBlockID, as a ndnb-encoded blob, or is
          NULL to omit.
 * @param key_locator is the ndnb-encoded KeyLocator element, or NULL to omit.
 * @returns 0 for success or -1 for error.
 */
int
ndn_signed_info_create(struct ndn_charbuf *c,
                       const void *publisher_key_id,	/* input, sha256 hash */
                       size_t publisher_key_id_size, 	/* input, 32 for sha256 hashes */
                       const struct ndn_charbuf *timestamp,/* input ndnb blob, NULL for "now" */
                       enum ndn_content_type type,	/* input */
                       int freshness,			/* input, -1 means omit */
                       const struct ndn_charbuf *finalblockid,  /* input, NULL means omit */
                       const struct ndn_charbuf *key_locator)	/* input, optional, ndnb encoded */
{
    int res = 0;
    const char fakepubkeyid[32] = {0};
 
    if (publisher_key_id != NULL && publisher_key_id_size != 32)
        return(-1);

    res |= ndn_charbuf_append_tt(c, NDN_DTAG_SignedInfo, NDN_DTAG);

    res |= ndn_charbuf_append_tt(c, NDN_DTAG_PublisherPublicKeyDigest, NDN_DTAG);
    if (publisher_key_id != NULL) {
        res |= ndn_charbuf_append_tt(c, publisher_key_id_size, NDN_BLOB);
        res |= ndn_charbuf_append(c, publisher_key_id, publisher_key_id_size);
    } else {
        /* XXX - obtain the default publisher key id and append it */
        res |= ndn_charbuf_append_tt(c, sizeof(fakepubkeyid), NDN_BLOB);
        res |= ndn_charbuf_append(c, fakepubkeyid, sizeof(fakepubkeyid));
    }
    res |= ndn_charbuf_append_closer(c);

    res |= ndn_charbuf_append_tt(c, NDN_DTAG_Timestamp, NDN_DTAG);
    if (timestamp != NULL)
        res |= ndn_charbuf_append_charbuf(c, timestamp);
    else
        res |= ndnb_append_now_blob(c, NDN_MARKER_NONE);
    res |= ndn_charbuf_append_closer(c);

    if (type != NDN_CONTENT_DATA) {
        res |= ndn_charbuf_append_tt(c, NDN_DTAG_Type, NDN_DTAG);
        res |= ndn_charbuf_append_tt(c, 3, NDN_BLOB);
        res |= ndn_charbuf_append_value(c, type, 3);
        res |= ndn_charbuf_append_closer(c);
    }

    if (freshness >= 0)
        res |= ndnb_tagged_putf(c, NDN_DTAG_FreshnessSeconds, "%d", freshness);

    if (finalblockid != NULL) {
        res |= ndn_charbuf_append_tt(c, NDN_DTAG_FinalBlockID, NDN_DTAG);
        res |= ndn_charbuf_append_charbuf(c, finalblockid);
        res |= ndn_charbuf_append_closer(c);
    }

    if (key_locator != NULL) {
	/* key_locator is a sub-type that should already be encoded */
	res |= ndn_charbuf_append_charbuf(c, key_locator);
    }
    
    res |= ndn_charbuf_append_closer(c);

    return(res == 0 ? 0 : -1);
}

static int
ndn_encode_Signature(struct ndn_charbuf *buf,
                     const char *digest_algorithm,
                     const void *witness,
                     size_t witness_size,
                     const struct ndn_signature *signature,
                     size_t signature_size)
{
    int res = 0;

    if (signature == NULL)
        return(-1);

    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_Signature, NDN_DTAG);

    if (digest_algorithm != NULL) {
        res |= ndn_charbuf_append_tt(buf, NDN_DTAG_DigestAlgorithm, NDN_DTAG);
        res |= ndn_charbuf_append_tt(buf, strlen(digest_algorithm), NDN_UDATA);
        res |= ndn_charbuf_append_string(buf, digest_algorithm);
        res |= ndn_charbuf_append_closer(buf);
    }

    if (witness != NULL) {
        res |= ndn_charbuf_append_tt(buf, NDN_DTAG_Witness, NDN_DTAG);
        res |= ndn_charbuf_append_tt(buf, witness_size, NDN_BLOB);
        res |= ndn_charbuf_append(buf, witness, witness_size);
        res |= ndn_charbuf_append_closer(buf);
    }

    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_SignatureBits, NDN_DTAG);
    res |= ndn_charbuf_append_tt(buf, signature_size, NDN_BLOB);
    res |= ndn_charbuf_append(buf, signature, signature_size);
    res |= ndn_charbuf_append_closer(buf);
    
    res |= ndn_charbuf_append_closer(buf);

    return(res == 0 ? 0 : -1);
}

/**
 * Encode and sign a ContentObject.
 * @param buf is the output buffer where encoded object is written.
 * @param Name is the ndnb-encoded name from ndn_name_init and friends.
 * @param SignedInfo is the ndnb-encoded info from ndn_signed_info_create.
 * @param data pintes to the raw data to be encoded.
 * @param size is the size, in bytes, of the raw data to be encoded.
 * @param digest_algorithm may be NULL for default.
 * @param private_key is the private key to use for signing.
 * @returns 0 for success or -1 for error.
 */
int
ndn_encode_ContentObject(struct ndn_charbuf *buf,
                         const struct ndn_charbuf *Name,
                         const struct ndn_charbuf *SignedInfo,
                         const void *data,
                         size_t size,
                         const char *digest_algorithm,
                         const struct ndn_pkey *private_key
                         )
{
    int res = 0;
    struct ndn_sigc *sig_ctx;
    struct ndn_signature *signature;
    size_t signature_size;
    struct ndn_charbuf *content_header;
    size_t closer_start;

    content_header = ndn_charbuf_create();
    res |= ndn_charbuf_append_tt(content_header, NDN_DTAG_Content, NDN_DTAG);
    if (size != 0)
        res |= ndn_charbuf_append_tt(content_header, size, NDN_BLOB);
    closer_start = content_header->length;
    res |= ndn_charbuf_append_closer(content_header);
    if (res < 0)
        return(-1);
    sig_ctx = ndn_sigc_create();
    if (sig_ctx == NULL)
        return(-1);
    if (0 != ndn_sigc_init(sig_ctx, digest_algorithm, private_key))
        return(-1);
    if (0 != ndn_sigc_update(sig_ctx, Name->buf, Name->length))
        return(-1);
    if (0 != ndn_sigc_update(sig_ctx, SignedInfo->buf, SignedInfo->length))
        return(-1);
    if (0 != ndn_sigc_update(sig_ctx, content_header->buf, closer_start))
        return(-1);
    if (0 != ndn_sigc_update(sig_ctx, data, size))
        return(-1);
    if (0 != ndn_sigc_update(sig_ctx, content_header->buf + closer_start,
                             content_header->length - closer_start))
        return(-1);
    signature = calloc(1, ndn_sigc_signature_max_size(sig_ctx, private_key));
    if (signature == NULL)
        return(-1);
    res = ndn_sigc_final(sig_ctx, signature, &signature_size, private_key);
    if (0 != res) {
        free(signature);
        return(-1);
    }
    ndn_sigc_destroy(&sig_ctx);
    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_ContentObject, NDN_DTAG);
    res |= ndn_encode_Signature(buf, digest_algorithm,
                                NULL, 0, signature, signature_size);
    res |= ndn_charbuf_append_charbuf(buf, Name);
    res |= ndn_charbuf_append_charbuf(buf, SignedInfo);
    res |= ndnb_append_tagged_blob(buf, NDN_DTAG_Content, data, size);
    res |= ndn_charbuf_append_closer(buf);
    free(signature);
    ndn_charbuf_destroy(&content_header);
    return(res == 0 ? 0 : -1);
}

/***********************************
 * Append a StatusResponse
 * 
 *  @param buf is the buffer to append to.
 *  @param errcode is a 3-digit error code.
 *            It should be documented in StatusResponse.txt.
 *  @param errtext is human-readable text (may be NULL).
 *  @returns 0 for success or -1 for error.
 */
int
ndn_encode_StatusResponse(struct ndn_charbuf *buf,
                          int errcode, const char *errtext)
{
    int res = 0;
    if (errcode < 100 || errcode > 999)
        return(-1);
    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_StatusResponse, NDN_DTAG);
    res |= ndnb_tagged_putf(buf, NDN_DTAG_StatusCode, "%d", errcode);
    if (errtext != NULL && errtext[0] != 0)
        res |= ndnb_tagged_putf(buf, NDN_DTAG_StatusText, "%s", errtext);
    res |= ndn_charbuf_append_closer(buf);
    return(res);
}

/**
 * Append a ndnb start marker
 *
 * This forms the basic building block of ndnb-encoded data.
 * @param c is the buffer to append to.
 * @param val is the numval, intepreted according to tt (see enum ndn_tt).
 * @param tt is the type field.
 * @returns 0 for success or -1 for error.
 */
int
ndn_charbuf_append_tt(struct ndn_charbuf *c, size_t val, enum ndn_tt tt)
{
    unsigned char buf[1+8*((sizeof(val)+6)/7)];
    unsigned char *p = &(buf[sizeof(buf)-1]);
    int n = 1;
    p[0] = (NDN_TT_HBIT & ~NDN_CLOSE) |
           ((val & NDN_MAX_TINY) << NDN_TT_BITS) |
           (NDN_TT_MASK & tt);
    val >>= (7-NDN_TT_BITS);
    while (val != 0) {
        (--p)[0] = (((unsigned char)val) & ~NDN_TT_HBIT) | NDN_CLOSE;
        n++;
        val >>= 7;
    }
    return(ndn_charbuf_append(c, p, n));
}

int
ndn_charbuf_append_closer(struct ndn_charbuf *c)
{
    int res;
    const unsigned char closer = NDN_CLOSE;
    res = ndn_charbuf_append(c, &closer, 1);
    return(res);
}

/**
 * Append a non-negative integer as a UDATA.
 * @param c is the buffer to append to.
 * @param nni is a non-negative value.
 * @returns 0 for success or -1 for error.
 */
int
ndnb_append_number(struct ndn_charbuf *c, int nni)
{
    char nnistring[40];
    int nnistringlen;
    int res;

    if (nni < 0)
        return(-1);
    nnistringlen = snprintf(nnistring, sizeof(nnistring), "%d", nni);
    if (nnistringlen >= sizeof(nnistring))
        return(-1);
    res = ndn_charbuf_append_tt(c, nnistringlen, NDN_UDATA);
    res |= ndn_charbuf_append_string(c, nnistring);
    return(res);
}

/**
 * Append a binary timestamp
 * as a BLOB using the ndn binary Timestamp representation (12-bit fraction).
 * @param c is the buffer to append to.
 * @param marker
 *   If marker >= 0, the low-order byte is used as a marker byte, useful for
 *   some content naming conventions (versioning, in particular).
 * @param secs - seconds since epoch
 * @param nsecs - nanoseconds
 * @returns 0 for success or -1 for error.
 */
int
ndnb_append_timestamp_blob(struct ndn_charbuf *c,
                           enum ndn_marker marker,
                           intmax_t secs, int nsecs)
{
    int i;
    int n;
    uintmax_t ts, tsh;
    int tsl;
    unsigned char *p;
    if (secs <= 0 || nsecs < 0 || nsecs > 999999999)
        return(-1);
    /* arithmetic contortions are to avoid overflowing 31 bits */
    tsl = ((int)(secs & 0xf) << 12) + ((nsecs / 5 * 8 + 195312) / 390625);
    tsh = (secs >> 4) + (tsl >> 16);
    tsl &= 0xffff;
    n = 2;
    for (ts = tsh; n < 7 && ts != 0; ts >>= 8)
        n++;
    ndn_charbuf_append_tt(c, n + (marker >= 0), NDN_BLOB);
    if (marker >= 0)
        ndn_charbuf_append_value(c, marker, 1);
    p = ndn_charbuf_reserve(c, n);
    if (p == NULL)
        return(-1);
    for (i = 0; i < n - 2; i++)
        p[i] = tsh >> (8 * (n - 3 - i));
    for (i = n - 2; i < n; i++)
        p[i] = tsl >> (8 * (n - 1 - i));
    c->length += n;
    return(0);
}

/**
 * Append a binary timestamp, using the current time.
 * 
 * Like ndnb_append_timestamp_blob() but uses current time
 * @param c is the buffer to append to.
 * @param marker - see ndnb_append_timestamp_blob()
 * @returns 0 for success or -1 for error.
 */
int
ndnb_append_now_blob(struct ndn_charbuf *c, enum ndn_marker marker)
{
    struct timeval now;
    int res;

    gettimeofday(&now, NULL);
    res = ndnb_append_timestamp_blob(c, marker, now.tv_sec, now.tv_usec * 1000);
    return(res);
}

/**
 * Append a start-of-element marker.
 */
int
ndnb_element_begin(struct ndn_charbuf *c, enum ndn_dtag dtag)
{
    return(ndn_charbuf_append_tt(c, dtag, NDN_DTAG));
}

/**
 * Append an end-of-element marker.
 *
 * This is the same as ndn_charbuf_append_closer()
 */
int ndnb_element_end(struct ndn_charbuf *c)
{
    return(ndn_charbuf_append_closer(c));
}

/**
 * Append a tagged BLOB
 *
 * This is a ndnb-encoded element with containing the BLOB as content
 * @param c is the buffer to append to.
 * @param dtag is the element's dtab
 * @param data points to the binary data
 * @param size is the size of the data, in bytes
 * @returns 0 for success or -1 for error.
 */
int
ndnb_append_tagged_blob(struct ndn_charbuf *c,
                        enum ndn_dtag dtag,
                        const void *data,
                        size_t size)
{
    int res;

    res = ndn_charbuf_append_tt(c, dtag, NDN_DTAG);
    if (size != 0) {
        res |= ndn_charbuf_append_tt(c, size, NDN_BLOB);
        res |= ndn_charbuf_append(c, data, size);
    }
    res |= ndn_charbuf_append_closer(c);
    return(res == 0 ? 0 : -1);
}
/**
 * Append a tagged binary number as a blob containing the integer value
 *
 * This is a ndnb-encoded element holding a 
 * @param cb is the buffer to append to.
 * @param dtag is the element's dtab
 * @param val is the unsigned integer to be appended
 * @returns 0 for success or -1 for error.
 */
int
ndnb_append_tagged_binary_number(struct ndn_charbuf *cb,
                                 enum ndn_dtag dtag,
                                 uintmax_t val) {
    unsigned char buf[sizeof(val)];
    int pos;
    int res = 0;
    for (pos = sizeof(buf); val != 0 && pos > 0; val >>= 8)
        buf[--pos] = val & 0xff;
    res |= ndnb_append_tagged_blob(cb, dtag, buf+pos, sizeof(buf)-pos);
    return(res);
}

/**
 * Append a tagged UDATA string, with printf-style formatting
 *
 * This is a ndnb-encoded element with containing UDATA as content.
 * @param c is the buffer to append to.
 * @param dtag is the element's dtab.
 * @param fmt is a printf-style format string, followed by its values
 * @returns 0 for success or -1 for error.
 */
int
ndnb_tagged_putf(struct ndn_charbuf *c,
                 enum ndn_dtag dtag, const char *fmt, ...)
{
    int res;
    int size;
    va_list ap;
    char *ptr;
    
    res = ndn_charbuf_append_tt(c, dtag, NDN_DTAG);
    if (res < 0)
        return(-1);
    ptr = (char *)ndn_charbuf_reserve(c, strlen(fmt) + 20);
    if (ptr == NULL)
        return(-1);
    va_start(ap, fmt);
    size = vsnprintf(ptr + 2, (c->limit - c->length - 2), fmt, ap);
    va_end(ap);
    if (size < 0)
        return(-1);
    if (size > 0) {
        if (size >= (c->limit - c->length - 2))
            ptr = NULL;
        res |= ndn_charbuf_append_tt(c, size, NDN_UDATA);
        if (ptr == (char *)c->buf + c->length + 2)
            c->length += size;
        else if (ptr == (char *)c->buf + c->length + 1) {
            memmove(ptr - 1, ptr, size);
            c->length += size;
        }
        else {
            ptr = (char *)ndn_charbuf_reserve(c, size + 1);
            va_start(ap, fmt);
            size = vsnprintf(ptr, size + 1, fmt, ap);
            va_end(ap);
            if (size < 0)
                return(-1);
            c->length += size;
        }
    }
    res |= ndn_charbuf_append_closer(c);
    return(res == 0 ? 0 : -1);    
}

/**
 * Append a representation of a Link to a charbuf.
 * @param buf is the output buffer where encoded link is written.
 * @param name is the ndnb-encoded name from ndn_name_init and friends.
 * @param label is a UTF-8 string in a ndn_charbuf.
 * @param linkAuthenticator is the ndnb-encoded LinkAuthenticator.
 * @returns 0 for success or -1 for error.
 */
int
ndnb_append_Link(struct ndn_charbuf *buf,
                 const struct ndn_charbuf *name,
                 const char *label,
                 const struct ndn_charbuf *linkAuthenticator
                 )
{
    int res = 0;
    
    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_Link, NDN_DTAG);
    res |= ndn_charbuf_append_charbuf(buf, name);
    if (label != NULL) {
        res |= ndn_charbuf_append_tt(buf, NDN_DTAG_Label, NDN_DTAG);
        res |= ndn_charbuf_append_tt(buf, strlen(label), NDN_UDATA);
        res |= ndn_charbuf_append_string(buf, label);
        res |= ndn_charbuf_append_closer(buf);
    }
    if (linkAuthenticator != NULL) {
        res |= ndn_charbuf_append_charbuf(buf, linkAuthenticator);
    }
    res |= ndn_charbuf_append_closer(buf);
    return(res == 0 ? 0 : -1);
}

