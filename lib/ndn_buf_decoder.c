/**
 * @file ndn_buf_decoder.c
 * @brief Support for Interest and ContentObject decoding.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2012 Palo Alto Research Center, Inc.
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
#include <stdlib.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>
#include <ndn/indexbuf.h>

struct ndn_buf_decoder *
ndn_buf_decoder_start(struct ndn_buf_decoder *d,
                      const unsigned char *buf, size_t size)
{
    memset(&d->decoder, 0, sizeof(d->decoder));
    d->decoder.state |= NDN_DSTATE_PAUSE;
    d->buf = buf;
    d->size = size;
    ndn_skeleton_decode(&d->decoder, buf, size);
    return(d);
}

void
ndn_buf_advance(struct ndn_buf_decoder *d)
{
    ndn_skeleton_decode(&d->decoder,
                        d->buf + d->decoder.index,
                        d->size - d->decoder.index);
}

int
ndn_buf_match_dtag(struct ndn_buf_decoder *d, enum ndn_dtag dtag)
{
    return (d->decoder.state >= 0 &&
            NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_DTAG &&
            d->decoder.numval == dtag);
}

int
ndn_buf_match_some_dtag(struct ndn_buf_decoder *d)
{
    return(d->decoder.state >= 0 &&
           NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_DTAG);
}

int
ndn_buf_match_some_blob(struct ndn_buf_decoder *d)
{
    return(d->decoder.state >= 0 &&
           NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_BLOB);
}

int
ndn_buf_match_blob(struct ndn_buf_decoder *d,
                   const unsigned char **bufp, size_t *sizep)
{
    if (ndn_buf_match_some_blob(d)) {
        if (bufp != NULL)
            *bufp = d->buf + d->decoder.index;
        if (sizep != NULL)
            *sizep = d->decoder.numval;
        return (1);
    }
    if (bufp != NULL)
        *bufp = d->buf + d->decoder.token_index;
    if (sizep != NULL)
        *sizep = 0;
    return(0);
}

int
ndn_buf_match_udata(struct ndn_buf_decoder *d, const char *s)
{
    size_t len = strlen(s);
    return (d->decoder.state >= 0 &&
            NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA &&
            d->decoder.numval == len &&
            0 == memcmp(d->buf + d->decoder.index, s, len));
}

int
ndn_buf_match_attr(struct ndn_buf_decoder *d, const char *s)
{
    size_t len = strlen(s);
    return (d->decoder.state >= 0 &&
            NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_ATTR &&
            d->decoder.numval == len &&
            0 == memcmp(d->buf + d->decoder.index, s, len));
}

void
ndn_buf_check_close(struct ndn_buf_decoder *d)
{
    if (d->decoder.state >= 0) {
        if (NDN_GET_TT_FROM_DSTATE(d->decoder.state) != NDN_NO_TOKEN)
            d->decoder.state = NDN_DSTATE_ERR_NEST;
        else
            ndn_buf_advance(d);
    }
}

int
ndn_buf_advance_past_element(struct ndn_buf_decoder *d)
{
    enum ndn_tt tt;
    int nest;
    if (d->decoder.state < 0)
        return(d->decoder.state);
    tt = NDN_GET_TT_FROM_DSTATE(d->decoder.state);
    if (tt == NDN_DTAG || tt == NDN_TAG) {
        nest = d->decoder.nest;
        ndn_buf_advance(d);
        while (d->decoder.state >= 0 && d->decoder.nest >= nest)
            ndn_buf_advance(d);
        /* The nest decrements before the closer is consumed */
        ndn_buf_check_close(d);
    }
    else
        return(-1);
    if (d->decoder.state < 0)
        return(d->decoder.state);
    return (0);
}

int
ndn_parse_required_tagged_BLOB(struct ndn_buf_decoder *d, enum ndn_dtag dtag,
                               int minlen, int maxlen)
{
    int res = -1;
    size_t len = 0;
    if (ndn_buf_match_dtag(d, dtag)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        if (ndn_buf_match_some_blob(d)) {
            len = d->decoder.numval;
            ndn_buf_advance(d);
        }
        ndn_buf_check_close(d);
        if (len < minlen || (maxlen >= 0 && len > maxlen)) {
            d->decoder.state = -__LINE__;
        }
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}

int
ndn_parse_optional_tagged_BLOB(struct ndn_buf_decoder *d, enum ndn_dtag dtag,
                               int minlen, int maxlen)
{
    if (ndn_buf_match_dtag(d, dtag))
        return(ndn_parse_required_tagged_BLOB(d, dtag, minlen, maxlen));
    return(-1);
}

uintmax_t
ndn_parse_required_tagged_binary_number(struct ndn_buf_decoder *d,
                                        enum ndn_dtag dtag,
                                        int minlen, int maxlen)
{
    uintmax_t value = 0;
    const unsigned char *p = NULL;
    size_t len = 0;
    int i;
    if (0 <= minlen && minlen <= maxlen && maxlen <= sizeof(value) &&
          ndn_buf_match_dtag(d, dtag)) {
        ndn_buf_advance(d);
        if (ndn_buf_match_blob(d, &p, &len))
            ndn_buf_advance(d);
        ndn_buf_check_close(d);
        if (d->decoder.state < 0)
            return(value);
        if (minlen <= len && len <= maxlen)
            for (i = 0; i < len; i++)
                value = (value << 8) + p[i];
        else
            d->decoder.state = -__LINE__;
    }
    else
        d->decoder.state = -__LINE__;
    return(value);
}

uintmax_t
ndn_parse_optional_tagged_binary_number(struct ndn_buf_decoder *d, enum ndn_dtag dtag,
int minlen, int maxlen, uintmax_t default_value)
{
    if (ndn_buf_match_dtag(d, dtag))
        return(ndn_parse_required_tagged_binary_number(d, dtag, minlen, maxlen));
    return(default_value);
}

int
ndn_parse_required_tagged_UDATA(struct ndn_buf_decoder *d, enum ndn_dtag dtag)
{
    int res = -1;
    if (ndn_buf_match_dtag(d, dtag)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        if (d->decoder.state >= 0 &&
            NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA)
            ndn_buf_advance(d);
        else
            d->decoder.state = -__LINE__;
        ndn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return (-1);
    return(res);
}

int
ndn_parse_optional_tagged_UDATA(struct ndn_buf_decoder *d, enum ndn_dtag dtag)
{
    if (ndn_buf_match_dtag(d, dtag))
        return(ndn_parse_required_tagged_UDATA(d, dtag));
    return(-1);
}

/**
 * Parses a ndnb-encoded element expected to contain a UDATA string.
 * @param d is the decoder
 * @param dtag is the expected dtag value
 * @param store - on success, the string value is appended to store,
 *        with null termination.
 * @returns the offset into the store buffer of the copied value, or -1 for error.
 *        If a parse error occurs, d->decoder.state is set to a negative value.
 *        If the element is not present, -1 is returned but no parse error
 *        is indicated.
 */
int
ndn_parse_tagged_string(struct ndn_buf_decoder *d, enum ndn_dtag dtag, struct ndn_charbuf *store)
{
    const unsigned char *p = NULL;
    size_t size = 0;
    int res;
    
    if (ndn_buf_match_dtag(d, dtag)) {
        ndn_buf_advance(d);
        if (d->decoder.state >= 0 &&
            NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA) {
            p = d->buf + d->decoder.index;
            size = d->decoder.numval;
            ndn_buf_advance(d);
        }
        ndn_buf_check_close(d);
        if (d->decoder.state >= 0) {
            // XXX - should check for valid utf-8 data.
            res = store->length;
            if (size > 0)
                ndn_charbuf_append(store, p, size);
            ndn_charbuf_append_value(store, 0, 1);
            return(res);
        }
    }
    return(-1);
}

/**
 * Parses a ndnb-encoded name
 * @param d is the decoder
 * @param components may be NULL, otherwise is filled in with the 
 *        Component boundary offsets
 * @returns the number of Components in the Name, or -1 if there is an error.
 */
int
ndn_parse_Name(struct ndn_buf_decoder *d, struct ndn_indexbuf *components)
{
    int ncomp = 0;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        if (components != NULL) components->n = 0;
        ndn_buf_advance(d);
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            if (components != NULL)
                ndn_indexbuf_append_element(components, d->decoder.token_index);
            ncomp += 1;
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, NULL, NULL))
                ndn_buf_advance(d);
            ndn_buf_check_close(d);
        }
        if (components != NULL)
            ndn_indexbuf_append_element(components, d->decoder.token_index);
        ndn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return(-1);
    else
        return(ncomp);
}

int
ndn_parse_PublisherID(struct ndn_buf_decoder *d, struct ndn_parsed_interest *pi)
{
    int res = -1;
    int iskey = 0;
    unsigned pubstart = d->decoder.token_index;
    unsigned keystart = pubstart;
    unsigned keyend = pubstart;
    unsigned pubend = pubstart;
    iskey = ndn_buf_match_dtag(d, NDN_DTAG_PublisherPublicKeyDigest);
    if (iskey                                                          ||
        ndn_buf_match_dtag(d, NDN_DTAG_PublisherCertificateDigest)     ||
        ndn_buf_match_dtag(d, NDN_DTAG_PublisherIssuerKeyDigest)       ||
        ndn_buf_match_dtag(d, NDN_DTAG_PublisherIssuerCertificateDigest)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        keystart = d->decoder.token_index;
        if (!ndn_buf_match_some_blob(d))
            return (d->decoder.state = -__LINE__);
        ndn_buf_advance(d);
        keyend = d->decoder.token_index;
        ndn_buf_check_close(d);
        pubend = d->decoder.token_index;
    }
    if (d->decoder.state < 0)
        return (d->decoder.state);
    if (pi != NULL) {
        pi->offset[NDN_PI_B_PublisherID] = pubstart;
        pi->offset[NDN_PI_B_PublisherIDKeyDigest] = keystart;
        pi->offset[NDN_PI_E_PublisherIDKeyDigest] = iskey ? keyend : keystart;
        pi->offset[NDN_PI_E_PublisherID] = pubend;
    }
    return(res);
}

static int
ndn_parse_optional_Any_or_Bloom(struct ndn_buf_decoder *d)
{
    int res;
    res = ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_Bloom, 1, 1024+8);
    if (res >= 0)
        return(res);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
        ndn_buf_advance(d);
        ndn_buf_check_close(d);
        res = 0;
    }
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}

int
ndn_parse_Exclude(struct ndn_buf_decoder *d)
{
    int res = -1;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Exclude)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        ndn_parse_optional_Any_or_Bloom(d);
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            ndn_parse_required_tagged_BLOB(d, NDN_DTAG_Component, 0, -1);
            ndn_parse_optional_Any_or_Bloom(d);
        }
        ndn_buf_check_close(d);
    }
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}



int
ndn_parse_nonNegativeInteger(struct ndn_buf_decoder *d)
{
    const unsigned char *p;
    int i;
    int n;
    unsigned val;
    unsigned newval;
    unsigned char c;
    if (d->decoder.state < 0)
        return(-1);
    if (NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA) {
        p = d->buf + d->decoder.index;
        n = d->decoder.numval;
        if (n < 1) { d->decoder.state = -__LINE__; return(-1); }
        val = 0;
        for (i = 0; i < n; i++) {
            c = p[i];
            if ('0' <= c && c <= '9') {
                newval = val * 10 + (c - '0');
                if (newval < val) {
                    d->decoder.state = -__LINE__;
                    return(-1);
                }
                val = newval;
            }
            else {
                d->decoder.state = -__LINE__;
                return(-1);
            }
        }
        ndn_buf_advance(d);
        return(val);
    }
    d->decoder.state = -__LINE__;
    return(-1);
}

/**
 * Parse a potentially large non-negative integer.
 *
 * @returns 0 for success, and the value is place in *result; for an error
 * a negative value is returned and *result is unchanged.
 */
int
ndn_parse_uintmax(struct ndn_buf_decoder *d, uintmax_t *result)
{
    const unsigned char *p;
    int i;
    int n;
    uintmax_t val;
    uintmax_t newval;
    unsigned char c;
    if (d->decoder.state < 0)
        return(d->decoder.state);
    if (NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA) {
        p = d->buf + d->decoder.index;
        n = d->decoder.numval;
        if (n < 1)
            return(d->decoder.state = -__LINE__);
        val = 0;
        for (i = 0; i < n; i++) {
            c = p[i];
            if ('0' <= c && c <= '9') {
                newval = val * 10 + (c - '0');
                if (newval < val)
                    return(d->decoder.state = -__LINE__);
                val = newval;
            }
            else
                return(d->decoder.state = -__LINE__);
        }
        ndn_buf_advance(d);
        *result = val;
        return(0);
    }
    return(d->decoder.state = -__LINE__);
}

int
ndn_parse_timestamp(struct ndn_buf_decoder *d)
{
    const unsigned char dlm[] = "--T::.Z";
    const unsigned char *p;
    int i;
    int k;
    int n;
    if (d->decoder.state < 0)
        return(d->decoder.state);
    if (NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_BLOB) {
        /* New-style binary timestamp, 12-bit fraction */
        n = d->decoder.numval;
        if (n < 3 || n > 7)
            return(d->decoder.state = -__LINE__);
        ndn_buf_advance(d);
        return(0);
    }
    if (NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA) {
        /* This is for some temporary back-compatibility */
        p = d->buf + d->decoder.index;
        n = d->decoder.numval;
        if (n < 8 || n > 40)
            return(d->decoder.state = -__LINE__);
        if (p[n - 1] != 'Z')
            return(d->decoder.state = -__LINE__);
        for (i = 0, k = 0; i < n && '0' <= p[i] && p[i] <= '9';) {
            i++;
            if (i < n && p[i] == dlm[k]) {
                if (dlm[k++] == 0)
                    return(d->decoder.state = -__LINE__);
                i++;
            }
        }
        if (k < 5)
            return(d->decoder.state = -__LINE__);
        if (!(i == n || i == n - 1))
            return(d->decoder.state = -__LINE__);
        ndn_buf_advance(d);
        return(0);
    }
    return(d->decoder.state = -__LINE__);
}

int
ndn_parse_required_tagged_timestamp(struct ndn_buf_decoder *d, enum ndn_dtag dtag)
{
    int res = -1;
    if (ndn_buf_match_dtag(d, dtag)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        ndn_parse_timestamp(d);
        ndn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return (-1);
    return(res);
}

int
ndn_parse_optional_tagged_nonNegativeInteger(struct ndn_buf_decoder *d, enum ndn_dtag dtag)
{
    int res = -1;
    if (ndn_buf_match_dtag(d, dtag)) {
        ndn_buf_advance(d);
        res = ndn_parse_nonNegativeInteger(d);
        ndn_buf_check_close(d);
    }
    if (d->decoder.state < 0)
        return (-1);
    return(res);
}

int
ndn_fetch_tagged_nonNegativeInteger(enum ndn_dtag tt,
                                    const unsigned char *buf,
                                    size_t start, size_t stop)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    int result = -1;
    if (stop < start) return(-1);
    d = ndn_buf_decoder_start(&decoder, buf + start, stop - start);
    if (ndn_buf_match_dtag(d, tt)) {
        ndn_buf_advance(d);
        result = ndn_parse_nonNegativeInteger(d);
        ndn_buf_check_close(d);
    }
    if (result < 0)
        return(-1);
    return(result);
}


int
ndn_parse_interest(const unsigned char *msg, size_t size,
                   struct ndn_parsed_interest *interest,
                   struct ndn_indexbuf *components)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, msg, size);
    int magic = 0;
    int ncomp = 0;
    int res;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Interest)) {
        if (components == NULL) {
            /* We need to have the component offsets. */
            components = ndn_indexbuf_create();
            if (components == NULL) return(-1);
            res = ndn_parse_interest(msg, size, interest, components);
            ndn_indexbuf_destroy(&components);
            return(res);
        }
        ndn_buf_advance(d);
        interest->offset[NDN_PI_B_Name] = d->decoder.element_index;
        interest->offset[NDN_PI_B_Component0] = d->decoder.index;
        ncomp = ndn_parse_Name(d, components);
        if (d->decoder.state < 0) {
            memset(interest->offset, 0, sizeof(interest->offset));
            return(d->decoder.state);
        }
        interest->offset[NDN_PI_E_ComponentLast] = d->decoder.token_index - 1;
        interest->offset[NDN_PI_E_Name] = d->decoder.token_index;
        interest->prefix_comps = ncomp;
        interest->offset[NDN_PI_B_LastPrefixComponent] = components->buf[(ncomp > 0) ? (ncomp - 1) : 0];
        interest->offset[NDN_PI_E_LastPrefixComponent] = components->buf[ncomp];
        /* optional MinSuffixComponents, MaxSuffixComponents */
        interest->min_suffix_comps = 0;
        interest->max_suffix_comps = 32767;
        interest->offset[NDN_PI_B_MinSuffixComponents] = d->decoder.token_index;
        res = ndn_parse_optional_tagged_nonNegativeInteger(d,
                                                           NDN_DTAG_MinSuffixComponents);
        interest->offset[NDN_PI_E_MinSuffixComponents] = d->decoder.token_index;
        if (res >= 0)
            interest->min_suffix_comps = res;
        interest->offset[NDN_PI_B_MaxSuffixComponents] = d->decoder.token_index;
        res = ndn_parse_optional_tagged_nonNegativeInteger(d,
                                                           NDN_DTAG_MaxSuffixComponents);
        interest->offset[NDN_PI_E_MaxSuffixComponents] = d->decoder.token_index;
        if (res >= 0)
            interest->max_suffix_comps = res;
        if (interest->max_suffix_comps < interest->min_suffix_comps)
            return (d->decoder.state = -__LINE__);
        /* optional PublisherID */
        res = ndn_parse_PublisherID(d, interest);
        /* optional Exclude element */
        interest->offset[NDN_PI_B_Exclude] = d->decoder.token_index;
        res = ndn_parse_Exclude(d);
        interest->offset[NDN_PI_E_Exclude] = d->decoder.token_index;
        /* optional ChildSelector */
        interest->offset[NDN_PI_B_ChildSelector] = d->decoder.token_index;
        res = ndn_parse_optional_tagged_nonNegativeInteger(d,
                         NDN_DTAG_ChildSelector);
        if (res < 0)
            res = 0;
        interest->orderpref = res;
        interest->offset[NDN_PI_E_ChildSelector] = d->decoder.token_index;
        if (interest->orderpref > 5)
            return (d->decoder.state = -__LINE__);        
        /* optional AnswerOriginKind */
        interest->offset[NDN_PI_B_AnswerOriginKind] = d->decoder.token_index;
        interest->answerfrom = ndn_parse_optional_tagged_nonNegativeInteger(d,
                         NDN_DTAG_AnswerOriginKind);
        interest->offset[NDN_PI_E_AnswerOriginKind] = d->decoder.token_index;
        if (interest->answerfrom == -1)
            interest->answerfrom = NDN_AOK_DEFAULT;
        else if ((interest->answerfrom & NDN_AOK_NEW) != 0 &&
                 (interest->answerfrom & NDN_AOK_CS) == 0)
            return (d->decoder.state = -__LINE__);
        /* optional Scope */
        interest->offset[NDN_PI_B_Scope] = d->decoder.token_index;
        interest->scope = ndn_parse_optional_tagged_nonNegativeInteger(d,
                         NDN_DTAG_Scope);
        interest->offset[NDN_PI_E_Scope] = d->decoder.token_index;
        if (interest->scope > 9)
                return (d->decoder.state = -__LINE__);
        if ((interest->answerfrom & NDN_AOK_EXPIRE) != 0 &&
            interest->scope != 0)
                return (d->decoder.state = -__LINE__);
        /* optional InterestLifetime */
        interest->offset[NDN_PI_B_InterestLifetime] = d->decoder.token_index;
        res = ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_InterestLifetime, 1, 8);
        if (res >= 0)
            magic |= 20100401;
        interest->offset[NDN_PI_E_InterestLifetime] = d->decoder.token_index;
        /* optional Nonce */
        interest->offset[NDN_PI_B_Nonce] = d->decoder.token_index;
        res = ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_Nonce, 4, 64);
        interest->offset[NDN_PI_E_Nonce] = d->decoder.token_index;
        interest->offset[NDN_PI_B_OTHER] = d->decoder.token_index;
        /* this is for local use */
        ndn_parse_optional_tagged_nonNegativeInteger(d, NDN_DTAG_FaceID);
        interest->offset[NDN_PI_E_OTHER] = d->decoder.token_index;
        ndn_buf_check_close(d);
        interest->offset[NDN_PI_E] = d->decoder.index;
    }
    else
        return (d->decoder.state = -__LINE__);
    if (d->decoder.state < 0)
        return (d->decoder.state);
    if (d->decoder.index != size || !NDN_FINAL_DSTATE(d->decoder.state))
        return (NDN_DSTATE_ERR_CODING);
    if (magic == 0)
        magic = 20090701;
    if (!(magic == 20090701 || magic == 20100401))
        return (d->decoder.state = -__LINE__);
    interest->magic = magic;
    return (ncomp);
}

struct parsed_KeyName {
    int Name;
    int endName;
    int PublisherID;
    int endPublisherID;
};

static int
ndn_parse_KeyName(struct ndn_buf_decoder *d, struct parsed_KeyName *x)
{
    int res = -1;
    if (ndn_buf_match_dtag(d, NDN_DTAG_KeyName)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        x->Name = d->decoder.token_index;
        ndn_parse_Name(d, NULL);
        x->endName = d->decoder.token_index;
        x->PublisherID = ndn_parse_PublisherID(d, NULL);
        x->endPublisherID = d->decoder.token_index;
        ndn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}

static int
ndn_parse_Signature(struct ndn_buf_decoder *d, struct ndn_parsed_ContentObject *x)
{
    int res = -1;
    int i;
    struct ndn_parsed_ContentObject dummy;
    if (x == NULL)
        x = &dummy;
    for (i = NDN_PCO_B_Signature; i <= NDN_PCO_E_Signature; i++) {
        x->offset[i] = d->decoder.token_index;
    }
    if (ndn_buf_match_dtag(d, NDN_DTAG_Signature)) {
        res = d->decoder.element_index;
        ndn_buf_advance(d);
        x->offset[NDN_PCO_B_DigestAlgorithm] = d->decoder.token_index;
        ndn_parse_optional_tagged_UDATA(d, NDN_DTAG_DigestAlgorithm);
        x->offset[NDN_PCO_E_DigestAlgorithm] = d->decoder.token_index;
        x->offset[NDN_PCO_B_Witness] = d->decoder.token_index;
        ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_Witness, 8, -1);
        x->offset[NDN_PCO_E_Witness] = d->decoder.token_index;
        x->offset[NDN_PCO_B_SignatureBits] = d->decoder.token_index;
        ndn_parse_required_tagged_BLOB(d, NDN_DTAG_SignatureBits, 16, -1);
        x->offset[NDN_PCO_E_SignatureBits] = d->decoder.token_index;
        ndn_buf_check_close(d);
        x->offset[NDN_PCO_E_Signature] = d->decoder.token_index;
    }
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}

static int
ndn_parse_SignedInfo(struct ndn_buf_decoder *d, struct ndn_parsed_ContentObject *x)
{
    x->offset[NDN_PCO_B_SignedInfo] = d->decoder.token_index;
    if (ndn_buf_match_dtag(d, NDN_DTAG_SignedInfo)) {
        ndn_buf_advance(d);
        x->offset[NDN_PCO_B_PublisherPublicKeyDigest] = d->decoder.token_index;
        ndn_parse_required_tagged_BLOB(d, NDN_DTAG_PublisherPublicKeyDigest, 16, 64);
        x->offset[NDN_PCO_E_PublisherPublicKeyDigest] = d->decoder.token_index;
        
        x->offset[NDN_PCO_B_Timestamp] = d->decoder.token_index;
        ndn_parse_required_tagged_timestamp(d, NDN_DTAG_Timestamp);
        x->offset[NDN_PCO_E_Timestamp] = d->decoder.token_index;
        
        x->offset[NDN_PCO_B_Type] = d->decoder.token_index;
        x->type = NDN_CONTENT_DATA;
        x->type = ndn_parse_optional_tagged_binary_number(d, NDN_DTAG_Type, 3, 3, NDN_CONTENT_DATA);
        x->offset[NDN_PCO_E_Type] = d->decoder.token_index;
        
        x->offset[NDN_PCO_B_FreshnessSeconds] = d->decoder.token_index;
        ndn_parse_optional_tagged_nonNegativeInteger(d, NDN_DTAG_FreshnessSeconds);
        x->offset[NDN_PCO_E_FreshnessSeconds] = d->decoder.token_index;
        
        x->offset[NDN_PCO_B_FinalBlockID] = d->decoder.token_index;
        ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_FinalBlockID, 1, -1);
        x->offset[NDN_PCO_E_FinalBlockID] = d->decoder.token_index;
        
        x->offset[NDN_PCO_B_KeyLocator] = d->decoder.token_index;
        x->offset[NDN_PCO_B_Key_Certificate_KeyName] = d->decoder.token_index;
        x->offset[NDN_PCO_E_Key_Certificate_KeyName] = d->decoder.token_index;
        x->offset[NDN_PCO_B_KeyName_Name] = d->decoder.token_index;
        x->offset[NDN_PCO_E_KeyName_Name] = d->decoder.token_index;
        x->offset[NDN_PCO_B_KeyName_Pub] = d->decoder.token_index;
        x->offset[NDN_PCO_E_KeyName_Pub] = d->decoder.token_index;
        if (ndn_buf_match_dtag(d, NDN_DTAG_KeyLocator)) {
            ndn_buf_advance(d);
            x->offset[NDN_PCO_B_Key_Certificate_KeyName] = d->decoder.token_index;
            if (ndn_buf_match_dtag(d, NDN_DTAG_Key)) {
                (void)ndn_parse_required_tagged_BLOB(d, NDN_DTAG_Key, 0, -1);
            }
            else if (ndn_buf_match_dtag(d, NDN_DTAG_Certificate)) {
                (void)ndn_parse_required_tagged_BLOB(d, NDN_DTAG_Certificate, 0, -1);
            }
            else {
                struct parsed_KeyName keyname = {-1, -1, -1, -1};
                if (ndn_parse_KeyName(d, &keyname) >= 0) {
                    if (keyname.Name >= 0) {
                        x->offset[NDN_PCO_B_KeyName_Name] = keyname.Name;
                        x->offset[NDN_PCO_E_KeyName_Name] = keyname.endName;
                    }
                    if (keyname.PublisherID >= 0) {
                        x->offset[NDN_PCO_B_KeyName_Pub] = keyname.PublisherID;
                        x->offset[NDN_PCO_E_KeyName_Pub] = keyname.endPublisherID;
                    }
                }
            }
            x->offset[NDN_PCO_E_Key_Certificate_KeyName] = d->decoder.token_index;
            ndn_buf_check_close(d);
        }
        x->offset[NDN_PCO_E_KeyLocator] = d->decoder.token_index;
        
        x->offset[NDN_PCO_B_ExtOpt] = d->decoder.token_index;
        ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_ExtOpt, 2, -1);
        x->offset[NDN_PCO_E_ExtOpt] = d->decoder.token_index;
        
        ndn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    x->offset[NDN_PCO_E_SignedInfo] = d->decoder.token_index;
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(0);
}

int
ndn_parse_ContentObject(const unsigned char *msg, size_t size,
                        struct ndn_parsed_ContentObject *x,
                        struct ndn_indexbuf *components)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, msg, size);
    int res;
    x->magic = 20090415;
    x->digest_bytes = 0;
    if (ndn_buf_match_dtag(d, NDN_DTAG_ContentObject)) {
        ndn_buf_advance(d);
        res = ndn_parse_Signature(d, x);
        x->offset[NDN_PCO_B_Name] = d->decoder.token_index;
        x->offset[NDN_PCO_B_Component0] = d->decoder.index;
        res = ndn_parse_Name(d, components);
        if (res < 0)
            d->decoder.state = -__LINE__;
        x->name_ncomps = res;
        x->offset[NDN_PCO_E_ComponentLast] = d->decoder.token_index - 1;
        x->offset[NDN_PCO_E_Name] = d->decoder.token_index;
        ndn_parse_SignedInfo(d, x);
        x->offset[NDN_PCO_B_Content] = d->decoder.token_index;
        ndn_parse_required_tagged_BLOB(d, NDN_DTAG_Content, 0, -1);
        x->offset[NDN_PCO_E_Content] = d->decoder.token_index;
        ndn_buf_check_close(d);
        x->offset[NDN_PCO_E] = d->decoder.index;
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.index != size || !NDN_FINAL_DSTATE(d->decoder.state))
        return (NDN_DSTATE_ERR_CODING);
    return(0);
}

int
ndn_ref_tagged_BLOB(enum ndn_dtag tt,
                    const unsigned char *buf, size_t start, size_t stop,
                    const unsigned char **presult, size_t *psize)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    if (stop < start) return(-1);
    d = ndn_buf_decoder_start(&decoder, buf + start, stop - start);
    if (ndn_buf_match_dtag(d, tt)) {
        ndn_buf_advance(d);
        if (ndn_buf_match_blob(d, presult, psize))
            ndn_buf_advance(d);
        ndn_buf_check_close(d);
    }
    else
        return(-1);
    if (d->decoder.index != d->size || !NDN_FINAL_DSTATE(d->decoder.state))
        return (NDN_DSTATE_ERR_CODING);
    return(0);
}
/**
 * Produce a pointer and length for the string in a ndnb-encoded tagged element
 * containing a UDATA string.
 * @param dtag is the expected dtag value
 * @param buf is a ndnb-encoded source.
 * @param start is an offset into buf at which the element starts
 * @param stop is an offset into buf where the element ends
 * @param presult if non-NULL, a pointer through which pointer into buf
 *        for start of string will be stored
 * @param psize if non-NULL, a pointer through which size of string will be stored.
 * @returns 0 on success, <0 on failure.
 */

int
ndn_ref_tagged_string(enum ndn_dtag dtag,
                    const unsigned char *buf, size_t start, size_t stop,
                    const unsigned char **presult, size_t *psize)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    const unsigned char *result = NULL;
    size_t size = 0;

    if (stop < start) return(-1);
    d = ndn_buf_decoder_start(&decoder, buf + start, stop - start);
    if (ndn_buf_match_dtag(d, dtag)) {
        ndn_buf_advance(d);
        if (d->decoder.state >= 0 &&
            NDN_GET_TT_FROM_DSTATE(d->decoder.state) == NDN_UDATA) {
            result = d->buf + d->decoder.index;
            size = d->decoder.numval;
            ndn_buf_advance(d);
        }
        ndn_buf_check_close(d);
    }
    else
        return(-1);
    if (d->decoder.index != d->size || !NDN_FINAL_DSTATE(d->decoder.state))
        return (NDN_DSTATE_ERR_CODING);
    if (presult) *presult = result;
    if (psize) *psize = size;
    return(0);
}

static struct ndn_buf_decoder *
ndn_buf_decoder_start_at_components(struct ndn_buf_decoder *d,
    const unsigned char *buf, size_t buflen)
{
    ndn_buf_decoder_start(d, buf, buflen);
    while (ndn_buf_match_dtag(d, NDN_DTAG_Name) ||
           ndn_buf_match_dtag(d, NDN_DTAG_Interest) ||
           ndn_buf_match_dtag(d, NDN_DTAG_ContentObject)
           ) {
        ndn_buf_advance(d);
        ndn_parse_Signature(d, NULL);
    }
    return(d);
}

int
ndn_content_get_value(const unsigned char *data, size_t data_size,
                      const struct ndn_parsed_ContentObject *content,
                      const unsigned char **value, size_t *value_size)
{
    int res;
    res = ndn_ref_tagged_BLOB(NDN_DTAG_Content, data,
          content->offset[NDN_PCO_B_Content],
          content->offset[NDN_PCO_E_Content],
          value, value_size);
    return(res);
}

int
ndn_compare_names(const unsigned char *a, size_t asize,
                  const unsigned char *b, size_t bsize)
{
    struct ndn_buf_decoder a_decoder;
    struct ndn_buf_decoder b_decoder;
    struct ndn_buf_decoder *aa =
        ndn_buf_decoder_start_at_components(&a_decoder, a, asize);
    struct ndn_buf_decoder *bb =
        ndn_buf_decoder_start_at_components(&b_decoder, b, bsize);
    const unsigned char *acp = NULL;
    const unsigned char *bcp = NULL;
    size_t acsize;
    size_t bcsize;
    int cmp = 0;
    int more_a;
    for (;;) {
        more_a = ndn_buf_match_dtag(aa, NDN_DTAG_Component);
        cmp = more_a - ndn_buf_match_dtag(bb, NDN_DTAG_Component);
        if (more_a == 0 || cmp != 0)
            break;
        ndn_buf_advance(aa);
        ndn_buf_advance(bb);
        acsize = bcsize = 0;
        if (ndn_buf_match_blob(aa, &acp, &acsize))
            ndn_buf_advance(aa);
        if (ndn_buf_match_blob(bb, &bcp, &bcsize))
            ndn_buf_advance(bb);
        cmp = acsize - bcsize;
        if (cmp != 0)
            break;
        cmp = memcmp(acp, bcp, acsize);
        if (cmp != 0)
            break;
        ndn_buf_check_close(aa);
        ndn_buf_check_close(bb);
    }
    return (cmp);
}

int
ndn_parse_LinkAuthenticator(struct ndn_buf_decoder *d, struct ndn_parsed_Link *pl)
{    
    /* Implement with a single offset for the blob, NDN_PL_[BE]_PublisherDigest
     * and remember the DTAG value to indicate which type of digest it is
     */
    if (ndn_buf_match_dtag(d, NDN_DTAG_LinkAuthenticator)) {
        ndn_buf_advance(d);                         // advance over DTAG token
        pl->offset[NDN_PL_B_LinkAuthenticator] = d->decoder.token_index;
        pl->offset[NDN_PL_B_PublisherID] = d->decoder.token_index;
        pl->offset[NDN_PL_B_PublisherDigest] = d->decoder.token_index;
        pl->offset[NDN_PL_E_PublisherDigest] = d->decoder.token_index;
        
        if (ndn_buf_match_dtag(d, NDN_DTAG_PublisherPublicKeyDigest)      ||
            ndn_buf_match_dtag(d, NDN_DTAG_PublisherCertificateDigest)    ||
            ndn_buf_match_dtag(d, NDN_DTAG_PublisherIssuerKeyDigest)      ||
            ndn_buf_match_dtag(d, NDN_DTAG_PublisherIssuerCertificateDigest)) {
            pl->publisher_digest_type = d->decoder.numval;  // remember the DTAG 
            ndn_buf_advance(d);                         // over the DTAG token
            if (!ndn_buf_match_some_blob(d))
                return (d->decoder.state = -__LINE__);
            pl->offset[NDN_PL_B_PublisherDigest] = d->decoder.token_index;
            ndn_buf_advance(d);                         // over the digest
            pl->offset[NDN_PL_E_PublisherDigest] = d->decoder.token_index;
            ndn_buf_check_close(d);                     // over the DTAG closer
        }
        if (d->decoder.state < 0)
            return (d->decoder.state);
        pl->offset[NDN_PL_E_PublisherID] = d->decoder.token_index;
        
        /* parse optional NameComponentCount nonNegativeInteger */
        pl->offset[NDN_PL_B_NameComponentCount] = d->decoder.token_index;
        pl->name_component_count = ndn_parse_optional_tagged_nonNegativeInteger(d, NDN_DTAG_NameComponentCount);
        pl->offset[NDN_PL_E_NameComponentCount] = d->decoder.token_index;
        
        /* parse optional Timestamp TimestampType */
        pl->offset[NDN_PL_B_Timestamp] = d->decoder.token_index;
        if (ndn_buf_match_dtag(d, NDN_DTAG_Timestamp))
            ndn_parse_required_tagged_timestamp(d, NDN_DTAG_Timestamp);
        pl->offset[NDN_PL_E_Timestamp] = d->decoder.token_index;
        
        /* parse optional Type ContentType */
        pl->offset[NDN_PL_B_Type] = d->decoder.token_index;
        pl->type = ndn_parse_optional_tagged_binary_number(d, NDN_DTAG_Type, 3, 3, NDN_CONTENT_DATA);
        pl->offset[NDN_PL_E_Type] = d->decoder.token_index;
        
        /* parse optional ContentDigest Base64BinaryType */
        pl->offset[NDN_PL_B_ContentDigest] = d->decoder.token_index;
        ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_ContentDigest, 32, 32);
        pl->offset[NDN_PL_E_ContentDigest] = d->decoder.token_index;
        ndn_buf_check_close(d);
        pl->offset[NDN_PL_E_LinkAuthenticator] = d->decoder.token_index;
	} else
        d->decoder.state = -__LINE__;
    if (!NDN_FINAL_DSTATE(d->decoder.state))
        return (NDN_DSTATE_ERR_CODING);
    return(0);
}

int
ndn_parse_Link(struct ndn_buf_decoder *d,
               struct ndn_parsed_Link *link,
               struct ndn_indexbuf *components)
{
    int ncomp = 0;
    int res;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Link)) {
        if (components == NULL) {
            /* We need to have the component offsets. */
            components = ndn_indexbuf_create();
            if (components == NULL) return(-1);
            res = ndn_parse_Link(d, link, components);
            ndn_indexbuf_destroy(&components);
            return(res);
        }
        ndn_buf_advance(d);
        link->offset[NDN_PL_B_Name] = d->decoder.element_index;
        link->offset[NDN_PL_B_Component0] = d->decoder.index;
        ncomp = ndn_parse_Name(d, components);
        if (d->decoder.state < 0) {
            memset(link->offset, 0, sizeof(link->offset));
            return(d->decoder.state);
        }
        link->offset[NDN_PL_E_ComponentLast] = d->decoder.token_index - 1;
        link->offset[NDN_PL_E_Name] = d->decoder.token_index;
        link->name_ncomps = ncomp;
        /* parse optional Label string */
        link->offset[NDN_PL_B_Label] = d->decoder.token_index;
        res = ndn_parse_optional_tagged_UDATA(d, NDN_DTAG_Label);
        link->offset[NDN_PL_E_Label] = d->decoder.token_index;
        /* parse optional LinkAuthenticator LinkAuthenticatorType */
        if (ndn_buf_match_dtag(d, NDN_DTAG_LinkAuthenticator))
            res = ndn_parse_LinkAuthenticator(d, link);
        ndn_buf_check_close(d);
    }
    else
        return (d->decoder.state = -__LINE__);
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(ncomp);
}

int
ndn_parse_Collection_start(struct ndn_buf_decoder *d)
{
    if (ndn_buf_match_dtag(d, NDN_DTAG_Collection)) {
        ndn_buf_advance(d);
    }
    else
        return (d->decoder.state = -__LINE__);
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(0);    

}

int
ndn_parse_Collection_next(struct ndn_buf_decoder *d,
                          struct ndn_parsed_Link *link,
                          struct ndn_indexbuf *components)
{
    if (ndn_buf_match_dtag(d, NDN_DTAG_Link)) {
        return(ndn_parse_Link(d, link, components));
    } else
        ndn_buf_check_close(d);
    
    if (d->decoder.state < 0)
        return(d->decoder.state);
    else
        return(0);
}
