/**
 * @file ndn_reg_mgmt.c
 * @brief Support for parsing and creating ForwardingEntry elements.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/reg_mgmt.h>

struct ndn_forwarding_entry *
ndn_forwarding_entry_parse(const unsigned char *p, size_t size)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, p, size);
    struct ndn_charbuf *store = ndn_charbuf_create();
    struct ndn_forwarding_entry *result;
    const unsigned char *val;
    size_t sz;
    size_t start;
    size_t end;
    int action_off = -1;
    int ndnd_id_off = -1;
    
    if (store == NULL)
        return(NULL);
    result = calloc(1, sizeof(*result));
    if (result == NULL) {
        ndn_charbuf_destroy(&store);
        return(NULL);
    }
    if (ndn_buf_match_dtag(d, NDN_DTAG_ForwardingEntry)) {
        ndn_buf_advance(d);
        action_off = ndn_parse_tagged_string(d, NDN_DTAG_Action, store);
        if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
            result->name_prefix = ndn_charbuf_create();
            start = d->decoder.token_index;
            ndn_parse_Name(d, NULL);
            end = d->decoder.token_index;
            ndn_charbuf_append(result->name_prefix, p + start, end - start);
        }
        else
            result->name_prefix = NULL;
        if (ndn_buf_match_dtag(d, NDN_DTAG_PublisherPublicKeyDigest)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, &val, &sz)) {
                ndn_buf_advance(d);
                if (sz != 32)
                    d->decoder.state = -__LINE__;
            }
            ndn_buf_check_close(d);
            if (d->decoder.state >= 0) {
                ndnd_id_off = store->length;
                ndn_charbuf_append(store, val, sz);
                result->ndnd_id_size = sz;
            }
        }
        result->faceid = ndn_parse_optional_tagged_nonNegativeInteger(d, NDN_DTAG_FaceID);
        result->flags = ndn_parse_optional_tagged_nonNegativeInteger(d, NDN_DTAG_ForwardingFlags);
        result->lifetime = ndn_parse_optional_tagged_nonNegativeInteger(d, NDN_DTAG_FreshnessSeconds);
        ndn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    
    if (d->decoder.index != size || !NDN_FINAL_DSTATE(d->decoder.state) ||
        store->length > sizeof(result->store))
        ndn_forwarding_entry_destroy(&result);
    else {
        char *b = (char *)result->store;
        memcpy(b, store->buf, store->length);
        result->action = (action_off == -1) ? NULL : b + action_off;
        result->ndnd_id = (ndnd_id_off == -1) ? NULL : result->store + ndnd_id_off;
    }
    ndn_charbuf_destroy(&store);
    return(result);
}

/**
 * Destroy the result of ndn_forwarding_entry_parse().
 */
void
ndn_forwarding_entry_destroy(struct ndn_forwarding_entry **pfe)
{
    if (*pfe == NULL)
        return;
    ndn_charbuf_destroy(&(*pfe)->name_prefix);
    free(*pfe);
    *pfe = NULL;
}

int
ndnb_append_forwarding_entry(struct ndn_charbuf *c,
                             const struct ndn_forwarding_entry *fe)
{
    int res;
    res = ndnb_element_begin(c, NDN_DTAG_ForwardingEntry);
    if (fe->action != NULL)
        res |= ndnb_tagged_putf(c, NDN_DTAG_Action, "%s",
                                   fe->action);
    if (fe->name_prefix != NULL && fe->name_prefix->length > 0)
        res |= ndn_charbuf_append(c, fe->name_prefix->buf,
                                     fe->name_prefix->length);
    if (fe->ndnd_id_size != 0)
        res |= ndnb_append_tagged_blob(c, NDN_DTAG_PublisherPublicKeyDigest,
                                          fe->ndnd_id, fe->ndnd_id_size);
    if (fe->faceid != ~0)
        res |= ndnb_tagged_putf(c, NDN_DTAG_FaceID, "%u",
                                   fe->faceid);
    if (fe->flags >= 0)
        res |= ndnb_tagged_putf(c, NDN_DTAG_ForwardingFlags, "%d",
                                   fe->flags);
    if (fe->lifetime >= 0)
        res |= ndnb_tagged_putf(c, NDN_DTAG_FreshnessSeconds, "%d",
                                   fe->lifetime);
    res |= ndnb_element_end(c);
    return(res);
}
