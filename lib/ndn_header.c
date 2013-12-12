/**
 * @file ndn_header.c
 * @brief Support for parsing and creating file headers
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009, 2013 Palo Alto Research Center, Inc.
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
#include <ndn/coding.h>

#include <ndn/header.h>

const unsigned char meta[8] = {NDN_MARKER_CONTROL, '.', 'M', 'E', 'T', 'A', '.', 'M'};

int
ndn_parse_tagged_required_uintmax(struct ndn_buf_decoder *d, enum ndn_dtag dtag, uintmax_t *result)
{
    int res = -1;
    if (ndn_buf_match_dtag(d, dtag)) {
        ndn_buf_advance(d);
        res = ndn_parse_uintmax(d, result);
        ndn_buf_check_close(d);
    } else {
        return (d->decoder.state = -__LINE__);
    }
    return (res);
}
/**
 * Parse a ndnb-encoded Header 
 */
struct ndn_header *
ndn_header_parse(const unsigned char *p, size_t size)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, p, size);
    struct ndn_header *result;
    const unsigned char *blob;
    size_t blobsize;
    int res = 0;

    result = calloc(1, sizeof(*result));
    if (result == NULL)
        return (NULL);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Header)) {
        ndn_buf_advance(d);
        res |= ndn_parse_tagged_required_uintmax(d, NDN_DTAG_Start, &result->start);
        res |= ndn_parse_tagged_required_uintmax(d, NDN_DTAG_Count, &result->count);
        res |= ndn_parse_tagged_required_uintmax(d, NDN_DTAG_BlockSize, &result->block_size);
        res |= ndn_parse_tagged_required_uintmax(d, NDN_DTAG_Length, &result->length);
        if (res != 0) {
            free(result);
            return (NULL);
        }
        if (ndn_buf_match_dtag(d, NDN_DTAG_ContentDigest)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, &blob, &blobsize)) {
                result->content_digest = ndn_charbuf_create();
                ndn_charbuf_append(result->content_digest, blob, blobsize);
                ndn_buf_advance(d);
            }
            ndn_buf_check_close(d);
        }
        if (ndn_buf_match_dtag(d, NDN_DTAG_RootDigest)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, &blob, &blobsize)) {
                result->root_digest = ndn_charbuf_create();
                ndn_charbuf_append(result->root_digest, blob, blobsize);
                ndn_buf_advance(d);
            }
            ndn_buf_check_close(d);
        }
        ndn_buf_check_close(d);
    } 
    else
        d->decoder.state = -__LINE__;
    
    if (d->decoder.index != size || !NDN_FINAL_DSTATE(d->decoder.state)) {
        ndn_header_destroy(&result);
    }
    return (result);
}
/*
 * Destroy the result of a ndn_header_parse or ndn_get_header
 */
void
ndn_header_destroy(struct ndn_header **ph)
{
    if (*ph == NULL)
        return;
    ndn_charbuf_destroy(&(*ph)->root_digest);
    ndn_charbuf_destroy(&(*ph)->content_digest);
    free(*ph);
    *ph = NULL;
}

int
ndnb_append_header(struct ndn_charbuf *c,
                   const struct ndn_header *h)
{
    int res;
    res = ndnb_element_begin(c, NDN_DTAG_Header);
    res |= ndnb_tagged_putf(c, NDN_DTAG_Start, "%u", h->start);
    res |= ndnb_tagged_putf(c, NDN_DTAG_Count, "%u", h->count);
    res |= ndnb_tagged_putf(c, NDN_DTAG_BlockSize, "%u", h->block_size);
    res |= ndnb_tagged_putf(c, NDN_DTAG_Length, "%u", h->length);
    if (h->content_digest != NULL) {
        res |= ndnb_append_tagged_blob(c, NDN_DTAG_ContentDigest,
                                       h->content_digest->buf, h->content_digest->length);
    }
    if (h->root_digest != NULL) {
        res |= ndnb_append_tagged_blob(c, NDN_DTAG_RootDigest,
                                       h->root_digest->buf, h->root_digest->length);
    }
    res |= ndnb_element_end(c);
    return (res);
}

struct ndn_header *
ndn_get_header(struct ndn *h, struct ndn_charbuf *name, int timeout)
{
    struct ndn_charbuf *hn;
    struct ndn_header *result = NULL;
    int res;

    hn = ndn_charbuf_create();
    ndn_charbuf_append_charbuf(hn, name);
    /*
     * Requires consistency with metadata profile in
     * javasrc/src/main/org/ndnx/ndn/profiles/metadata/MetadataProfile.java
     */
    ndn_name_append(hn, meta, sizeof(meta));
    ndn_name_append_str(hn, ".header");
    res = ndn_resolve_version(h, hn, NDN_V_HIGHEST, timeout);
    if (res <= 0) {
        /* Version not found: try old header name from prior to 04/2010 */
        ndn_charbuf_reset(hn);
        ndn_charbuf_append_charbuf(hn, name);
        ndn_name_append_str(hn, "_meta_");
        ndn_name_append_str(hn, ".header");
        res = ndn_resolve_version(h, hn, NDN_V_HIGHEST, timeout);
    }
    /* headers must be versioned */
    if (res > 0) {
        struct ndn_charbuf *ho = ndn_charbuf_create();
        struct ndn_parsed_ContentObject pcobuf = { 0 };
        const unsigned char *hc;
        size_t hcs;

        res = ndn_get(h, hn, NULL, timeout, ho, &pcobuf, NULL, 0);
        if (res == 0) {
            hc = ho->buf;
            hcs = ho->length;
            ndn_content_get_value(hc, hcs, &pcobuf, &hc, &hcs);
            result = ndn_header_parse(hc, hcs);
        }
        ndn_charbuf_destroy(&ho);
    }
    ndn_charbuf_destroy(&hn);
    return (result);
}
