/**
 * @file ndn_seqwriter.c
 * @brief
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2010-2011 Palo Alto Research Center, Inc.
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
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <ndn/ndn.h>
#include <ndn/seqwriter.h>

#define MAX_DATA_SIZE 4096

struct ndn_seqwriter {
    struct ndn_closure cl;
    struct ndn *h;
    struct ndn_charbuf *nb;
    struct ndn_charbuf *nv;
    struct ndn_charbuf *buffer;
    struct ndn_charbuf *cob0;
    uintmax_t seqnum;
    int batching;
    int blockminsize;
    int blockmaxsize;
    int freshness;
    unsigned char interests_possibly_pending;
    unsigned char closed;
};

static struct ndn_charbuf *
seqw_next_cob(struct ndn_seqwriter *w)
{
    struct ndn_charbuf *cob = ndn_charbuf_create();
    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int res;
    
    if (w->closed)
        sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    if (w->freshness > -1)
        sp.freshness = w->freshness;
    ndn_charbuf_append(name, w->nv->buf, w->nv->length);
    ndn_name_append_numeric(name, NDN_MARKER_SEQNUM, w->seqnum);
    res = ndn_sign_content(w->h, cob, name, &sp, w->buffer->buf, w->buffer->length);
    if (res < 0)
        ndn_charbuf_destroy(&cob);
    ndn_charbuf_destroy(&name);
    return(cob);
}

static enum ndn_upcall_res
seqw_incoming_interest(
                       struct ndn_closure *selfp,
                       enum ndn_upcall_kind kind,
                       struct ndn_upcall_info *info)
{
    int res;
    struct ndn_charbuf *cob = NULL;
    struct ndn_seqwriter *w = selfp->data;
    
    if (w == NULL || selfp != &(w->cl))
        abort();
    switch (kind) {
        case NDN_UPCALL_FINAL:
            ndn_charbuf_destroy(&w->nb);
            ndn_charbuf_destroy(&w->nv);
            ndn_charbuf_destroy(&w->buffer);
            ndn_charbuf_destroy(&w->cob0);
            free(w);
            break;
        case NDN_UPCALL_INTEREST:
            if (w->closed || w->buffer->length > w->blockminsize) {
                cob = seqw_next_cob(w);
                if (cob == NULL)
                    return(NDN_UPCALL_RESULT_OK);
                if (ndn_content_matches_interest(cob->buf, cob->length,
                                                 1, NULL,
                                                 info->interest_ndnb,
                                                 info->pi->offset[NDN_PI_E],
                                                 info->pi)) {
                    w->interests_possibly_pending = 0;
                    res = ndn_put(info->h, cob->buf, cob->length);
                    if (res >= 0) {
                        w->buffer->length = 0;
                        w->seqnum++;
                        return(NDN_UPCALL_RESULT_INTEREST_CONSUMED);
                    }
                }
                ndn_charbuf_destroy(&cob);
            }
            if (w->cob0 != NULL) {
                cob = w->cob0;
                if (ndn_content_matches_interest(cob->buf, cob->length,
                                                 1, NULL,
                                                 info->interest_ndnb,
                                                 info->pi->offset[NDN_PI_E],
                                                 info->pi)) {
                    w->interests_possibly_pending = 0;
                    ndn_put(info->h, cob->buf, cob->length);
                    return(NDN_UPCALL_RESULT_INTEREST_CONSUMED);
                }
            }
            w->interests_possibly_pending = 1;
            break;
        default:
            break;
    }
    return(NDN_UPCALL_RESULT_OK);
}

/**
 * Create a seqwriter for writing data to a versioned, segmented stream.
 *
 * @param h is the ndn handle - must not be NULL.
 * @param name is a ndnb-encoded Name.  It will be provided with a version
 *        based on the current time unless it already ends in a version
 *        component.
 */
struct ndn_seqwriter *
ndn_seqw_create(struct ndn *h, struct ndn_charbuf *name)
{
    struct ndn_seqwriter *w = NULL;
    struct ndn_charbuf *nb = NULL;
    struct ndn_charbuf *nv = NULL;
    int res;
    
    w = calloc(1, sizeof(*w));
    if (w == NULL)
        return(NULL);
    nb = ndn_charbuf_create();
    ndn_charbuf_append(nb, name->buf, name->length);
    nv = ndn_charbuf_create();
    ndn_charbuf_append(nv, name->buf, name->length);
    res = ndn_create_version(h, nv, NDN_V_NOW, 0, 0);
    if (res < 0 || nb == NULL) {
        ndn_charbuf_destroy(&nv);
        ndn_charbuf_destroy(&nb);
        free(w);
        return(NULL);
    }
    
    w->cl.p = &seqw_incoming_interest;
    w->cl.data = w;
    w->nb = nb;
    w->nv = nv;
    w->buffer = ndn_charbuf_create();
    w->h = h;
    w->seqnum = 0;
    w->interests_possibly_pending = 1;
    w->blockminsize = 0;
    w->blockmaxsize = MAX_DATA_SIZE;
    w->freshness = -1;
    res = ndn_set_interest_filter(h, nb, &(w->cl));
    if (res < 0) {
        ndn_charbuf_destroy(&w->nb);
        ndn_charbuf_destroy(&w->nv);
        ndn_charbuf_destroy(&w->buffer);
        free(w);
        return(NULL);
    }
    return(w);
}

/**
 * Append to a charbuf the versioned ndnb-encoded Name that will be used for
 * this stream.
 *
 * @param w the seqwriter for which the name is requested
 * @param nv the charbuf to which the name will be appended
 * @returns 0 for success, -1 for failure
 */
int
ndn_seqw_get_name(struct ndn_seqwriter *w, struct ndn_charbuf *nv)
{
    if (nv == NULL || w == NULL)
        return (-1);
    return (ndn_charbuf_append_charbuf(nv, w->nv));
}

/**
 * Write some data to a seqwriter.
 *
 * This is roughly analogous to a write(2) call in non-blocking mode.
 *
 * The current implementation returns an error and refuses the new data if
 * it does not fit in the current buffer.
 * That is, there are no partial writes.
 * In this case, the caller should ndn_run() for a little while and retry.
 * 
 * It is also an error to attempt to write more than 4096 bytes.
 *
 * @returns the size written, or -1 for an error.  In case of an error,
 *          the caller may test ndn_geterror() for values of EAGAIN or
 *          EINVAL from errno.h.
 */
int
ndn_seqw_write(struct ndn_seqwriter *w, const void *buf, size_t size)
{
    struct ndn_charbuf *cob = NULL;
    int res;
    int ans;
    
    if (w == NULL || w->cl.data != w)
        return(-1);
    if (w->buffer == NULL || size > w->blockmaxsize)
        return(ndn_seterror(w->h, EINVAL));
    ans = size;
    if (size + w->buffer->length > w->blockmaxsize)
        ans = ndn_seterror(w->h, EAGAIN);
    else if (size != 0)
        ndn_charbuf_append(w->buffer, buf, size);
    if (w->interests_possibly_pending &&
        (w->closed || w->buffer->length >= w->blockminsize) &&
        (w->batching == 0 || ans == -1)) {
        cob = seqw_next_cob(w);
        if (cob != NULL) {
            res = ndn_put(w->h, cob->buf, cob->length);
            if (res >= 0) {
                if (w->seqnum == 0) {
                    w->cob0 = cob;
                    cob = NULL;
                }
                w->buffer->length = 0;
                w->seqnum++;
                w->interests_possibly_pending = 0;
            }
            ndn_charbuf_destroy(&cob);
        }
    }
    return(ans);
}

/**
 * Start a batch of writes.
 *
 * This will delay the signing of content objects until the batch ends,
 * producing a more efficient result.
 * Must have a matching ndn_seqw_batch_end() call.
 * Batching may be nested.
 */
int
ndn_seqw_batch_start(struct ndn_seqwriter *w)
{
    if (w == NULL || w->cl.data != w || w->closed)
        return(-1);
    return(++(w->batching));
}

/**
 * End a batch of writes.
 */
int
ndn_seqw_batch_end(struct ndn_seqwriter *w)
{
    if (w == NULL || w->cl.data != w || w->batching == 0)
        return(-1);
    if (--(w->batching) == 0)
        ndn_seqw_write(w, NULL, 0);
    return(w->batching);
}
int
ndn_seqw_set_block_limits(struct ndn_seqwriter *w, int l, int h)
{
    if (w == NULL || w->cl.data != w || w->closed)
        return(-1);
    if (l < 0 || l > MAX_DATA_SIZE || h < 0 || h > MAX_DATA_SIZE || l > h)
        return(-1);
    w->blockminsize = l;
    w->blockmaxsize = h;
    return(0);
}

int
ndn_seqw_set_freshness(struct ndn_seqwriter *w, int freshness)
{
    if (w == NULL || w->cl.data != w || w->closed)
        return(-1);
    if (freshness < -1)
        return(-1);
    w->freshness = freshness;
    return(0);
}
/**
 * Assert that an interest has possibly been expressed that matches
 * the seqwriter's data.  This is useful, for example, if the seqwriter
 * was created in response to an interest.
 */
int
ndn_seqw_possible_interest(struct ndn_seqwriter *w)
{
    if (w == NULL || w->cl.data != w)
        return(-1);
    w->interests_possibly_pending = 1;
    ndn_seqw_write(w, NULL, 0);
    return(0);
}

/**
 * Close the seqwriter, which will be freed.
 */
int
ndn_seqw_close(struct ndn_seqwriter *w)
{
    if (w == NULL || w->cl.data != w)
        return(-1);
    w->closed = 1;
    w->interests_possibly_pending = 1;
    w->batching = 0;
    ndn_seqw_write(w, NULL, 0);
    ndn_set_interest_filter(w->h, w->nb, NULL);
    return(0);
}
