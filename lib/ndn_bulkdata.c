/**
 * @file ndn_bulkdata.c
 * @brief (INCOMPLETE)Support for transport of bulk data.
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
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ndn/bloom.h>
#include <ndn/ndn.h>

/************ Candidate API stuff - was in ndn/ndn.h for a while ******/
/***********************************
 * Bulk data
 */

/*
 * The client provides a ndn_seqfunc * (and perhaps a matching param)
 * to specify the scheme for naming the content items in the sequence.
 * Given the sequence number x, it should place in resultbuf the
 * corresponding blob that that will be used in the final explicit
 * Component of the Name of item x in the sequence.  This should
 * act as a mathematical function, returning the same answer for a given x.
 * (Usually param will be NULL, but is provided in case it is needed.)
 */
typedef void ndn_seqfunc(uintmax_t x, void *param,
                         struct ndn_charbuf *resultbuf);

/*
 * Ready-to-use sequencing functions
 */
extern ndn_seqfunc ndn_decimal_seqfunc;
extern ndn_seqfunc ndn_binary_seqfunc;
/**********************************************************************/

/*
 * Encode the number in decimal ascii
 */
void
ndn_decimal_seqfunc(uintmax_t x, void *param, struct ndn_charbuf *resultbuf)
{
    (void)param; /* unused */
    assert(resultbuf->length == 0);
    ndn_charbuf_putf(resultbuf, "%ju", x);
}

/*
 * Encode the number in big-endian binary, using one more than the
 * minimum number of bytes (that is, the first byte is always zero).
 */
void
ndn_binary_seqfunc(uintmax_t x, void *param, struct ndn_charbuf *resultbuf)
{
    uintmax_t m;
    int n;
    unsigned char *b;
    (void)param; /* unused */
    for (n = 0, m = 0; x < m; n++)
        m = (m << 8) | 0xff;
    b = ndn_charbuf_reserve(resultbuf, n + 1);
    resultbuf->length = n + 1;
    for (; n >= 0; n--, x >>= 8)
        b[n] = x & 0xff;
}

/*
 * Our private record of the state of the bulk data reception
 */
struct bulkdata {
    ndn_seqfunc *seqfunc;           /* the sequence number scheme */
    void *seqfunc_param;            /* parameters thereto, if needed */
    struct pending *first;          /* start of list of pending items */
    struct ndn_closure *client;     /* client-supplied upcall for delivery */
    uintmax_t next_expected;        /* smallest undelivered sequence number */
    struct ndn_charbuf *name_prefix;
    int prefix_comps;
    /* pubid, etc? */
};

struct pending {
    struct pending *prev;           /* links for doubly-linked list */
    struct pending *next;
    struct bulkdata *parent;
    uintmax_t x;                    /* sequence number for this item */
    struct ndn_closure closure;     /* our closure for getting matching data */
    unsigned char *content_ndnb;    /* the content that has arrived */
    size_t content_size;
};

static enum ndn_upcall_res deliver_content(struct ndn *h, struct bulkdata *b);
static void express_bulkdata_interest(struct ndn *h, struct pending *b);
// XXX - missing a way to create a struct bulkdata *
// XXX - missing code to create new pendings


/*static*/ enum ndn_upcall_res
imcoming_bulkdata(struct ndn_closure *selfp,
                  enum ndn_upcall_kind kind,
                  struct ndn_upcall_info *info)
{
    struct bulkdata *b;
    struct pending *p = selfp->data;
    enum ndn_upcall_res res = NDN_UPCALL_RESULT_ERR;

    assert(selfp == &p->closure);
    b = p->parent;
    
    switch (kind) {
        case NDN_UPCALL_FINAL:
            p->prev->next = p->next->prev;
            p->next->prev = p->prev->next;
            if (b != NULL && p == b->first)
                b->first = (p == p->next) ? NULL : p->next;
            if (p->content_ndnb != NULL)
                free(p->content_ndnb);
            free(p);
            return(NDN_UPCALL_RESULT_OK);
	case NDN_UPCALL_CONTENT:
    	case NDN_UPCALL_CONTENT_UNVERIFIED:
	case NDN_UPCALL_CONTENT_BAD:
            /* XXX - should we be returning bad (signature failed) content */
            break;
        case NDN_UPCALL_INTEREST_TIMED_OUT:
            /* XXX - may want to give client a chance to decide */ 
            return(NDN_UPCALL_RESULT_REEXPRESS);
        default:
            return(NDN_UPCALL_RESULT_ERR);
    }
    /* XXX - check to see if seq comp matches, if not we have a hole to fill */
    
    if (p->content_ndnb == NULL) {
    if (p->x == b->next_expected) {
        /* Good, we have in-order data to deliver to the caller */
        res = (*b->client->p)(b->client, kind, info);
        if (res == NDN_UPCALL_RESULT_OK) {
            b->next_expected += 1;
            b->first = (p == p->next) ? NULL : p->next;
            p->prev->next = p->next->prev;
            p->next->prev = p->prev->next;
            p->next = p->prev = p;
            p->parent = NULL;
        }
        // else ...
    }
    else if (p->content_ndnb == NULL) {
        /* Out-of-order data, save it for later */
        size_t size = info->pco->offset[NDN_PCO_E];
        selfp->refcount++; /* don't call FINAL just yet */
        p->content_ndnb = malloc(size);
        memcpy(p->content_ndnb, info->content_ndnb, size);
        p->content_size = size;
    }
    }
    while (b->first != NULL && b->first->x == b->next_expected &&
           b->first->content_ndnb != NULL) {
        res = deliver_content(info->h, b);
        if (res != NDN_UPCALL_RESULT_OK)
            break;
    }
    if (b->first == NULL) {
        // XXX 
        return(NDN_UPCALL_RESULT_OK);
    }
    for (p = b->first; p->x >= b->next_expected; p = p->next) {
        // XXX - this is not really right ...
        if (p->content_ndnb == NULL)
            express_bulkdata_interest(info->h, p);
    }
    return(NDN_UPCALL_RESULT_OK);
}

static void
express_bulkdata_interest(struct ndn *h, struct pending *p)
{
    int res;
    struct bulkdata *b = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *templ = NULL;
    struct ndn_charbuf *seq = NULL;
    
    b = p->parent;
    if (b == NULL)
        return;
    name = ndn_charbuf_create();
    templ = ndn_charbuf_create();
    seq = ndn_charbuf_create();

    ndn_charbuf_append(name, b->name_prefix->buf, b->name_prefix->length);
    
    seq->length = 0;
    (*b->seqfunc)(p->x, b->seqfunc_param, seq);
    ndn_name_append(name, seq->buf, seq->length);
    
    ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);

    ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
    ndn_charbuf_append_closer(templ); /* </Name> */

    // XXX - may want to set Min/MaxSuffixComponents
    
    ndn_charbuf_append_closer(templ); /* </Interest> */
    res = ndn_express_interest(h, name, &p->closure, templ);
    assert(res >= 0); // XXX - handle this better
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&templ);
    ndn_charbuf_destroy(&seq);
}

/*
 * deliver_content is used to deliver a previously-buffered
 * ContentObject to the client.
 */
static enum ndn_upcall_res
deliver_content(struct ndn *h, struct bulkdata *b)
{
    struct ndn_upcall_info info = {0};
    struct ndn_parsed_ContentObject obj = {0};
    struct pending *p = b->first;
    int res;
    enum ndn_upcall_res ans;
    assert(p != NULL && p->x == b->next_expected && p->content_ndnb != NULL);
    info.pco = &obj;
    info.content_comps = ndn_indexbuf_create();
    res = ndn_parse_ContentObject(p->content_ndnb, p->content_size,
                                  &obj, info.content_comps);
    assert(res >= 0);
    info.content_ndnb = p->content_ndnb;
    info.matched_comps = info.content_comps->n - 2;
    /* XXX - we have no matched interest to present */
    ans = (*b->client->p)(b->client, NDN_UPCALL_CONTENT, &info);
    // XXX - check for refusal
    info.content_ndnb = NULL;
    free(p->content_ndnb);
    p->content_ndnb = NULL;
    p->content_size = 0;
    ndn_indexbuf_destroy(&info.content_comps);
    if (ans == NDN_UPCALL_RESULT_OK) {
        struct ndn_closure *old = &p->closure;
        if ((--(old->refcount)) == 0) {
            info.pco = NULL;
            (old->p)(old, NDN_UPCALL_FINAL, &info);
        }
    }
    return(ans);
}
