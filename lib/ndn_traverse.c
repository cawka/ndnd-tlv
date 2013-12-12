/**
 * @file ndn_traverse.c
 * @brief Support for traversing a branch of the ndn name hierarchy.
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
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ndn/bloom.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/uri.h>


/************ Candidate API  ******/

/**
 * Private record of the state of traversal
 */
struct ndn_traversal {
    int magic; /* 68955871 */
    long *counter;
    unsigned warn;
    int flags;
    int n_excl;
    struct ndn_charbuf **excl; /* Array of n_excl items */
    
};

#define EXCLUDE_LOW 1
#define EXCLUDE_HIGH 2
#define MUST_VERIFY 4
#define LOCAL_SCOPE 8
#define ALLOW_STALE 0x10

/* Prototypes */
static int namecompare(const void *a, const void *b);
static struct ndn_traversal *get_my_data(struct ndn_closure *selfp);
static void append_Any_filter(struct ndn_charbuf *c);
static int express_my_interest(struct ndn *h,
                               struct ndn_closure *selfp,
                               struct ndn_charbuf *name);
static struct ndn_closure *split_my_excludes(struct ndn_closure *selfp);
static enum ndn_upcall_res incoming_content(struct ndn_closure *selfp,
                                            enum ndn_upcall_kind kind,
                                            struct ndn_upcall_info *);
static struct ndn_charbuf *ndn_charbuf_duplicate(struct ndn_charbuf *);
static void answer_passive(struct ndn_charbuf *templ, int allow_stale);
static void local_scope(struct ndn_charbuf *templ);

/**
 * Comparison operator for sorting the excl list with qsort.
 * For convenience, the items in the excl array are
 * charbufs containing ndnb-encoded Names of one component each.
 * (This is not the most efficient representation.)
 */
static int /* for qsort */
namecompare(const void *a, const void *b)
{
    const struct ndn_charbuf *aa = *(const struct ndn_charbuf **)a;
    const struct ndn_charbuf *bb = *(const struct ndn_charbuf **)b;
    int ans = ndn_compare_names(aa->buf, aa->length, bb->buf, bb->length);
    if (ans == 0)
        abort();
    return (ans);
}

static struct ndn_traversal *get_my_data(struct ndn_closure *selfp)
{
    struct ndn_traversal *data = selfp->data;
    if (data->magic != 68955871) abort();
    return(data);
}

/*
 * This upcall gets called for each piece of incoming content that
 * matches one of our interests.  We need to issue a new interest that
 * excludes another component at the current level, and perhaps also
 * and interest to start exploring the next level.  Thus if the matched
 * interest is
 *   /a/b/c exclude {d,e,f,i,j,k}
 * and we get
 *   /a/b/c/g/h
 * we would issue a new interest
 *   /a/b/c exclude {d,e,f,g,i,j,k}
 * to continue exploring the current level, plus a simple interest
 *   /a/b/c/g
 * to start exploring the next level as well.
 *
 * This does end up fetching each piece of content multiple times, once for
 * each level in the name. The repeated requests will be answered from the local
 * content store, though, and so should not generate extra network traffic.
 * There is a lot of unanswerable interest generated, though.  
 *
 * To prevent the interests from becoming too huge, we may need to split them.
 * Thus if the first new interest above were deemed too large, we could instead
 * issue the two interests
 *   /a/b/c exclude {d,e,f,g,*}
 *   /a/b/c exclude {*,g,i,j,k}
 * where * stands for a Bloom filter that excludes anything.  Note the
 * repetition of g to ensure that these two interests cover disjoint portions
 * of the hierarchy. We need to keep track of the endpoint conditions
 * as well as the excluded set in our upcall data.
 * When a split happens, we need a new closure to track it, as we do when
 * we start exploring a new level.
 */
static enum ndn_upcall_res
incoming_content(
    struct ndn_closure *selfp,
    enum ndn_upcall_kind kind,
    struct ndn_upcall_info *info)
{
    struct ndn_charbuf *c = NULL;
    struct ndn_charbuf *comp = NULL;
    struct ndn_charbuf *uri = NULL;
    const unsigned char *ndnb = NULL;
    size_t ndnb_size = 0;
    struct ndn_indexbuf *comps = NULL;
    int matched_comps = 0;
    int res;
    int i;
    struct ndn_traversal *data = get_my_data(selfp);
    
    if (kind == NDN_UPCALL_FINAL) {
        for (i = 0; i < data->n_excl; i++)
            ndn_charbuf_destroy(&(data->excl[i]));
        if (data->excl != NULL)
            free(data->excl);
        free(data);
        free(selfp);
        return(0);
    }
    if (kind == NDN_UPCALL_INTEREST_TIMED_OUT)
        return(0);
    if (kind == NDN_UPCALL_CONTENT_BAD)
        return(0);
    if (kind == NDN_UPCALL_CONTENT_UNVERIFIED) {
        if ((data->flags & MUST_VERIFY) != 0)
            return(NDN_UPCALL_RESULT_VERIFY);
    }
    if (kind != NDN_UPCALL_CONTENT && kind != NDN_UPCALL_CONTENT_UNVERIFIED) abort();

    ndnb = info->content_ndnb;
    ndnb_size = info->pco->offset[NDN_PCO_E];
    comps = info->content_comps;
    matched_comps = info->pi->prefix_comps;
    c = ndn_charbuf_create();
    uri = ndn_charbuf_create();
        
    if (matched_comps + 1 > comps->n) {
        ndn_uri_append(c, ndnb, ndnb_size, 1);
        fprintf(stderr, "How did this happen?  %s\n", ndn_charbuf_as_string(uri));
        exit(1);
    }
    
    data->counter[0]++; /* Tell main that something new came in */

    /* Recover the same prefix as before */
    ndn_name_init(c);
    ndn_name_append_components(c, ndnb, comps->buf[0], comps->buf[matched_comps]);
    
    comp = ndn_charbuf_create();
    ndn_name_init(comp);
    if (matched_comps + 1 == comps->n) {
        /* Reconstruct the implicit content digest component */
        ndn_digest_ContentObject(ndnb, info->pco);
        ndn_name_append(comp, info->pco->digest, info->pco->digest_bytes);
    }
    else {
        ndn_name_append_components(comp, ndnb,
                                   comps->buf[matched_comps],
                                   comps->buf[matched_comps + 1]);
    }
    data->excl = realloc(data->excl, (data->n_excl + 1) * sizeof(data->excl[0]));
    data->excl[data->n_excl++] = comp;
    comp = NULL;
    qsort(data->excl, data->n_excl, sizeof(data->excl[0]), &namecompare);
    res = express_my_interest(info->h, selfp, c);
    if (res == -1) {
        struct ndn_closure *high = split_my_excludes(selfp);
        if (high == NULL) abort();
        express_my_interest(info->h, selfp, c);
        express_my_interest(info->h, high, c);
    }
    /* Explore the next level, if there is one. */
    if (matched_comps + 2 < comps->n) {
        struct ndn_traversal *newdat = NULL;
        struct ndn_closure *cl;
        newdat = calloc(1, sizeof(*newdat));
        newdat->magic = 68955871;
        newdat->warn = 1492;
        newdat->counter = data->counter;
        newdat->flags = data->flags & ~(EXCLUDE_LOW | EXCLUDE_HIGH);
        newdat->n_excl = 0;
        newdat->excl = NULL;
        cl = calloc(1, sizeof(*cl));
        cl->p = &incoming_content;
        cl->data = newdat;
        ndn_name_init(c);
        ndn_name_append_components(c, ndnb,
                                   comps->buf[0],
                                   comps->buf[matched_comps + 1]);
        express_my_interest(info->h, cl, c);
    }
    else {
        res = ndn_uri_append(uri, info->content_ndnb, info->pco->offset[NDN_PCO_E], 1);
        if (res < 0)
            fprintf(stderr, "*** Error: ndn_traverse line %d res=%d\n", __LINE__, res);
        else
            printf("%s\n", ndn_charbuf_as_string(uri));
    }
    ndn_charbuf_destroy(&c);
    ndn_charbuf_destroy(&uri);
    return(0);
}

/*
 * Construct and send a new interest that uses the exclusion list.
 * Return -1 if not sent because of packet size, 0 for success.
 */
static int
express_my_interest(struct ndn *h,
                    struct ndn_closure *selfp,
                    struct ndn_charbuf *name)
{
    int ans;
    struct ndn_charbuf *templ = NULL;
    int i;
    struct ndn_traversal *data = get_my_data(selfp);

    templ = ndn_charbuf_create();
    ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
    ndn_charbuf_append_closer(templ); /* </Name> */
    if (data->n_excl != 0) {
        ndn_charbuf_append_tt(templ, NDN_DTAG_Exclude, NDN_DTAG);
        if ((data->flags & EXCLUDE_LOW) != 0)
            append_Any_filter(templ);
        for (i = 0; i < data->n_excl; i++) {
            struct ndn_charbuf *comp = data->excl[i];
            if (comp->length < 4) abort();
            ndn_charbuf_append(templ, comp->buf + 1, comp->length - 2);
        }
        if ((data->flags & EXCLUDE_HIGH) != 0)
            append_Any_filter(templ);
        ndn_charbuf_append_closer(templ); /* </Exclude> */
    }
    answer_passive(templ, (data->flags & ALLOW_STALE) != 0);
    if ((data->flags & LOCAL_SCOPE) != 0)
        local_scope(templ);
    ndn_charbuf_append_closer(templ); /* </Interest> */
    if (templ->length + name->length > data->warn + 2) {
        fprintf(stderr, "*** Interest packet is %d bytes\n", (int)templ->length);
        data->warn = data->warn * 8 / 5;
    }
    if (templ->length + name->length > 1450 && data->n_excl > 3)
        ans = -1;
    else {
        ndn_express_interest(h, name, selfp, templ);
        ans = 0;
    }
    ndn_charbuf_destroy(&templ);
    return(ans);
}

/*
 * Build a new closure to handle the high half of the excludes, and modify the
 * old closure to handle the low half.
 */
static struct ndn_closure *
split_my_excludes(struct ndn_closure *selfp)
{
    int i;
    int m;
    struct ndn_traversal *newdat = NULL;
    struct ndn_closure *cl;
    struct ndn_traversal *data = get_my_data(selfp);
    
    if (data->n_excl < 3)
        return NULL;
    m = data->n_excl / 2;
    newdat = calloc(1, sizeof(*newdat));
    newdat->magic = 68955871;
    newdat->warn = 1492;
    newdat->counter = data->counter;
    newdat->n_excl = data->n_excl - m;
    newdat->excl = calloc(newdat->n_excl, sizeof(newdat->excl[0]));
    if (newdat->excl == NULL) {
        free(newdat);
        return(NULL);
    }
    newdat->excl[0] = ndn_charbuf_duplicate(data->excl[m]);
    newdat->flags = data->flags | EXCLUDE_LOW;
    for (i = 1; i < newdat->n_excl; i++) {
        newdat->excl[i] = data->excl[m + i];
        data->excl[m + i] = NULL;
    }
    data->n_excl = m + 1;
    data->flags |= EXCLUDE_HIGH;
    cl = calloc(1, sizeof(*cl));
    cl->p = &incoming_content;
    cl->data = newdat;
    return(cl);
}

/**
 * Append an Any filter, useful for excluding
 * everything between two 'fenceposts' in an Exclude construct.
 */
static void
append_Any_filter(struct ndn_charbuf *c)
{
    ndn_charbuf_append_tt(c, NDN_DTAG_Any, NDN_DTAG);
    ndn_charbuf_append_closer(c);
}

static struct ndn_charbuf *
ndn_charbuf_duplicate(struct ndn_charbuf *c)
{
    struct ndn_charbuf *ans = ndn_charbuf_create();
    ndn_charbuf_append(ans, c->buf, c->length);
    return(ans);
}

/*
 * Append AnswerOriginKind element to partially constructed Interest,
 * requesting to not generate new content.
 */
static void
answer_passive(struct ndn_charbuf *templ, int allow_stale)
{
    int aok = NDN_AOK_CS;
    if (allow_stale)
        aok |= NDN_AOK_STALE;
    ndnb_tagged_putf(templ, NDN_DTAG_AnswerOriginKind, "%d", aok);
}

/*
 * Append Scope=0 to partially constructed Interest, meaning
 * to address only the local ndnd.
 */
static void
local_scope(struct ndn_charbuf *templ)
{
    ndn_charbuf_append_tt(templ, NDN_DTAG_Scope, NDN_DTAG);
    ndn_charbuf_append_tt(templ, 1, NDN_UDATA);
    ndn_charbuf_append(templ, "0", 1);
    ndn_charbuf_append_closer(templ); /* </Scope> */
}

/**
 * Temporary driver - exits when done!
 */

void
ndn_dump_names(struct ndn *h, struct ndn_charbuf *name_prefix, int local_scope, int allow_stale)
{
    long *counter;
    int i;
    long n;
    int res;
    struct ndn_traversal *data = NULL;
    struct ndn_closure *cl = NULL;
    
    counter = calloc(1, sizeof(*counter));
    data = calloc(1, sizeof(*data));
    data->magic = 68955871;
    data->warn = 1492;
    data->flags = 0;
    data->counter = counter;
    if (local_scope)
        data->flags |= LOCAL_SCOPE;
    if (allow_stale)
        data->flags |= ALLOW_STALE;
    
    cl = calloc(1, sizeof(*cl));
    cl->p = &incoming_content;
    cl->data = data;
    
    express_my_interest(h, cl, name_prefix);
    cl = NULL;
    data = NULL;
    for (i = 0;; i++) {
        n = *counter;
        res = ndn_run(h, 1000); /* stop if we run dry for 1 sec */
        fflush(stdout);
        if (*counter == n || res < 0)
            break;
    }
    exit(0);
}
