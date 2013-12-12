/**
 * @file ndnd_internal_client.c
 *
 * Internal client of ndnd, handles requests for
 * inspecting and controlling operation of the ndnd;
 * requests and responses themselves use ndn protocols.
 *
 * Part of ndnd - the NDNx Daemon.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2013 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/ndn_private.h>
#include <ndn/hashtb.h>
#include <ndn/keystore.h>
#include <ndn/schedule.h>
#include <ndn/sockaddrutil.h>
#include <ndn/uri.h>
#include "ndnd_private.h"

#if 0
#define GOT_HERE ndnd_msg(ndnd, "at ndnd_internal_client.c:%d", __LINE__);
#else
#define GOT_HERE
#endif
#define NDND_NOTICE_NAME "notice.txt"

#ifndef NDND_TEST_100137
#define NDND_TEST_100137 0
#endif

#ifndef NDND_PING
/* The ping responder is deprecated, but enable it by default for now */
#define NDND_PING 1
#endif

static void ndnd_start_notice(struct ndnd_handle *ndnd);
static void adjacency_timed_reset(struct ndnd_handle *ndnd, unsigned faceid);

/**
 * Creates a key object using the service discovery name profile.
 */
static struct ndn_charbuf *
ndnd_init_service_ndnb(struct ndnd_handle *ndnd, const char *baseuri, int freshness)
{
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct ndn *h = ndnd->internal_client;
    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_charbuf *pubid = ndn_charbuf_create();
    struct ndn_charbuf *pubkey = ndn_charbuf_create();
    struct ndn_charbuf *keyid = ndn_charbuf_create();
    struct ndn_charbuf *cob = ndn_charbuf_create();
    int res;
    
    res = ndn_get_public_key(h, NULL, pubid, pubkey);
    if (res < 0) abort();
    ndn_name_from_uri(name, baseuri);
    ndn_charbuf_append_value(keyid, NDN_MARKER_CONTROL, 1);
    ndn_charbuf_append_string(keyid, ".M.K");
    ndn_charbuf_append_value(keyid, 0, 1);
    ndn_charbuf_append_charbuf(keyid, pubid);
    ndn_name_append(name, keyid->buf, keyid->length);
    ndn_create_version(h, name, 0, ndnd->starttime, ndnd->starttime_usec * 1000);
    sp.template_ndnb = ndn_charbuf_create();
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_KeyLocator, NDN_DTAG);
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_KeyName, NDN_DTAG);
    ndn_charbuf_append_charbuf(sp.template_ndnb, name);
    ndn_charbuf_append_closer(sp.template_ndnb);
    ndn_charbuf_append_closer(sp.template_ndnb);
    ndn_charbuf_append_closer(sp.template_ndnb);
    sp.sp_flags |= NDN_SP_TEMPL_KEY_LOCATOR;
    ndn_name_from_uri(name, "%00");
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    sp.type = NDN_CONTENT_KEY;
    sp.freshness = freshness;
    res = ndn_sign_content(h, cob, name, &sp, pubkey->buf, pubkey->length);
    if (res != 0) abort();
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&pubid);
    ndn_charbuf_destroy(&pubkey);
    ndn_charbuf_destroy(&keyid);
    ndn_charbuf_destroy(&sp.template_ndnb);
    return(cob);
}

/* These are used in face->adjstate to track our state */
#define ADJ_SOL_SENT (1U << 0)
#define ADJ_SOL_RECV (1U << 1)
#define ADJ_OFR_SENT (1U << 2)
#define ADJ_OFR_RECV (1U << 3)
#define ADJ_CRQ_SENT (1U << 4)
#define ADJ_CRQ_RECV (1U << 5)
#define ADJ_DAT_SENT (1U << 6)
#define ADJ_DAT_RECV (1U << 7)
#define ADJ_TIMEDWAIT (1U << 8)
#define ADJ_PINGING  (1U << 9)
#define ADJ_RETRYING (1U << 10)
#define ADJ_ACTIVE   (1U << 11)

/**
 * Update face->adjstate by setting / clearing the indicated bits.
 *
 * If a bit is in both masks, it is set.
 * @returns the old values, or -1 for an error.
 */
int
adjstate_change_db(struct ndnd_handle *ndnd, struct face *face,
                int set, int clear, int line)
{
    int new;
    int old;
    
    if (face == NULL)
        return(-1);
    old = face->adjstate;
    new = (old & ~clear) | set;
    if (new != old) {
        face->adjstate = new;
        if (ndnd->debug & (2 | 4)) {
            /* display the bits in face->adjstate */
            char f[] = "sSoOcCdDTPRA\0";
            int i;
            for (i = 0; f[i] != 0; i++)
                if (((new >> i) & 1) == 0)
                    f[i] = '.';
            ndnd_msg(ndnd, "ic.%d adjstate %u %s %#x", line,
                     face->faceid, f, face->flags);
        }
    }
    return(old);
}
#define adjstate_change(h, f, s, c) adjstate_change_db(h, f, s, c, __LINE__)
/**
 * Append the URI representation of the adjacency prefix for face to the
 * charbuf cb.
 * @returns 0 for success, -1 for error.
 */
static int
append_adjacency_uri(struct ndnd_handle *ndnd,
                     struct ndn_charbuf *cb, struct face *face)
{
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *comp = NULL;
    int res;
    
    if (face->guid == NULL)
        return(-1);
    comp = ndn_charbuf_create();
    name = ndn_charbuf_create();
    ndn_name_from_uri(name, "ndn:/%C1.M.FACE");
    ndn_charbuf_append_value(comp, NDN_MARKER_CONTROL, 1);
    ndn_charbuf_append_string(comp, ".M.G");
    ndn_charbuf_append_value(comp, 0, 1);
    ndnd_append_face_guid(ndnd, comp, face);
    ndn_name_append(name, comp->buf, comp->length);
    res = ndn_uri_append(cb, name->buf, name->length, 1);
    ndn_charbuf_destroy(&comp);
    ndn_charbuf_destroy(&name);
    return(res < 0 ? -1 : 0);
}

#define ADJ_REFRESH_SEC 120
#define ADJ_MICROS (ADJ_REFRESH_SEC * 1000000)
/**
 * Scheduled event to refresh adjacency
 */
static int
adjacency_do_refresh(struct ndn_schedule *sched,
                     void *clienth,
                     struct ndn_scheduled_event *ev,
                     int flags)
{
    struct ndnd_handle *ndnd = clienth;
    struct face *face = NULL;
    unsigned both;
    
    face = ndnd_face_from_faceid(ndnd, ev->evint);
    if (face == NULL)
        return(0);
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        adjstate_change(ndnd, face, 0, ADJ_ACTIVE);
        return(0);
    }
    both = ADJ_DAT_RECV | ADJ_DAT_SENT;
    if ((face->adjstate & both) == both) {
        ndnd_adjacency_offer_or_commit_req(ndnd, face);
        if ((face->adjstate & ADJ_PINGING) != 0)
            return((ADJ_MICROS + nrand48(ndnd->seed) % ADJ_MICROS) / 2);
    }
    adjstate_change(ndnd, face, 0, ADJ_ACTIVE);
    return(0);
}

/**
 * Register the adjacency prefix with the given forwarding flags.
 */
static void
ndnd_register_adjacency(struct ndnd_handle *ndnd, struct face *face,
                        unsigned forwarding_flags)
{
    struct ndn_charbuf *uri = NULL;
    unsigned both;
    int res;
    int adj = 0;
    int lifetime = 0;
    
    if ((forwarding_flags & NDN_FORW_ACTIVE) != 0) {
        adj = NDN_FACE_ADJ;
        lifetime = ADJ_REFRESH_SEC; /* seconds */
    }
    both = ADJ_DAT_RECV | ADJ_DAT_SENT;
    if ((face->adjstate & both) != both)
        return;
    uri = ndn_charbuf_create();
    res = append_adjacency_uri(ndnd, uri, face);
    if (res >= 0)
        res = ndnd_reg_uri(ndnd, ndn_charbuf_as_string(uri), face->faceid,
                           forwarding_flags, lifetime);
    if (res >= 0) {
        if ((face->flags & NDN_FACE_ADJ) != adj) {
            face->flags ^= NDN_FACE_ADJ;
            ndnd_face_status_change(ndnd, face->faceid);
        }
        if (lifetime != 0 && (face->adjstate & ADJ_ACTIVE) == 0) {
            ndn_schedule_event(ndnd->sched, lifetime * 1000000,
                               adjacency_do_refresh, NULL, face->faceid);
            adjstate_change(ndnd, face, ADJ_ACTIVE, 0);
        }
    }
    ndn_charbuf_destroy(&uri);
}

/**
 * Scheduled event for getting rid of an old guid cob.
 */
static int
ndnd_flush_guid_cob(struct ndn_schedule *sched,
                    void *clienth,
                    struct ndn_scheduled_event *ev,
                    int flags)
{
    struct ndnd_handle *ndnd = clienth;
    struct face *face = NULL;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    face = ndnd_face_from_faceid(ndnd, ev->evint);
    if (face != NULL)
        ndn_charbuf_destroy(&face->guid_cob);
    return(0);
}

/**
 * Create the adjacency content object for our endpoint of the face.
 */
static void
ndnd_init_face_guid_cob(struct ndnd_handle *ndnd, struct face *face)
{
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct ndn *h = ndnd->internal_client;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *payload = NULL;
    struct ndn_charbuf *comp = NULL;
    struct ndn_charbuf *cob = NULL;
    int res;
    int seconds = 60; /* freshness in the object */
    int nfresh = 20; /* flush it after this many freshness periods */
    
    if (face->guid == NULL || face->guid_cob != NULL)
        return;
    if ((face->adjstate & (ADJ_OFR_SENT | ADJ_OFR_RECV)) == 0)
        return;
    name = ndn_charbuf_create();
    payload = ndn_charbuf_create();
    comp = ndn_charbuf_create();
    cob = ndn_charbuf_create();
    
    ndn_name_from_uri(name, "ndn:/%C1.M.FACE");
    /* %C1.G.%00<guid> */
    ndn_charbuf_reset(comp);
    ndn_charbuf_append_value(comp, NDN_MARKER_CONTROL, 1);
    ndn_charbuf_append_string(comp, ".M.G");
    ndn_charbuf_append_value(comp, 0, 1);
    ndnd_append_face_guid(ndnd, comp, face);
    ndn_name_append(name, comp->buf, comp->length);
    ndn_name_from_uri(name, "%C1.M.NODE");
    /* %C1.K.%00<ndndid> */
    ndn_charbuf_reset(comp);
    ndn_charbuf_append_value(comp, NDN_MARKER_CONTROL, 1);
    ndn_charbuf_append_string(comp, ".M.K");
    ndn_charbuf_append_value(comp, 0, 1);
    ndn_charbuf_append(comp, ndnd->ndnd_id, sizeof(ndnd->ndnd_id));
    ndn_name_append(name, comp->buf, comp->length);
    ndn_charbuf_reset(comp);
    ndn_charbuf_putf(comp, "face~%u", face->faceid);
    ndn_name_append(name, comp->buf, comp->length);
    ndn_create_version(h, name, NDN_V_NOW, 0, 0);
    ndn_name_from_uri(name, "%00");
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    sp.freshness = seconds;
    res = ndn_sign_content(h, cob, name, &sp, payload->buf, payload->length);
    if (res != 0)
        ndn_charbuf_destroy(&cob);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&payload);
    ndn_charbuf_destroy(&comp);
    ndn_charbuf_destroy(&sp.template_ndnb);
    face->guid_cob = cob;
    if (cob != NULL)
        ndn_schedule_event(ndnd->sched, nfresh * seconds * 1000000 - 800000,
                           ndnd_flush_guid_cob, NULL, face->faceid);
}

/**
 * Isolate the lower and upper bounds for the guid component from Exclude
 *
 * This is used as part of the adjacency protocol.
 */
static int
extract_bounds(const unsigned char *ndnb, struct ndn_parsed_interest *pi,
               const unsigned char **plo, const unsigned char **phi)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = NULL;
    int res = -1;
    int x;
    int y;
    int z;
    size_t sz;
    
    /* We are interested only in the Exclude element. */
    ndnb = ndnb + pi->offset[NDN_PI_B_Exclude];
    sz = pi->offset[NDN_PI_E_Exclude] - pi->offset[NDN_PI_B_Exclude];
    if (sz != 0) {
        d = ndn_buf_decoder_start(&decoder, ndnb, sz);
        if (ndn_buf_match_dtag(d, NDN_DTAG_Exclude)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
                ndn_buf_advance(d);
                ndn_buf_check_close(d);
            }
            else return(-1);
            x = d->decoder.token_index;
            ndn_parse_required_tagged_BLOB(d, NDN_DTAG_Component, 8, 70);
            y = d->decoder.token_index;
            ndn_parse_required_tagged_BLOB(d, NDN_DTAG_Component, 8, 70);
            z = d->decoder.token_index;
            if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
                ndn_buf_advance(d);
                ndn_buf_check_close(d);
            }
            else return(-1);
            ndn_buf_check_close(d);
            if (d->decoder.state < 0)
                return (-1);
            if (y - x != z - y)
                return(-1);
            res = ndn_ref_tagged_BLOB(NDN_DTAG_Component, ndnb, x, y, plo, &sz);
            if (res < 0) return(-1);
            res = ndn_ref_tagged_BLOB(NDN_DTAG_Component, ndnb, y, z, phi, &sz);
            if (res < 0) return(-1);
            return(sz);
        }
    }
    return(-1);
}

/**
 * Handle the data that comes back in response to interest sent by
 * send_adjacency_solicit.
 *
 * We don't actually need to do much here, since the protocol is actually
 * looking for an interest from the other side.
 */
static enum ndn_upcall_res
solicit_response(struct ndn_closure *selfp,
                   enum ndn_upcall_kind kind,
                   struct ndn_upcall_info *info)
{
    struct face *face = NULL;
    struct ndnd_handle *ndnd = selfp->data;
    
    switch (kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            return(NDN_UPCALL_RESULT_OK);
        default:
            face = ndnd_face_from_faceid(ndnd, selfp->intdata);
            if (face == NULL)
                return(NDN_UPCALL_RESULT_ERR);
            if ((face->adjstate & (ADJ_SOL_SENT)) != 0)
                adjacency_timed_reset(ndnd, face->faceid);
            return(NDN_UPCALL_RESULT_ERR);
    }
}

/**
 * Send an adjacency solitiation interest, to elicit an offer from the
 * other side.
 */
static int
send_adjacency_solicit(struct ndnd_handle *ndnd, struct face *face)
{
    struct ndn_charbuf *name;
    struct ndn_charbuf *c;
    struct ndn_charbuf *g;
    struct ndn_charbuf *templ;
    struct ndn_closure *action = NULL;
    int i;
    int ans = -1;

    if (face == NULL || face->guid != NULL || face->adjstate != 0)
        return(-1);
    /* Need to poke the client library here so that it gets the curren time */
    ndn_process_scheduled_operations(ndnd->internal_client);
    name = ndn_charbuf_create();
    c = ndn_charbuf_create();
    g = ndn_charbuf_create();
    templ = ndn_charbuf_create();
    /* Construct a proposed partial guid, without marker bytes */
    ndn_charbuf_reset(g);
    ndn_charbuf_append_value(g, 0, 1); /* 1 reserved byte of zero */
    /* The first half is chosen by our side */
    for (i = 0; i < 6; i++)
        ndn_charbuf_append_value(g, nrand48(ndnd->seed) & 0xff, 1);
    /* The second half will be chosen by the other side */
    for (i = 0; i < 6; i++)
        ndn_charbuf_append_value(g, 0, 1);
    /* Construct the interest */
    ndn_charbuf_reset(templ);
    ndnb_element_begin(templ, NDN_DTAG_Interest);
    ndn_name_from_uri(name, "ndn:/%C1.M.FACE");
    ndn_charbuf_append_charbuf(templ, name);
    /* This interest excludes all but a range of possible guid components */
    ndnb_element_begin(templ, NDN_DTAG_Exclude);
    ndnb_tagged_putf(templ, NDN_DTAG_Any, "");
    ndn_charbuf_reset(c);
    ndn_charbuf_append_string(c, "\xC1.M.G");
    ndn_charbuf_append_value(c, 0, 1);
    ndn_charbuf_append(c, g->buf, g->length);
    ndnb_append_tagged_blob(templ, NDN_DTAG_Component, c->buf, c->length);
    ndn_charbuf_reset(c);
    ndn_charbuf_append_string(c, "\xC1.M.G");
    ndn_charbuf_append_value(c, 0, 1);
    ndn_charbuf_append(c, g->buf, g->length - 6);
    for (i = 0; i < 6; i++)
        ndn_charbuf_append_value(c, 0xff, 1);
    ndnb_append_tagged_blob(templ, NDN_DTAG_Component, c->buf, c->length);
    ndnb_tagged_putf(templ, NDN_DTAG_Any, "");
    ndnb_element_end(templ); /* Exclude */
    /* We don't want to get confused by cached content */
    ndnb_tagged_putf(templ, NDN_DTAG_AnswerOriginKind, "%d", 0);
    /* Only talk to direct peers */
    ndnb_tagged_putf(templ, NDN_DTAG_Scope, "2");
    /* Bypass the FIB - send to just the face we want */
    ndnb_tagged_putf(templ, NDN_DTAG_FaceID, "%u", face->faceid);
    ndnb_element_end(templ); /* Interest */
    action = calloc(1, sizeof(*action));
    if (action != NULL) {
        action->p = &solicit_response;
        action->intdata = face->faceid;
        action->data = ndnd;
        ans = ndn_express_interest(ndnd->internal_client, name, action, templ);
        /* Use the guid slot to hold our proposal */
        if (ans >= 0)
            ans = ndnd_set_face_guid(ndnd, face, g->buf, g->length);
        if (ans >= 0) {
            adjstate_change(ndnd, face, ADJ_SOL_SENT, 0);
            ndnd_internal_client_has_somthing_to_say(ndnd);
        }
        ans = (ans < 0) ? -1 : 0;
    }
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&c);
    ndn_charbuf_destroy(&g);
    ndn_charbuf_destroy(&templ);
    return(ans);
}

/**
 * Scheduled event to call send_adjacency_solicit.
 */
static int
ndnd_do_solicit(struct ndn_schedule *sched,
                void *clienth,
                struct ndn_scheduled_event *ev,
                int flags)
{
    struct ndnd_handle *ndnd = clienth;
    struct face *face = NULL;
    unsigned faceid;
    unsigned check, want;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    
    faceid = ev->evint;
    face = ndnd_face_from_faceid(ndnd, faceid);
    if (face == NULL)
        return(0);
    check = NDN_FACE_CONNECTING | NDN_FACE_UNDECIDED | NDN_FACE_NOSEND |
            NDN_FACE_GG | NDN_FACE_MCAST | NDN_FACE_PASSIVE | NDN_FACE_NORECV |
            NDN_FACE_BC | NDN_FACE_ADJ;
    want = 0;
    if (face->adjstate == 0 && (face->flags & check) == want)
        send_adjacency_solicit(ndnd, face);
    return(0);
}

/**
 * Answer an adjacency guid request from any face, based on the guid
 * in the name.
 *
 * @returns NDN_UPCALL_RESULT_INTEREST_CONSUMED if an answer was sent,
 *  otherwise -1.
 */
static int
ndnd_answer_by_guid(struct ndnd_handle *ndnd, struct ndn_upcall_info *info)
{
    struct face *face = NULL;
    unsigned char mb[6] = "\xC1.M.G\x00";
    const unsigned char *p = NULL;
    size_t size = 0;
    unsigned faceid;
    int res;
    
    res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, 1,
                            &p, &size);
    if (res < 0)
        return(-1);
    if (size < sizeof(mb))
        return(-1);
    if (memcmp(p, mb, sizeof(mb)) != 0)
        return(-1);
    faceid = ndnd_faceid_from_guid(ndnd, p + sizeof(mb), size - sizeof(mb));
    if (faceid == NDN_NOFACEID)
        return(-1);
    face = ndnd_face_from_faceid(ndnd, faceid);
    if (face == NULL)
        return(-1);
    if ((face->flags & NDN_FACE_ADJ) == 0)
        return(-1);
    if (face->guid_cob == NULL)
        ndnd_init_face_guid_cob(ndnd, face);
    if (face->guid_cob == NULL)
        return(-1);
    res = -1;
    if (ndn_content_matches_interest(face->guid_cob->buf,
                                     face->guid_cob->length,
                                     1,
                                     NULL,
                                     info->interest_ndnb,
                                     info->pi->offset[NDN_PI_E],
                                     info->pi
                                     )) {
        ndn_put(info->h, face->guid_cob->buf, face->guid_cob->length);
        res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
    }
    return(res);
}

/**
 * Handle the data comming back from an adjacency offer or commit request.
 */
static enum ndn_upcall_res
incoming_adjacency(struct ndn_closure *selfp,
                   enum ndn_upcall_kind kind,
                   struct ndn_upcall_info *info)
{
    struct face *face = NULL;
    struct ndnd_handle *ndnd = selfp->data;
    switch (kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            return(NDN_UPCALL_RESULT_OK);
        case NDN_UPCALL_CONTENT:
            face = ndnd_face_from_faceid(ndnd, selfp->intdata);
            if (face == NULL)
                return(NDN_UPCALL_RESULT_ERR);
            if ((face->adjstate & (ADJ_TIMEDWAIT)) != 0)
                return(NDN_UPCALL_RESULT_ERR);
            /* XXX - this should scrutinize the data to make sure it is OK */
            if ((face->adjstate & (ADJ_OFR_SENT | ADJ_CRQ_SENT)) != 0)
                adjstate_change(ndnd, face, ADJ_DAT_RECV, 0);
            adjstate_change(ndnd, face, 0, ADJ_PINGING | ADJ_RETRYING);
            if ((face->adjstate & (ADJ_CRQ_RECV)) != 0 &&
                (face->adjstate & (ADJ_DAT_SENT)) == 0 &&
                face->guid_cob != 0) {
                ndn_put(info->h, face->guid_cob->buf,
                                 face->guid_cob->length);
                adjstate_change(ndnd, face, ADJ_DAT_SENT, 0);
                if ((face->adjstate & (ADJ_DAT_RECV)) == 0)
                    ndnd_adjacency_offer_or_commit_req(ndnd, face);
            }
            ndnd_register_adjacency(ndnd, face,
                                    NDN_FORW_CHILD_INHERIT | NDN_FORW_ACTIVE);
            return(NDN_UPCALL_RESULT_OK);
        case NDN_UPCALL_INTEREST_TIMED_OUT:
            face = ndnd_face_from_faceid(ndnd, selfp->intdata);
            if (face == NULL)
                return(NDN_UPCALL_RESULT_ERR);
            if ((face->adjstate & (ADJ_RETRYING | ADJ_TIMEDWAIT)) == 0) {
                /* Retry one time */
                adjstate_change(ndnd, face, ADJ_RETRYING, 0);
                return(NDN_UPCALL_RESULT_REEXPRESS);
            }
            adjacency_timed_reset(ndnd, face->faceid);
            return(NDN_UPCALL_RESULT_OK);
        default:
            face = ndnd_face_from_faceid(ndnd, selfp->intdata);
            if (face != NULL)
                adjacency_timed_reset(ndnd, face->faceid);
            return(NDN_UPCALL_RESULT_ERR);
    }
}

/**
 * Express an interest to pull adjacency information from the other side
 */
void
ndnd_adjacency_offer_or_commit_req(struct ndnd_handle *ndnd, struct face *face)
{
    struct ndn_charbuf *name;
    struct ndn_charbuf *c;
    struct ndn_charbuf *templ;
    struct ndn_closure *action = NULL;
    
    if (face == NULL || face->guid == NULL)
        return;
    if ((face->adjstate & (ADJ_SOL_SENT | ADJ_TIMEDWAIT)) != 0)
        return;
    if ((face->adjstate & (ADJ_PINGING)) != 0)
        return;
    /* Need to poke the client library here so that it gets the current time */
    ndn_process_scheduled_operations(ndnd->internal_client);
    name = ndn_charbuf_create();
    c = ndn_charbuf_create();
    templ = ndn_charbuf_create();
    ndn_name_from_uri(name, "ndn:/%C1.M.FACE");
    ndn_charbuf_reset(c);
    ndn_charbuf_append_string(c, "\xC1.M.G");
    ndn_charbuf_append_value(c, 0, 1);
    ndnd_append_face_guid(ndnd, c, face);
    ndn_name_append(name, c->buf, c->length);
    ndn_name_from_uri(name, "%C1.M.NODE");
    ndn_charbuf_reset(templ);
    ndnb_element_begin(templ, NDN_DTAG_Interest);
    ndn_charbuf_append_charbuf(templ, name);
    ndnb_element_begin(templ, NDN_DTAG_Exclude);
    ndn_charbuf_reset(c);
    ndn_charbuf_append_string(c, "\xC1.M.K");
    ndn_charbuf_append_value(c, 0, 1);
    ndn_charbuf_append(c, ndnd->ndnd_id, sizeof(ndnd->ndnd_id));
    ndnb_append_tagged_blob(templ, NDN_DTAG_Component, c->buf, c->length);
    ndnb_element_end(templ); /* Exclude */
    ndnb_tagged_putf(templ, NDN_DTAG_AnswerOriginKind, "%d", 0);
    ndnb_tagged_putf(templ, NDN_DTAG_Scope, "2");
    ndnb_tagged_putf(templ, NDN_DTAG_FaceID, "%u", face->faceid);
    ndnb_element_end(templ); /* Interest */
    action = calloc(1, sizeof(*action));
    if (action != NULL) {
        action->p = &incoming_adjacency;
        action->intdata = face->faceid;
        action->data = ndnd;
        adjstate_change(ndnd, face, ADJ_PINGING, ADJ_RETRYING);
        ndn_express_interest(ndnd->internal_client, name, action, templ);
        if ((face->adjstate & ADJ_OFR_RECV) != 0)
            adjstate_change(ndnd, face, ADJ_CRQ_SENT, 0);
        else
            adjstate_change(ndnd, face, ADJ_OFR_SENT, 0);
    }
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&c);
    ndn_charbuf_destroy(&templ);
}

/**
 * Determine whether an offer matches up with our solicitation.
 */
static void
check_offer_matches_my_solicit(struct ndnd_handle *ndnd, struct face *face,
                               struct ndn_upcall_info *info)
{
    const unsigned char *p = NULL;
    size_t size = 0;
    int res;
    const char *mg = "\xC1.M.G";
    const char *mn = "\xC1.M.NODE";
    
    if (info->pi->prefix_comps != 3)
        return;
    if ((face->adjstate & ADJ_SOL_SENT) == 0)
        return;
    if (face->guid == NULL)
        return;
    res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, 2,
                            &p, &size);
    if (res < 0)
        return;
    if (size != strlen(mn) || 0 != memcmp(p, mn, size))
        return;
    res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, 1,
                            &p, &size);
    if (res < 0)
        return;
    res = strlen(mg) + 1;
    if (size != res + face->guid[0] || face->guid[0] <= 6)
        return;
    if (0 != memcmp(p, mg, res))
        return;
    if (0 != memcmp(p + res, face->guid + 1, face->guid[0] - 6))
        return;
    ndnd_forget_face_guid(ndnd, face);
    ndnd_set_face_guid(ndnd, face, p + res, size - res);
    adjstate_change(ndnd, face, ADJ_OFR_RECV, ADJ_SOL_SENT);
}

/**
 * Schedule negotiation of a link guid if appropriate
 */
static void
schedule_adjacency_negotiation(struct ndnd_handle *ndnd, unsigned faceid)
{
    struct face *face = ndnd_face_from_faceid(ndnd, faceid);
    unsigned check, want;
    int delay;
    
    if (face == NULL)
        return;
    check = NDN_FACE_CONNECTING | NDN_FACE_UNDECIDED | NDN_FACE_NOSEND |
            NDN_FACE_GG | NDN_FACE_MCAST | NDN_FACE_PASSIVE | NDN_FACE_NORECV |
            NDN_FACE_BC | NDN_FACE_ADJ;
    want = 0;
    if (ndnd->sched != NULL && (face->flags & check) == want) {
        /* If face creation was initiated remotely, dally a bit longer. */
        delay = 2000 + nrand48(ndnd->seed) % 131072U;
        if ((face->flags & NDN_FACE_PERMANENT) == 0)
            delay += 200000;
        ndn_schedule_event(ndnd->sched, delay, ndnd_do_solicit, NULL, faceid);
    }
}

/**
 * Scheduled event for recovering from a broken adjacency negotiation
 */
static int
adjacency_do_reset(struct ndn_schedule *sched,
                   void *clienth,
                   struct ndn_scheduled_event *ev,
                   int flags)
{
    struct ndnd_handle *ndnd = clienth;
    struct face *face = NULL;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    face = ndnd_face_from_faceid(ndnd, ev->evint);
    if (face == NULL)
        return(0);
    if ((face->adjstate & ADJ_TIMEDWAIT) == 0)
        return(0);
    if (face->adjstate != ADJ_TIMEDWAIT) {
        adjstate_change(ndnd, face, ADJ_TIMEDWAIT, ~ADJ_ACTIVE);
        ndnd_forget_face_guid(ndnd, face);
        return(666666);
    }
    adjstate_change(ndnd, face, 0, ~0);
    schedule_adjacency_negotiation(ndnd, face->faceid);
    return(0);
}

/**
 * Schedule recovery from a broken adjacency negotiation
 */
static void
adjacency_timed_reset(struct ndnd_handle *ndnd, unsigned faceid)
{
    struct face *face = ndnd_face_from_faceid(ndnd, faceid);
    
    if (face == NULL || ndnd->sched == NULL)
        return;
    if ((face->flags & NDN_FACE_ADJ) != 0) {
        ndnd_face_status_change(ndnd, faceid);
        face->flags &= ~NDN_FACE_ADJ;
    }
    adjstate_change(ndnd, face, ADJ_TIMEDWAIT, ~ADJ_ACTIVE);
    ndnd_forget_face_guid(ndnd, face);
    ndn_schedule_event(ndnd->sched, 9000000 + nrand48(ndnd->seed) % 8000000U,
                       adjacency_do_reset, NULL, faceid);
}

static int
clean_guest(struct ndn_schedule *sched,
            void *clienth,
            struct ndn_scheduled_event *ev,
            int flags)
{
    struct ndnd_handle *ndnd = clienth;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    unsigned faceid;
    int res;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    faceid = ev->evint;
    hashtb_start(ndnd->guest_tab, e);
    res = hashtb_seek(e, &faceid, sizeof(unsigned), 0);
    if (res < 0)
        return(-1);
    hashtb_delete(e);
    hashtb_end(e);
    return(0);
}

static enum ndn_upcall_res
ndnd_req_guest(struct ndn_closure *selfp,
               enum ndn_upcall_kind kind,
               struct ndn_upcall_info *info)
{
    struct ndnd_handle *ndnd = selfp->data;
    struct hashtb_enumerator ee;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct hashtb_enumerator *e = &ee;
    const char *guest_uri = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *uri = NULL;
    struct face *reqface = NULL;
    struct guest_entry *g = NULL;
    const unsigned char *p = NULL;
    size_t size = 0;
    size_t start = 0;
    size_t end = 0;
    int res;
    
    guest_uri = getenv("NDND_PREFIX");
    if (guest_uri == NULL || guest_uri[0] == 0)
        return(NDN_UPCALL_RESULT_ERR);
    reqface = ndnd_face_from_faceid(ndnd, ndnd->interest_faceid);
    if (reqface == NULL)
        return(NDN_UPCALL_RESULT_ERR);
    if ((reqface->flags & NDN_FACE_GG) != 0)
        return(NDN_UPCALL_RESULT_ERR);
    name = ndn_charbuf_create();
    if (name == NULL)
        return(NDN_UPCALL_RESULT_ERR);
    res = ndn_name_from_uri(name, guest_uri);
    if (res < 0) {
        ndn_charbuf_destroy(&name);
        return(NDN_UPCALL_RESULT_ERR);
    }
    hashtb_start(ndnd->guest_tab, e);
    res = hashtb_seek(e, &reqface->faceid, sizeof(unsigned), 0);
    if (res < 0) {
        ndn_charbuf_destroy(&name);
        return(NDN_UPCALL_RESULT_ERR);
    }
    g = e->data;
    hashtb_end(e);
    if (g->cob != NULL) {
        if (ndn_content_matches_interest(g->cob->buf,
                                         g->cob->length,
                                         1,
                                         NULL,
                                         info->interest_ndnb,
                                         info->pi->offset[NDN_PI_E],
                                         info->pi)) {
            ndn_put(info->h, g->cob->buf, g->cob->length);
            ndn_charbuf_destroy(&name);
            return(NDN_UPCALL_RESULT_INTEREST_CONSUMED);
        }
        /* We have a cob cached; no new one until the old one expires */
        ndn_charbuf_destroy(&name);
        return(NDN_UPCALL_RESULT_ERR);
    }
    if (info->interest_comps->n != 4) {
        ndn_charbuf_destroy(&name);
        return(NDN_UPCALL_RESULT_ERR);
    }
    res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, 2,
                            &p, &size);
    if (res < 0) {
        ndn_charbuf_destroy(&name);
        return(NDN_UPCALL_RESULT_ERR);
    }
    ndn_name_append(name, p, size);
    uri = ndn_charbuf_create();
    ndn_uri_append(uri, name->buf, name->length, 1);
    ndnd_reg_uri(ndnd, ndn_charbuf_as_string(uri), reqface->faceid,
                 NDN_FORW_CHILD_INHERIT | NDN_FORW_ACTIVE,
                 0x7FFFFFFF);
    g->cob = ndn_charbuf_create();
    ndn_charbuf_reset(name);
    start = info->pi->offset[NDN_PI_B_Name];
    end = info->interest_comps->buf[info->pi->prefix_comps];
    ndn_charbuf_append(name, info->interest_ndnb + start, end - start);
    ndn_charbuf_append_closer(name);
    ndn_create_version(info->h, name, NDN_V_NOW, 0, 0);
    ndn_name_from_uri(name, "%00");
    sp.sp_flags = NDN_SP_FINAL_BLOCK;
    sp.freshness = 5;
    res = ndn_sign_content(info->h, g->cob, name, &sp, uri->buf, uri->length);
    if (res < 0) {
        ndn_charbuf_destroy(&name);
        ndn_charbuf_destroy(&g->cob);
        ndn_charbuf_destroy(&uri);
        return(NDN_UPCALL_RESULT_ERR);
    }
    ndn_schedule_event(ndnd->sched, sp.freshness * 1000000,
                       clean_guest, NULL, reqface->faceid);
    if (g->cob != NULL &&
        ndn_content_matches_interest(g->cob->buf,
                                     g->cob->length,
                                     1,
                                     NULL,
                                     info->interest_ndnb,
                                     info->pi->offset[NDN_PI_E],
                                     info->pi)) {
        ndn_put(info->h, g->cob->buf, g->cob->length);
        ndn_charbuf_destroy(&name);
        ndn_charbuf_destroy(&uri);
        return(NDN_UPCALL_RESULT_INTEREST_CONSUMED);
    }
    return(NDN_UPCALL_RESULT_OK);
}

/**
 * Local interpretation of selfp->intdata
 */
#define MORECOMPS_MASK 0x007F
#define MUST_VERIFY    0x0080
#define MUST_VERIFY1   (MUST_VERIFY + 1)
#define OPER_MASK      0xFF00
#define OP_PING        0x0000
#define OP_NEWFACE     0x0200
#define OP_DESTROYFACE 0x0300
#define OP_PREFIXREG   0x0400
#define OP_SELFREG     0x0500
#define OP_UNREG       0x0600
#define OP_NOTICE      0x0700
#define OP_SERVICE     0x0800
#define OP_ADJACENCY   0x0900
#define OP_GUEST       0x0A00

/**
 * Common interest handler for ndnd_internal_client
 */
static enum ndn_upcall_res
ndnd_answer_req(struct ndn_closure *selfp,
                 enum ndn_upcall_kind kind,
                 struct ndn_upcall_info *info)
{
    struct ndn_charbuf *msg = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *keylocator = NULL;
    struct ndn_charbuf *signed_info = NULL;
    struct ndn_charbuf *reply_body = NULL;
    struct ndnd_handle *ndnd = NULL;
    int res = 0;
    int start = 0;
    int end = 0;
    int morecomps = 0;
    const unsigned char *final_comp = NULL;
    size_t final_size = 0;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct face *face = NULL;
    
    switch (kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            return(NDN_UPCALL_RESULT_OK);
        case NDN_UPCALL_INTEREST:
            break;
        case NDN_UPCALL_CONSUMED_INTEREST:
            return(NDN_UPCALL_RESULT_OK);
        default:
            return(NDN_UPCALL_RESULT_ERR);
    }
    ndnd = (struct ndnd_handle *)selfp->data;
    if ((ndnd->debug & 128) != 0)
        ndnd_debug_ndnb(ndnd, __LINE__, "ndnd_answer_req", NULL,
                        info->interest_ndnb, info->pi->offset[NDN_PI_E]);
    morecomps = selfp->intdata & MORECOMPS_MASK;
    if ((info->pi->answerfrom & NDN_AOK_NEW) == 0 &&
        selfp->intdata != OP_SERVICE &&
        selfp->intdata != OP_NOTICE &&
        selfp->intdata != OP_ADJACENCY &&
        selfp->intdata != OP_GUEST)
        return(NDN_UPCALL_RESULT_OK);
    if (info->matched_comps >= info->interest_comps->n)
        goto Bail;
    if (selfp->intdata != OP_PING &&
        selfp->intdata != OP_NOTICE &&
        selfp->intdata != OP_SERVICE &&
        selfp->intdata != OP_ADJACENCY &&
        selfp->intdata != OP_GUEST &&
        info->pi->prefix_comps != info->matched_comps + morecomps)
        goto Bail;
    if (morecomps == 1) {
        res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps,
                                info->matched_comps,
                                &final_comp, &final_size);
        if (res < 0)
            goto Bail;
    }
    if ((selfp->intdata & MUST_VERIFY) != 0) {
        struct ndn_parsed_ContentObject pco = {0};
        // XXX - probably should check for message origin BEFORE verify
        res = ndn_parse_ContentObject(final_comp, final_size, &pco, NULL);
        if (res < 0) {
            ndnd_debug_ndnb(ndnd, __LINE__, "co_parse_failed", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
            goto Bail;
        }
        res = ndn_verify_content(info->h, final_comp, &pco);
        if (res != 0) {
            ndnd_debug_ndnb(ndnd, __LINE__, "co_verify_failed", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
            goto Bail;
        }
    }
    sp.freshness = 10;
    switch (selfp->intdata & OPER_MASK) {
        case OP_PING:
            reply_body = ndn_charbuf_create();
            sp.freshness = (info->pi->prefix_comps == info->matched_comps) ? 60 : 5;
            res = 0;
            break;
        case OP_NEWFACE:
            reply_body = ndn_charbuf_create();
            res = ndnd_req_newface(ndnd, final_comp, final_size, reply_body);
            break;
        case OP_DESTROYFACE:
            reply_body = ndn_charbuf_create();
            res = ndnd_req_destroyface(ndnd, final_comp, final_size, reply_body);
            break;
        case OP_PREFIXREG:
            reply_body = ndn_charbuf_create();
            res = ndnd_req_prefixreg(ndnd, final_comp, final_size, reply_body);
            break;
        case OP_SELFREG:
            reply_body = ndn_charbuf_create();
            res = ndnd_req_selfreg(ndnd, final_comp, final_size, reply_body);
            break;
        case OP_UNREG:
            reply_body = ndn_charbuf_create();
            res = ndnd_req_unreg(ndnd, final_comp, final_size, reply_body);
            break;
        case OP_NOTICE:
            ndnd_start_notice(ndnd);
            goto Bail;
            break;
        case OP_SERVICE:
            if (ndnd->service_ndnb == NULL)
                ndnd->service_ndnb = ndnd_init_service_ndnb(ndnd, NDNDID_LOCAL_URI, 600);
            if (ndn_content_matches_interest(
                    ndnd->service_ndnb->buf,
                    ndnd->service_ndnb->length,
                    1,
                    NULL,
                    info->interest_ndnb,
                    info->pi->offset[NDN_PI_E],
                    info->pi
                )) {
                ndn_put(info->h, ndnd->service_ndnb->buf,
                                 ndnd->service_ndnb->length);
                res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                goto Finish;
            }
            // XXX this needs refactoring.
            if (ndnd->neighbor_ndnb == NULL)
                ndnd->neighbor_ndnb = ndnd_init_service_ndnb(ndnd, NDNDID_NEIGHBOR_URI, 5);
            if (ndn_content_matches_interest(
                    ndnd->neighbor_ndnb->buf,
                    ndnd->neighbor_ndnb->length,
                    1,
                    NULL,
                    info->interest_ndnb,
                    info->pi->offset[NDN_PI_E],
                    info->pi
                )) {
                ndn_put(info->h, ndnd->neighbor_ndnb->buf,
                                 ndnd->neighbor_ndnb->length);
                res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                goto Finish;
            }
            goto Bail;
            break;
        case OP_ADJACENCY:
            if (info->pi->prefix_comps >= 2 && (info->pi->answerfrom & NDN_AOK_CS) != 0) {
                res = ndnd_answer_by_guid(ndnd, info);
                if (res == NDN_UPCALL_RESULT_INTEREST_CONSUMED)
                    goto Finish;
            }
            face = ndnd_face_from_faceid(ndnd, ndnd->interest_faceid);
            if (face == NULL)
                goto Bail;
            if (info->pi->prefix_comps == 1 && face->guid == NULL) {
                const unsigned char *lo = NULL;
                const unsigned char *hi = NULL;
                int size = 0;
                unsigned char mb[6] = "\xC1.M.G\x00";
                
                size = extract_bounds(info->interest_ndnb, info->pi, &lo, &hi);
                if (size > (int)sizeof(mb) &&
                    0 == memcmp(mb, lo, sizeof(mb)) &&
                    0 == memcmp(mb, hi, sizeof(mb))) {
                    size -= sizeof(mb);
                    lo += sizeof(mb);
                    hi += sizeof(mb);
                    // XXX - we may want to be selective about proceeding
                    if ((face->adjstate & ADJ_SOL_SENT) != 0) {
                        /* The solicitations crossed in the mail. Arbitrate. */
                        if (face->guid != NULL && size >= face->guid[0] &&
                            memcmp(lo, face->guid + 1, face->guid[0]) > 0) {
                            ndnd_forget_face_guid(ndnd, face);
                            adjstate_change(ndnd, face, 0, ADJ_SOL_SENT);
                        }
                    }
                    adjstate_change(ndnd, face, ADJ_SOL_RECV, ADJ_TIMEDWAIT);
                    ndnd_generate_face_guid(ndnd, face, size, lo, hi);
                    if (face->guid != NULL) {
                        ndnd_adjacency_offer_or_commit_req(ndnd, face);
                        res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                        goto Finish;
                    }
                }
            }
            check_offer_matches_my_solicit(ndnd, face, info);
            if (face->guid_cob == NULL)
                ndnd_init_face_guid_cob(ndnd, face);
            if (face->guid_cob != NULL &&
                ndn_content_matches_interest(face->guid_cob->buf,
                                             face->guid_cob->length,
                                             1,
                                             NULL,
                                             info->interest_ndnb,
                                             info->pi->offset[NDN_PI_E],
                                             info->pi
                                             )) {
                if (info->pi->prefix_comps == 3)
                    adjstate_change(ndnd, face, ADJ_CRQ_RECV, 0);
                if ((face->adjstate & (ADJ_DAT_RECV | ADJ_OFR_RECV)) != 0) {
                    ndn_put(info->h, face->guid_cob->buf,
                            face->guid_cob->length);                    
                    adjstate_change(ndnd, face, ADJ_DAT_SENT, 0);
                    if ((face->adjstate & (ADJ_DAT_RECV)) == 0)
                        ndnd_adjacency_offer_or_commit_req(ndnd, face);
                }
                ndnd_register_adjacency(ndnd, face,
                      NDN_FORW_CHILD_INHERIT | NDN_FORW_ACTIVE);
                res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                goto Finish;
            }
            goto Bail;
        case OP_GUEST:
            res = ndnd_req_guest(selfp, kind, info);
            goto Finish;
        default:
            goto Bail;
    }
    if (res < 0)
        goto Bail;
    if (res == NDN_CONTENT_NACK)
        sp.type = res;
    msg = ndn_charbuf_create();
    name = ndn_charbuf_create();
    start = info->pi->offset[NDN_PI_B_Name];
    end = info->interest_comps->buf[info->pi->prefix_comps];
    ndn_charbuf_append(name, info->interest_ndnb + start, end - start);
    ndn_charbuf_append_closer(name);
    res = ndn_sign_content(info->h, msg, name, &sp,
                           reply_body->buf, reply_body->length);
    if (res < 0)
        goto Bail;
    if ((ndnd->debug & 128) != 0)
        ndnd_debug_ndnb(ndnd, __LINE__, "ndnd_answer_req_response", NULL,
                        msg->buf, msg->length);
    res = ndn_put(info->h, msg->buf, msg->length);
    if (res < 0)
        goto Bail;
    if (NDND_TEST_100137)
        ndn_put(info->h, msg->buf, msg->length);
    res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
    goto Finish;
Bail:
    res = NDN_UPCALL_RESULT_ERR;
Finish:
    ndn_charbuf_destroy(&msg);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&keylocator);
    ndn_charbuf_destroy(&reply_body);
    ndn_charbuf_destroy(&signed_info);
    return(res);
}

static int
ndnd_internal_client_refresh(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnd_handle *ndnd = clienth;
    int microsec = 0;
    if ((flags & NDN_SCHEDULE_CANCEL) == 0 &&
          ndnd->internal_client != NULL &&
          ndnd->internal_client_refresh == ev) {
        microsec = ndn_process_scheduled_operations(ndnd->internal_client);
        if (microsec > ev->evint)
            microsec = ev->evint;
    }
    if (microsec <= 0 && ndnd->internal_client_refresh == ev)
        ndnd->internal_client_refresh = NULL;
    return(microsec);
}

#define NDND_ID_TEMPL "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

static void
ndnd_uri_listen(struct ndnd_handle *ndnd, const char *uri,
                ndn_handler p, intptr_t intdata)
{
    struct ndn_charbuf *name;
    struct ndn_charbuf *uri_modified = NULL;
    struct ndn_closure *closure;
    struct ndn_indexbuf *comps;
    const unsigned char *comp;
    size_t comp_size;
    size_t offset;
    int reg_wanted = 1;
    
    name = ndn_charbuf_create();
    ndn_name_from_uri(name, uri);
    comps = ndn_indexbuf_create();
    if (ndn_name_split(name, comps) < 0)
        abort();
    if (ndn_name_comp_get(name->buf, comps, 1, &comp, &comp_size) >= 0) {
        if (comp_size == 32 && 0 == memcmp(comp, NDND_ID_TEMPL, 32)) {
            /* Replace placeholder with our ndnd_id */
            offset = comp - name->buf;
            memcpy(name->buf + offset, ndnd->ndnd_id, 32);
            uri_modified = ndn_charbuf_create();
            ndn_uri_append(uri_modified, name->buf, name->length, 1);
            uri = (char *)uri_modified->buf;
            reg_wanted = 0;
        }
    }
    closure = calloc(1, sizeof(*closure));
    closure->p = p;
    closure->data = ndnd;
    closure->intdata = intdata;
    /* Register explicitly if needed or requested */
    if (reg_wanted)
        ndnd_reg_uri(ndnd, uri,
                     0, /* special faceid for internal client */
                     NDN_FORW_CHILD_INHERIT | NDN_FORW_ACTIVE,
                     0x7FFFFFFF);
    ndn_set_interest_filter(ndnd->internal_client, name, closure);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&uri_modified);
    ndn_indexbuf_destroy(&comps);
}

/**
 * Make a forwarding table entry for ndn:/ndnx/NDNDID
 *
 * This one entry handles most of the namespace served by the
 * ndnd internal client.
 */
static void
ndnd_reg_ndnx_ndndid(struct ndnd_handle *ndnd)
{
    struct ndn_charbuf *name;
    struct ndn_charbuf *uri;
    
    name = ndn_charbuf_create();
    ndn_name_from_uri(name, "ndn:/ndnx");
    ndn_name_append(name, ndnd->ndnd_id, 32);
    uri = ndn_charbuf_create();
    ndn_uri_append(uri, name->buf, name->length, 1);
    ndnd_reg_uri(ndnd, ndn_charbuf_as_string(uri),
                 0, /* special faceid for internal client */
                 (NDN_FORW_CHILD_INHERIT |
                  NDN_FORW_ACTIVE        |
                  NDN_FORW_CAPTURE       |
                  NDN_FORW_ADVERTISE     ),
                 0x7FFFFFFF);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&uri);
}

#ifndef NDN_PATH_VAR_TMP
#define NDN_PATH_VAR_TMP "/var/tmp"
#endif

/*
 * This is used to shroud the contents of the keystore, which mainly serves
 * to add integrity checking and defense against accidental misuse.
 * The file permissions serve for restricting access to the private keys.
 */
#ifndef NDND_KEYSTORE_PASS
#define NDND_KEYSTORE_PASS "\010\043\103\375\327\237\152\351\155"
#endif

int
ndnd_init_internal_keystore(struct ndnd_handle *ndnd)
{
    struct ndn_charbuf *temp = NULL;
    struct ndn_charbuf *cmd = NULL;
    struct ndn_charbuf *culprit = NULL;
    struct stat statbuf;
    const char *dir = NULL;
    int res = -1;
    char *keystore_path = NULL;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    
    if (ndnd->internal_client == NULL)
        return(-1);
    temp = ndn_charbuf_create();
    cmd = ndn_charbuf_create();
    dir = getenv("NDND_KEYSTORE_DIRECTORY");
    if (dir != NULL && dir[0] == '/')
        ndn_charbuf_putf(temp, "%s/", dir);
    else
        ndn_charbuf_putf(temp, NDN_PATH_VAR_TMP "/.ndnx-user%d/", (int)geteuid());
    res = stat(ndn_charbuf_as_string(temp), &statbuf);
    if (res == -1) {
        if (errno == ENOENT)
            res = mkdir(ndn_charbuf_as_string(temp), 0700);
        if (res != 0) {
            culprit = temp;
            goto Finish;
        }
    }
    ndn_charbuf_putf(temp, ".ndnd_keystore_%s", ndnd->portstr);
    keystore_path = strdup(ndn_charbuf_as_string(temp));
    res = stat(keystore_path, &statbuf);
    if (res == 0)
        res = ndn_load_default_key(ndnd->internal_client, keystore_path, NDND_KEYSTORE_PASS);
    if (res >= 0)
        goto Finish;
    /* No stored keystore that we can access; create one. */
    res = ndn_keystore_file_init(keystore_path, NDND_KEYSTORE_PASS, "NDND-internal", 0, 0);
    if (res != 0) {
        culprit = temp;
        goto Finish;
    }
    res = ndn_load_default_key(ndnd->internal_client, keystore_path, NDND_KEYSTORE_PASS);
    if (res != 0)
        culprit = temp;
Finish:
    if (culprit != NULL) {
        ndnd_msg(ndnd, "%s: %s:\n", ndn_charbuf_as_string(culprit), strerror(errno));
        culprit = NULL;
    }
    res = ndn_chk_signing_params(ndnd->internal_client, NULL, &sp, NULL, NULL, NULL, NULL);
    if (res != 0)
        abort();
    memcpy(ndnd->ndnd_id, sp.pubid, sizeof(ndnd->ndnd_id));
    ndn_charbuf_destroy(&temp);
    ndn_charbuf_destroy(&cmd);
    if (keystore_path != NULL)
        free(keystore_path);
    return(res);
}

static int
post_face_notice(struct ndnd_handle *ndnd, unsigned faceid)
{
    struct face *face = ndnd_face_from_faceid(ndnd, faceid);
    struct ndn_charbuf *msg = ndn_charbuf_create();
    int res = -1;
    int port;
    int n;
    
    // XXX - text version for trying out stream stuff - replace with ndnb
    if (face == NULL)
        ndn_charbuf_putf(msg, "destroyface(%u);\n", faceid);
    else {
        ndn_charbuf_putf(msg, "newface(%u, 0x%x", faceid, face->flags);
        n = 2;
        if (face->addr != NULL &&
            (face->flags & (NDN_FACE_INET | NDN_FACE_INET6)) != 0) {
            ndn_charbuf_putf(msg, ", ");
            n++;
            port = ndn_charbuf_append_sockaddr(msg, face->addr);
            if (port < 0)
                msg->length--;
            else if (port > 0)
                ndn_charbuf_putf(msg, ":%d", port);
        }
        if ((face->flags & NDN_FACE_ADJ) != 0) {
            for (; n < 4; n++)
                ndn_charbuf_putf(msg, ", ");
            append_adjacency_uri(ndnd, msg, face);
        }
        ndn_charbuf_putf(msg, ");\n", faceid);
    }
    res = ndn_seqw_write(ndnd->notice, msg->buf, msg->length);
    ndn_charbuf_destroy(&msg);
    return(res);
}

static int
ndnd_notice_push(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnd_handle *ndnd = clienth;
    struct ndn_indexbuf *chface = NULL;
    int i = 0;
    int j = 0;
    int microsec = 0;
    int res = 0;
    
    if ((flags & NDN_SCHEDULE_CANCEL) == 0 &&
            ndnd->notice != NULL &&
            ndnd->notice_push == ev &&
            ndnd->chface != NULL) {
        chface = ndnd->chface;
        ndn_seqw_batch_start(ndnd->notice);
        for (i = 0; i < chface->n && res != -1; i++)
            res = post_face_notice(ndnd, chface->buf[i]);
        ndn_seqw_batch_end(ndnd->notice);
        for (j = 0; i < chface->n; i++, j++)
            chface->buf[j] = chface->buf[i];
        chface->n = j;
        if (res == -1)
            microsec = 3000;
    }
    if (microsec <= 0)
        ndnd->notice_push = NULL;
    return(microsec);
}

/**
 * Called by ndnd when a face undergoes a substantive status change that
 * should be reported to interested parties.
 *
 * In the destroy case, this is called from the hash table finalizer,
 * so it shouldn't do much directly.  Inspecting the face is OK, though.
 */
void
ndnd_face_status_change(struct ndnd_handle *ndnd, unsigned faceid)
{
    struct ndn_indexbuf *chface = ndnd->chface;
    
    if (chface != NULL) {
        ndn_indexbuf_set_insert(chface, faceid);
        if (ndnd->notice_push == NULL)
            ndnd->notice_push = ndn_schedule_event(ndnd->sched, 2000,
                                                   ndnd_notice_push,
                                                   NULL, 0);
    }
    schedule_adjacency_negotiation(ndnd, faceid);
}

static void
ndnd_start_notice(struct ndnd_handle *ndnd)
{
    struct ndn *h = ndnd->internal_client;
    struct ndn_charbuf *name = NULL;
    struct face *face = NULL;
    int i;
    
    if (h == NULL)
        return;
    if (ndnd->notice != NULL)
        return;
    if (ndnd->chface != NULL) {
        /* Probably should not happen. */
        ndnd_msg(ndnd, "ndnd_internal_client.c:%d Huh?", __LINE__);
        ndn_indexbuf_destroy(&ndnd->chface);
    }
    name = ndn_charbuf_create();
    ndn_name_from_uri(name, "ndn:/ndnx");
    ndn_name_append(name, ndnd->ndnd_id, 32);
    ndn_name_append_str(name, NDND_NOTICE_NAME);
    ndnd->notice = ndn_seqw_create(h, name);
    ndnd->chface = ndn_indexbuf_create();
    for (i = 0; i < ndnd->face_limit; i++) {
        face = ndnd->faces_by_faceid[i];
        if (face != NULL)
            ndn_indexbuf_set_insert(ndnd->chface, face->faceid);
    }
    if (ndnd->chface->n > 0)
        ndnd_face_status_change(ndnd, ndnd->chface->buf[0]);
    ndn_charbuf_destroy(&name);
}

int
ndnd_internal_client_start(struct ndnd_handle *ndnd)
{
    struct ndn *h;
    if (ndnd->internal_client != NULL)
        return(-1);
    if (ndnd->face0 == NULL)
        abort();
    ndnd->internal_client = h = ndn_create();
    if (ndnd_init_internal_keystore(ndnd) < 0) {
        ndn_destroy(&ndnd->internal_client);
        return(-1);
    }
#if (NDND_PING+0)
    ndnd_uri_listen(ndnd, "ndn:/ndnx/ping",
                    &ndnd_answer_req, OP_PING);
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/ping",
                    &ndnd_answer_req, OP_PING);
#endif
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/newface",
                    &ndnd_answer_req, OP_NEWFACE + MUST_VERIFY1);
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/destroyface",
                    &ndnd_answer_req, OP_DESTROYFACE + MUST_VERIFY1);
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/prefixreg",
                    &ndnd_answer_req, OP_PREFIXREG + MUST_VERIFY1);
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/selfreg",
                    &ndnd_answer_req, OP_SELFREG + MUST_VERIFY1);
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/unreg",
                    &ndnd_answer_req, OP_UNREG + MUST_VERIFY1);
    ndnd_uri_listen(ndnd, "ndn:/ndnx/" NDND_ID_TEMPL "/" NDND_NOTICE_NAME,
                    &ndnd_answer_req, OP_NOTICE);
    ndnd_uri_listen(ndnd, "ndn:/%C1.M.S.localhost/%C1.M.SRV/ndnd",
                    &ndnd_answer_req, OP_SERVICE);
    ndnd_uri_listen(ndnd, "ndn:/%C1.M.S.neighborhood",
                    &ndnd_answer_req, OP_SERVICE);
    ndnd_uri_listen(ndnd, "ndn:/%C1.M.S.neighborhood/guest",
                    &ndnd_answer_req, OP_GUEST);
    ndnd_uri_listen(ndnd, "ndn:/%C1.M.FACE",
                    &ndnd_answer_req, OP_ADJACENCY);
    ndnd_reg_ndnx_ndndid(ndnd);
    ndnd_reg_uri(ndnd, "ndn:/%C1.M.S.localhost",
                 0, /* special faceid for internal client */
                 (NDN_FORW_CHILD_INHERIT |
                  NDN_FORW_ACTIVE        |
                  NDN_FORW_LOCAL         ),
                 0x7FFFFFFF);
    ndnd->internal_client_refresh \
    = ndn_schedule_event(ndnd->sched, 50000,
                         ndnd_internal_client_refresh,
                         NULL, NDN_INTEREST_LIFETIME_MICROSEC);
    return(0);
}

void
ndnd_internal_client_stop(struct ndnd_handle *ndnd)
{
    ndnd->notice = NULL; /* ndn_destroy will free */
    if (ndnd->notice_push != NULL)
        ndn_schedule_cancel(ndnd->sched, ndnd->notice_push);
    ndn_indexbuf_destroy(&ndnd->chface);
    ndn_destroy(&ndnd->internal_client);
    ndn_charbuf_destroy(&ndnd->service_ndnb);
    ndn_charbuf_destroy(&ndnd->neighbor_ndnb);
    if (ndnd->internal_client_refresh != NULL)
        ndn_schedule_cancel(ndnd->sched, ndnd->internal_client_refresh);
}
