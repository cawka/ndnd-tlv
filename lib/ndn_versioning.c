/**
 * @file ndn_versioning.c
 * @brief Versioning support.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2013 Palo Alto Research Center, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ndn/bloom.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/uri.h>
#include <ndn/ndn_private.h>
#include <sys/time.h>

#define FF 0xff

/**
 * This appends a filter useful for
 * excluding everything between two 'fenceposts' in an Exclude construct.
 */
static void
append_filter_all(struct ndn_charbuf *c)
{
    ndn_charbuf_append_tt(c, NDN_DTAG_Any, NDN_DTAG);
    ndn_charbuf_append_closer(c);
}

/**
 * Append AnswerOriginKind=1 to partially constructed Interest, meaning
 * do not generate new content.
 */
static void
answer_passive(struct ndn_charbuf *templ)
{
    ndn_charbuf_append_tt(templ, NDN_DTAG_AnswerOriginKind, NDN_DTAG);
    ndn_charbuf_append_tt(templ, 1, NDN_UDATA);
    ndn_charbuf_append(templ, "1", 1);
    ndn_charbuf_append_closer(templ); /* </AnswerOriginKind> */
}

/**
 * Append ChildSelector to partially constructed Interest, meaning
 * prefer to send rightmost available.
 */
static void
answer_highest(struct ndn_charbuf *templ)
{
    ndnb_tagged_putf(templ, NDN_DTAG_ChildSelector, "1");
}

static void
append_future_vcomp(struct ndn_charbuf *templ)
{
    /* One beyond a distant future version stamp */
    unsigned char b[7] = {NDN_MARKER_VERSION + 1, 0, 0, 0, 0, 0, 0};
    ndn_charbuf_append_tt(templ, NDN_DTAG_Component, NDN_DTAG);
    ndn_charbuf_append_tt(templ, sizeof(b), NDN_BLOB);
    ndn_charbuf_append(templ, b, sizeof(b));
    ndn_charbuf_append_closer(templ); /* </Component> */
}

static struct ndn_charbuf *
resolve_templ(struct ndn_charbuf *templ, unsigned const char *vcomp,
              int size, int lifetime, int versioning_flags)
{
    if (templ == NULL)
        templ = ndn_charbuf_create();
    if (size < 3 || size > 16) {
        ndn_charbuf_destroy(&templ);
        return(NULL);
    }
    templ->length = 0;
    ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
    ndn_charbuf_append_closer(templ); /* </Name> */
    ndn_charbuf_append_tt(templ, NDN_DTAG_Exclude, NDN_DTAG);
    append_filter_all(templ);
    ndn_charbuf_append_tt(templ, NDN_DTAG_Component, NDN_DTAG);
    ndn_charbuf_append_tt(templ, size, NDN_BLOB);
    ndn_charbuf_append(templ, vcomp, size);
    ndn_charbuf_append_closer(templ); /* </Component> */
    append_future_vcomp(templ);
    append_filter_all(templ);
    ndn_charbuf_append_closer(templ); /* </Exclude> */
    answer_highest(templ);
    answer_passive(templ);
    if ((versioning_flags & NDN_V_SCOPE2) != 0)
        ndnb_tagged_putf(templ, NDN_DTAG_Scope, "%d", 2);
    else if ((versioning_flags & NDN_V_SCOPE1) != 0)
        ndnb_tagged_putf(templ, NDN_DTAG_Scope, "%d", 1);
    else if ((versioning_flags & NDN_V_SCOPE0) != 0)
        ndnb_tagged_putf(templ, NDN_DTAG_Scope, "%d", 0);
    if (lifetime > 0)
        ndnb_append_tagged_binary_number(templ, NDN_DTAG_InterestLifetime, lifetime);
    ndn_charbuf_append_closer(templ); /* </Interest> */
    return(templ);
}

static int
ms_to_tu(int m)
{
    return ((m * 4096) / 1000);
}

/**
 * Resolve the version, based on existing ndn content.
 * @param h is the the ndn handle; it may be NULL, but it is preferable to
 *        use the handle that the client probably already has.
 * @param name is a ndnb-encoded Name prefix. It gets extended in-place with
 *        one additional Component such that it names highest extant
 *        version that can be found, subject to the supplied timeout.
 * @param versioning_flags presently must be NDN_V_HIGH or NDN_V_HIGHEST,
 *        possibly combined with NDN_V_NESTOK.  If NDN_V_NESTOK is not present
 *        and the ending component appears to be a version, the routine
 *        returns 0 immediately, on the assumption that an explicit
 *        version has already been provided.
 * @param timeout_ms is a time value in milliseconds. This is the total time
 *        that the caller can wait.
 * @returns -1 for error, 0 if name was not extended, 1 if was.
 */
int
ndn_resolve_version(struct ndn *h, struct ndn_charbuf *name,
                    int versioning_flags, int timeout_ms)
{
    int res;
    int myres = -1;
    struct ndn_parsed_ContentObject pco_space = { 0 };
    struct ndn_charbuf *templ = NULL;
    struct ndn_charbuf *prefix = ndn_charbuf_create();
    struct ndn_charbuf *cobj = ndn_charbuf_create();
    struct ndn_parsed_ContentObject *pco = &pco_space;
    struct ndn_indexbuf *ndx = ndn_indexbuf_create();
    const unsigned char *vers = NULL;
    size_t vers_size = 0;
    struct timeval start, prev, now;
    int n;
    int rtt_max = 0;
    int rtt;
    int ttimeout;
    struct ndn_indexbuf *nix = ndn_indexbuf_create();
    unsigned char lowtime[7] = {NDN_MARKER_VERSION, 0, FF, FF, FF, FF, FF};
    
    if ((versioning_flags & ~NDN_V_NESTOK & ~NDN_V_EST) != NDN_V_HIGH) {
        ndn_seterror(h, EINVAL);
        ndn_perror(h, "ndn_resolve_version is only implemented for versioning_flags = NDN_V_HIGH(EST)");
        goto Finish;
    }
    n = ndn_name_split(name, nix);
    if (n < 0)
        goto Finish;
    if ((versioning_flags & NDN_V_NESTOK) == 0) {
        res = ndn_name_comp_get(name->buf, nix, n - 1, &vers, &vers_size);
        if (res >= 0 && vers_size == 7 && vers[0] == NDN_MARKER_VERSION) {
            myres = 0;
            goto Finish;
        }    
    }
    templ = resolve_templ(templ, lowtime, sizeof(lowtime),
                          ms_to_tu(timeout_ms) * 7 / 8, versioning_flags);
    ndn_charbuf_append(prefix, name->buf, name->length); /* our copy */
    cobj->length = 0;
    gettimeofday(&start, NULL);
    prev = start;
    /*
     * the algorithm for NDN_V_HIGHEST is to send the initial Interest with
     * a lifetime that will ensure 1 resend before the timeout, and to keep
     * keep sending an Interest, excluding earlier versions, tracking the
     * maximum round trip time and using a timeout of 4*RTT, and an interest
     * lifetime that should get a retransmit.   If there is no response,
     * return the highest version found so far.
     */
    myres = 0;
    res = ndn_get(h, prefix, templ, timeout_ms, cobj, pco, ndx, 0);
    while (cobj->length != 0) {
        if (pco->type == NDN_CONTENT_NACK) // XXX - also check for number of components
            break;
        res = ndn_name_comp_get(cobj->buf, ndx, n, &vers, &vers_size);
        if (res < 0)
            break;
        if (vers_size == 7 && vers[0] == NDN_MARKER_VERSION) {
            /* Looks like we have versions. */
            name->length = 0;
            ndn_charbuf_append(name, prefix->buf, prefix->length);
            ndn_name_append(name, vers, vers_size);
            myres = 1;
            if ((versioning_flags & NDN_V_EST) == 0)
                break;
            gettimeofday(&now, NULL);
            rtt = (now.tv_sec - prev.tv_sec) * 1000000 + (now.tv_usec - prev.tv_usec);
            if (rtt > rtt_max) rtt_max = rtt;
            prev = now;
            timeout_ms -= (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
            if (timeout_ms <= 0)
                break;
            ttimeout = timeout_ms < (rtt_max/250) ? timeout_ms : (rtt_max/250);
            templ = resolve_templ(templ, vers, vers_size, ms_to_tu(ttimeout) * 7 / 8, versioning_flags);
            if (templ == NULL) break;
            cobj->length = 0;
            res = ndn_get(h, prefix, templ, ttimeout, cobj, pco, ndx,
                          NDN_GET_NOKEYWAIT);
        }
        else break;
    }
Finish:
    ndn_charbuf_destroy(&prefix);
    ndn_charbuf_destroy(&cobj);
    ndn_indexbuf_destroy(&ndx);
    ndn_indexbuf_destroy(&nix);
    ndn_charbuf_destroy(&templ);
    return(myres);
}

/**
 * Extend a Name with a new version stamp
 * @param h is the the ndn handle.
 *        May be NULL.  This procedure does not use the connection.
 * @param name is a ndnb-encoded Name prefix. By default it gets extended
 *        in-place with one additional Component that conforms to the
 *        versioning profile and is based on the supplied time, unless a
 *        version component is already present.
 * @param versioning_flags modifies the default behavior:
 *        NDN_V_REPLACE causes the last component to be replaced if it
 *        appears to be a version stamp.  If NDN_V_HIGH is set as well, an
 *        attempt will be made to generate a new version stamp that is
 *        later than the existing one, or to return an error.
 *        NDN_V_NOW bases the version on the current time rather than the
 *        supplied time.
 *        NDN_V_NESTOK will allow the new version component to be appended
 *        even if there is one there (this makes no difference if NDN_V_REPLACE
 *        is also set).
 * @param secs is the desired time, in seconds since epoch
 *        (ignored if NDN_V_NOW is set).
 * @param nsecs is the number of nanoseconds.
 * @returns -1 for error, 0 for success.
 */
int
ndn_create_version(struct ndn *h, struct ndn_charbuf *name,
                   int versioning_flags, intmax_t secs, int nsecs)
{
    size_t i;
    size_t j;
    size_t lc = 0;
    size_t oc = 0;
    int n;
    struct ndn_indexbuf *nix = NULL;
    int myres = -1;
    int already_versioned = 0;
    int ok_flags = (NDN_V_REPLACE | NDN_V_HIGH | NDN_V_NOW | NDN_V_NESTOK);
    // XXX - right now we ignore h, but in the future we may use it to try to avoid non-monotonicies in the versions.
    
    nix = ndn_indexbuf_create();
    n = ndn_name_split(name, nix);
    if (n < 0)
        goto Finish;
    if ((versioning_flags & ~ok_flags) != 0)
        goto Finish;        
    /* Check for existing version component */
    if (n >= 1) {
        oc = nix->buf[n-1];
        lc = nix->buf[n] - oc;
        if (lc <= 11 && lc >= 6 && name->buf[oc + 2] == NDN_MARKER_VERSION)
            already_versioned = 1;
    }
    myres = 0;
    if (already_versioned &&
        (versioning_flags & (NDN_V_REPLACE | NDN_V_NESTOK)) == 0)
        goto Finish;
    name->length -= 1; /* Strip name closer */
    i = name->length;
    myres |= ndn_charbuf_append_tt(name, NDN_DTAG_Component, NDN_DTAG);
    if ((versioning_flags & NDN_V_NOW) != 0)
        myres |= ndnb_append_now_blob(name, NDN_MARKER_VERSION);
    else {
        myres |= ndnb_append_timestamp_blob(name, NDN_MARKER_VERSION, secs, nsecs);
    }
    myres |= ndn_charbuf_append_closer(name); /* </Component> */
    if (myres < 0) {
        name->length = i;
        goto CloseName;
    }
    j = name->length;
    if (already_versioned && (versioning_flags & NDN_V_REPLACE) != 0) {
        oc = nix->buf[n-1];
        lc = nix->buf[n] - oc;
        if ((versioning_flags & NDN_V_HIGH) != 0 &&
            memcmp(name->buf + oc, name->buf + i, j - i) > 0) {
            /* Supplied version is in the future. */
            name->length = i;
            // XXX - we could try harder to make this work, for now just error out
            myres = -1;
            goto CloseName;
        }
        memmove(name->buf + oc, name->buf + i, j - i);
        name->length -= lc;
    }
CloseName:
    myres |= ndn_charbuf_append_closer(name); /* </Name> */
Finish:
    myres = (myres < 0) ? -1 : 0;
    ndn_indexbuf_destroy(&nix);
    return(myres);
}
