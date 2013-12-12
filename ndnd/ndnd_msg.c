/**
 * @file ndnd_msg.c
 *
 * Logging support for ndnd.
 *
 * Part of ndnd - the NDNx Daemon.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2013 Palo Alto Research Center, Inc.
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

#include <stdio.h>
#include <sys/time.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include <ndn/ndn.h>
#include <ndn/ndnd.h>
#include <ndn/charbuf.h>
#include <ndn/hashtb.h>
#include <ndn/uri.h>

#include "ndnd_private.h"

/**
 *  Produce ndnd debug output.
 *  Output is produced via h->logger under the control of h->debug;
 *  prepends decimal timestamp and process identification.
 *  Caller should not supply newlines.
 *  @param      h  the ndnd handle
 *  @param      fmt  printf-like format string
 */
void
ndnd_msg(struct ndnd_handle *h, const char *fmt, ...)
{
    struct timeval t;
    va_list ap;
    struct ndn_charbuf *b;
    int res;
    time_t clock;
    if (h == NULL || h->debug == 0 || h->logger == 0)
        return;
    b = ndn_charbuf_create();
    gettimeofday(&t, NULL);
    if (((h->debug & 64) != 0) &&
        ((h->logbreak-- < 0 && t.tv_sec != h->logtime) ||
          t.tv_sec >= h->logtime + 30)) {
        clock = t.tv_sec;
        ndn_charbuf_putf(b, "%ld.000000 ndnd[%d]: %s ____________________ %s",
                         (long)t.tv_sec, h->logpid,
                         h->portstr ? h->portstr : "",
                         ctime(&clock));
        h->logtime = t.tv_sec;
        h->logbreak = 30;
    }
    ndn_charbuf_putf(b, "%ld.%06u ", (long)t.tv_sec, (unsigned)t.tv_usec);
    if (h->debug & 32)
        ndn_charbuf_putf(b, "%08x.", (unsigned)h->wtnow);
    ndn_charbuf_putf(b, "ndnd[%d]: %s\n", h->logpid, fmt);
    va_start(ap, fmt);
    res = (*h->logger)(h->loggerdata, (const char *)b->buf, ap);
    va_end(ap);
    ndn_charbuf_destroy(&b);
    /* if there's no one to hear, don't make a sound */
    if (res < 0)
        h->debug = 0;
}

/**
 *  Construct a printable representation of an Interest's excludes,
 *  and append it to the supplied ndn_charbuf.
 *  @param      c   pointer to the charbuf to append to
 *  @param      ndnb    pointer to ndnb-encoded Interest
 *  @param      pi  pointer to the parsed interest data
 *  @param      limit   number of components to print before ending with "..."
 */
void
ndnd_append_excludes(struct ndn_charbuf *c,
                     const unsigned char *ndnb,
                     struct ndn_parsed_interest *pi,
                     int limit)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    const unsigned char *bloom;
    size_t bloom_size = 0;
    const unsigned char *comp;
    size_t comp_size;
    int sep = 0;
    int l = pi->offset[NDN_PI_E_Exclude] - pi->offset[NDN_PI_B_Exclude];
    
    if (l <= 0) return;
    
    d = ndn_buf_decoder_start(&decoder, ndnb + pi->offset[NDN_PI_B_Exclude], l);
    if (!ndn_buf_match_dtag(d, NDN_DTAG_Exclude)) return;

    ndn_buf_advance(d);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
        ndn_buf_advance(d);
        ndn_charbuf_append_string(c, "*");
        ndn_buf_check_close(d);
        sep = 1;
    }
    else if (ndn_buf_match_dtag(d, NDN_DTAG_Bloom)) {
        ndn_buf_advance(d);
        if (ndn_buf_match_blob(d, &bloom, &bloom_size))
            ndn_buf_advance(d);
        ndn_charbuf_append_string(c, "?");
        ndn_buf_check_close(d);
        sep = 1;
    }
    while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
        if (sep) ndn_charbuf_append_string(c, ",");
        if (0 == limit--) {
            ndn_charbuf_append_string(c, " ..");
            return;
        }
        ndn_buf_advance(d);
        comp_size = 0;
        if (ndn_buf_match_blob(d, &comp, &comp_size))
            ndn_buf_advance(d);
        ndn_uri_append_percentescaped(c, comp, comp_size);
        ndn_buf_check_close(d);
        if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
            ndn_buf_advance(d);
            ndn_charbuf_append_string(c, ",*");
            ndn_buf_check_close(d);
        }
        else if (ndn_buf_match_dtag(d, NDN_DTAG_Bloom)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, &bloom, &bloom_size))
                ndn_buf_advance(d);
            ndn_charbuf_append_string(c, ",?");
            ndn_buf_check_close(d);
        }
        sep = 1;
    }
}

/**
 *  Produce a ndnd debug trace entry.
 *  Output is produced by calling ndnd_msg.
 *  @param      h  the ndnd handle
 *  @param      lineno  caller's source line number (usually __LINE__)
 *  @param      msg  a short text tag to identify the entry
 *  @param      face    handle of associated face; may be NULL
 *  @param      ndnb    points to ndnb-encoded Interest or ContentObject
 *  @param      ndnb_size   is in bytes
 */
void
ndnd_debug_ndnb(struct ndnd_handle *h,
                int lineno,
                const char *msg,
                struct face *face,
                const unsigned char *ndnb,
                size_t ndnb_size)
{
    struct ndn_charbuf *c;
    struct ndn_parsed_interest pi = {
        0
    };
    const unsigned char *nonce = NULL;
    size_t nonce_size = 0;
    const unsigned char *pubkey = NULL;
    size_t pubkey_size = 0;
    size_t i;
    size_t sim_hash = 0;
    struct interest_entry *ie = NULL;
    int default_lifetime = NDN_INTEREST_LIFETIME_SEC << 12;
    intmax_t lifetime = default_lifetime;
    
    if (h != NULL && h->debug == 0)
        return;
    if (ndn_parse_interest(ndnb, ndnb_size, &pi, NULL) >= 0) {
        pubkey_size = (pi.offset[NDN_PI_E_PublisherIDKeyDigest] -
                       pi.offset[NDN_PI_B_PublisherIDKeyDigest]);
        pubkey = ndnb + pi.offset[NDN_PI_B_PublisherIDKeyDigest];
        lifetime = ndn_interest_lifetime(ndnb, &pi);
        ndn_ref_tagged_BLOB(NDN_DTAG_Nonce, ndnb,
                  pi.offset[NDN_PI_B_Nonce],
                  pi.offset[NDN_PI_E_Nonce],
                  &nonce,
                  &nonce_size);
        ie = hashtb_lookup(h->interest_tab, ndnb, pi.offset[NDN_PI_B_Nonce]);
        sim_hash = hashtb_hash(ndnb, pi.offset[NDN_PI_B_InterestLifetime]);
    }
    else {
        pi.min_suffix_comps = 0;
        pi.max_suffix_comps = 32767;
        pi.orderpref = 0;
        pi.answerfrom = NDN_AOK_DEFAULT;
        pi.scope = -1;
    }
    c = ndn_charbuf_create();
    ndn_charbuf_putf(c, "debug.%d %s ", lineno, msg);
    if (face != NULL)
        ndn_charbuf_putf(c, "%u ", face->faceid);
    ndn_uri_append(c, ndnb, ndnb_size, 1);
    ndn_charbuf_putf(c, " (%u bytes", (unsigned)ndnb_size);
    if (pi.min_suffix_comps != 0 || pi.max_suffix_comps != 32767) {
        ndn_charbuf_putf(c, ",c=%d", pi.min_suffix_comps);
        if (pi.min_suffix_comps != pi.max_suffix_comps) {
            ndn_charbuf_putf(c, ":");
            if (pi.max_suffix_comps != 32767)
                ndn_charbuf_putf(c, "%d", pi.max_suffix_comps);
        }
    }
    if (pubkey_size >= 3)
        ndn_charbuf_putf(c, ",pb=%02X%02X%02X",
                         pubkey[0], pubkey[1], pubkey[2]);
    if (pi.orderpref != 0)
        ndn_charbuf_putf(c, ",cs=%d", pi.orderpref);
    if (pi.answerfrom != NDN_AOK_DEFAULT)
        ndn_charbuf_putf(c, ",aok=%#x", pi.answerfrom);
    if (pi.scope != -1)
        ndn_charbuf_putf(c, ",scope=%d", pi.scope);
    if (lifetime != default_lifetime) {
        ndn_charbuf_putf(c, ",life=%d.%04d",
                         (int)(lifetime >> 12),
                         (int)(lifetime & 0xFFF) * 10000 / 4096);
    }
    if (ie != NULL)
        ndn_charbuf_putf(c, ",i=%u", ie->serial);
    if (sim_hash != 0)
        ndn_charbuf_putf(c, ",sim=%08X", (unsigned)sim_hash);
    if (pi.offset[NDN_PI_E_Exclude] - pi.offset[NDN_PI_B_Exclude] > 0) {
        ndn_charbuf_putf(c, ",e=[");
        ndnd_append_excludes(c, ndnb, &pi, h->debug & 16 ? -1 : 7);
        ndn_charbuf_putf(c, "]");
    }
    ndn_charbuf_putf(c, ")");
    if (nonce_size > 0) {
        const char *p = "";
        ndn_charbuf_putf(c, " ");
        if (nonce_size == 12)
            p = "CCC-P-F-T-NN";
        for (i = 0; i < nonce_size; i++)
            ndn_charbuf_putf(c, "%s%02X", (*p) && (*p++)=='-' ? "-" : "", nonce[i]);
    }
    ndnd_msg(h, "%s", ndn_charbuf_as_string(c));
    ndn_charbuf_destroy(&c);
}

/**
 * NDND Usage message
 */
const char *ndnd_usage_message =
    "ndnd - NDNx Daemon\n"
    "  options: none\n"
    "  arguments: none\n"
    "  environment variables:\n"
    "    NDND_DEBUG=\n"
    "      0 - no messages\n"
    "      1 - basic messages (any non-zero value gets these)\n"
    "      2 - interest messages\n"
    "      4 - content messages\n"
    "      8 - matching details\n"
    "      16 - interest details\n"
    "      32 - gory interest details\n"
    "      64 - log occasional human-readable timestamps\n"
    "      128 - face registration debugging\n"
    "      bitwise OR these together for combinations; -1 gets max logging\n"
    "    NDN_LOCAL_PORT=\n"
    "      UDP port for unicast clients (default "NDN_DEFAULT_UNICAST_PORT").\n"
    "      Also listens on this TCP port for stream connections.\n"
    "      Also affects name of unix-domain socket.\n"
    "    NDN_LOCAL_SOCKNAME=\n"
    "      Name stem of unix-domain socket (default "NDN_DEFAULT_LOCAL_SOCKNAME").\n"
    "    NDND_CAP=\n"
    "      Capacity limit, in count of ContentObjects.\n"
    "      Not an absolute limit.\n"
    "    NDND_MTU=\n"
    "      Packet size in bytes.\n"
    "      If set, interest stuffing is allowed within this budget.\n"
    "      Single items larger than this are not precluded.\n"
    "    NDND_DATA_PAUSE_MICROSEC=\n"
    "      Adjusts content-send delay time for multicast and udplink faces\n"
    "    NDND_DEFAULT_TIME_TO_STALE=\n"
    "      Default for content objects without explicit FreshnessSeconds\n"
    "    NDND_MAX_TIME_TO_STALE=\n"
    "      Limit, in seconds, until content becomes stale\n"
    "    NDND_MAX_RTE_MICROSEC=\n"
    "      Value used to limit response time estimates kept by default strategy.\n"
    "    NDND_KEYSTORE_DIRECTORY=\n"
    "      Directory readable only by ndnd where its keystores are kept\n"
    "      Defaults to a private subdirectory of /var/tmp\n"
    "    NDND_LISTEN_ON=\n"
    "      List of ip addresses to listen on; defaults to wildcard\n"
    "    NDND_AUTOREG=\n"
    "      List of prefixes to auto-register on new faces initiated by peers\n"
    "      example: NDND_AUTOREG=ndn:/like/this,ndn:/and/this\n"
    "    NDND_PREFIX=\n"
    "      A prefix stem to use for generating guest prefixes\n"
    ;
