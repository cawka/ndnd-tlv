/**
 * @file ndnd_stats.c
 *
 * Statistics presentation for ndnd.
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

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/ndnd.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>
#include <ndn/indexbuf.h>
#include <ndn/schedule.h>
#include <ndn/sockaddrutil.h>
#include <ndn/hashtb.h>
#include <ndn/uri.h>

#include "ndnd_private.h"

#define CRLF "\r\n"
#define NL   "\n"

/**
 * Provide a way to monitor rates.
 */
struct ndnd_meter {
    uintmax_t total;
    char what[8];
    unsigned rate; /** a scale factor applies */
    unsigned lastupdate;
};

struct ndnd_stats {
    long total_interest_counts;
};

static int ndnd_collect_stats(struct ndnd_handle *h, struct ndnd_stats *ans);
static struct ndn_charbuf *collect_stats_html(struct ndnd_handle *h);
static void send_http_response(struct ndnd_handle *h, struct face *face,
                               const char *mime_type,
                               struct ndn_charbuf *response);
static struct ndn_charbuf *collect_stats_html(struct ndnd_handle *h);
static struct ndn_charbuf *collect_stats_xml(struct ndnd_handle *h);

/* HTTP */

static const char *resp404 =
    "HTTP/1.1 404 Not Found" CRLF
    "Connection: close" CRLF CRLF;

static const char *resp405 =
    "HTTP/1.1 405 Method Not Allowed" CRLF
    "Connection: close" CRLF CRLF;

static void
ndnd_stats_http_set_debug(struct ndnd_handle *h, struct face *face, int level)
{
    struct ndn_charbuf *response = ndn_charbuf_create();
    
    h->debug = 1;
    ndnd_msg(h, "NDND_DEBUG=%d", level);
    h->debug = level;
    ndn_charbuf_putf(response, "<title>NDND_DEBUG=%d</title><tt>NDND_DEBUG=%d</tt>" CRLF, level, level);
    send_http_response(h, face, "text/html", response);
    ndn_charbuf_destroy(&response);
}

int
ndnd_stats_handle_http_connection(struct ndnd_handle *h, struct face *face)
{
    struct ndn_charbuf *response = NULL;
    char rbuf[16];
    int i;
    int nspace;
    int n;
    
    if (face->inbuf->length < 4)
        return(-1);
    if ((face->flags & NDN_FACE_NOSEND) != 0) {
        ndnd_destroy_face(h, face->faceid);
        return(-1);
    }
    n = sizeof(rbuf) - 1;
    if (face->inbuf->length < n)
        n = face->inbuf->length;
    for (i = 0, nspace = 0; i < n && nspace < 2; i++) {
        rbuf[i] = face->inbuf->buf[i];
        if (rbuf[i] == ' ')
            nspace++;
    }
    rbuf[i] = 0;
    if (nspace < 2 && i < sizeof(rbuf) - 1)
        return(-1);
    if (0 == strcmp(rbuf, "GET / ") ||
        0 == strcmp(rbuf, "GET /? ")) {
        response = collect_stats_html(h);
        send_http_response(h, face, "text/html", response);
    }
    else if (0 == strcmp(rbuf, "GET /?l=none ")) {
        ndnd_stats_http_set_debug(h, face, 0);
    }
    else if (0 == strcmp(rbuf, "GET /?l=low ")) {
        ndnd_stats_http_set_debug(h, face, 1);
    }
    else if (0 == strcmp(rbuf, "GET /?l=co ")) {
        ndnd_stats_http_set_debug(h, face, 4);
    }
    else if (0 == strcmp(rbuf, "GET /?l=med ")) {
        ndnd_stats_http_set_debug(h, face, 71);
    }
    else if (0 == strcmp(rbuf, "GET /?l=high ")) {
        ndnd_stats_http_set_debug(h, face, -1);
    }
    else if (0 == strcmp(rbuf, "GET /?f=xml ")) {
        response = collect_stats_xml(h);
        send_http_response(h, face, "text/xml", response);
    }
    else if (0 == strcmp(rbuf, "GET "))
        ndnd_send(h, face, resp404, strlen(resp404));
    else
        ndnd_send(h, face, resp405, strlen(resp405));
    face->flags |= (NDN_FACE_NOSEND | NDN_FACE_CLOSING);
    ndn_charbuf_destroy(&response);
    return(0);
}

static void
send_http_response(struct ndnd_handle *h, struct face *face,
                   const char *mime_type, struct ndn_charbuf *response)
{
    struct linger linger = { .l_onoff = 1, .l_linger = 1 };
    char buf[128];
    int hdrlen;

    /* Set linger to prevent quickly resetting the connection on close.*/
    setsockopt(face->recv_fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
    hdrlen = snprintf(buf, sizeof(buf),
                      "HTTP/1.1 200 OK" CRLF
                      "Content-Type: %s; charset=utf-8" CRLF
                      "Connection: close" CRLF
                      "Content-Length: %jd" CRLF CRLF,
                      mime_type,
                      (intmax_t)response->length);
    ndnd_send(h, face, buf, hdrlen);
    ndnd_send(h, face, response->buf, response->length);
}

/* Common statistics collection */

static int
ndnd_collect_stats(struct ndnd_handle *h, struct ndnd_stats *ans)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    long sum;
    unsigned i;
    for (sum = 0, hashtb_start(h->nameprefix_tab, e);
         e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *npe = e->data;
        struct ielinks *head = &npe->ie_head;
        struct ielinks *ll;
        for (ll = head->next; ll != head; ll = ll->next) {
            struct interest_entry *ie = (struct interest_entry *)ll;
            struct pit_face_item *p;
            for (p = ie->pfl; p != NULL; p = p->next)
                if ((p->pfi_flags & NDND_PFI_PENDING) != 0)
                    if (ndnd_face_from_faceid(h, p->faceid) != NULL)
                        sum += 1;
        }
    }
    ans->total_interest_counts = sum;
    hashtb_end(e);
    /* Do a consistency check on pending interest counts */
    for (sum = 0, i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL)
            sum += face->pending_interests;
    }
    if (sum != ans->total_interest_counts)
        ndnd_msg(h, "ndnd_collect_stats found inconsistency %ld != %ld\n",
                 (long)sum, (long)ans->total_interest_counts);
    ans->total_interest_counts = sum;
    return(0);
}

/* HTML formatting */

static void
collect_faces_html(struct ndnd_handle *h, struct ndn_charbuf *b)
{
    int i;
    struct ndn_charbuf *nodebuf;
    int port;
    
    nodebuf = ndn_charbuf_create();
    ndn_charbuf_putf(b, "<h4>Faces</h4>" NL);
    ndn_charbuf_putf(b, "<ul>");
    for (i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL && (face->flags & NDN_FACE_UNDECIDED) == 0) {
            ndn_charbuf_putf(b, " <li>");
            ndn_charbuf_putf(b, "<b>face:</b> %u <b>flags:</b> 0x%x",
                             face->faceid, face->flags);
            ndn_charbuf_putf(b, " <b>pending:</b> %d",
                             face->pending_interests);
            if (face->recvcount != 0)
                ndn_charbuf_putf(b, " <b>activity:</b> %d",
                                 face->recvcount);
            nodebuf->length = 0;
            port = ndn_charbuf_append_sockaddr(nodebuf, face->addr);
            if (port > 0) {
                const char *node = ndn_charbuf_as_string(nodebuf);
                int chk = NDN_FACE_MCAST | NDN_FACE_UNDECIDED |
                NDN_FACE_NOSEND | NDN_FACE_GG | NDN_FACE_PASSIVE;
                if ((face->flags & chk) == 0)
                    ndn_charbuf_putf(b,
                                     " <b>remote:</b> "
                                     "<a href='http://%s:%s/'>"
                                     "%s:%d</a>",
                                     node, NDN_DEFAULT_UNICAST_PORT,
                                     node, port);
                else if ((face->flags & NDN_FACE_PASSIVE) == 0)
                    ndn_charbuf_putf(b, " <b>remote:</b> %s:%d",
                                     node, port);
                else
                    ndn_charbuf_putf(b, " <b>local:</b> %s:%d",
                                     node, port);
                if (face->sendface != face->faceid &&
                    face->sendface != NDN_NOFACEID)
                    ndn_charbuf_putf(b, " <b>via:</b> %u", face->sendface);
            }
            ndn_charbuf_putf(b, "</li>" NL);
        }
    }
    ndn_charbuf_putf(b, "</ul>");
    ndn_charbuf_destroy(&nodebuf);
}

static void
collect_face_meter_html(struct ndnd_handle *h, struct ndn_charbuf *b)
{
    int i;
    ndn_charbuf_putf(b, "<h4>Face Activity Rates</h4>");
    ndn_charbuf_putf(b, "<table cellspacing='0' cellpadding='0' class='tbl' summary='face activity rates'>");
    ndn_charbuf_putf(b, "<tbody>" NL);
    ndn_charbuf_putf(b, " <tr><td>        </td>\t"
                        " <td>Bytes/sec In/Out</td>\t"
                        " <td>recv data/intr sent</td>\t"
                        " <td>sent data/intr recv</td></tr>" NL);
    for (i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL && (face->flags & (NDN_FACE_UNDECIDED|NDN_FACE_PASSIVE)) == 0) {
            ndn_charbuf_putf(b, " <tr>");
            ndn_charbuf_putf(b, "<td><b>face:</b> %u</td>\t",
                             face->faceid);
            ndn_charbuf_putf(b, "<td>%6u / %u</td>\t\t",
                                 ndnd_meter_rate(h, face->meter[FM_BYTI]),
                                 ndnd_meter_rate(h, face->meter[FM_BYTO]));
            ndn_charbuf_putf(b, "<td>%9u / %u</td>\t\t",
                                 ndnd_meter_rate(h, face->meter[FM_DATI]),
                                 ndnd_meter_rate(h, face->meter[FM_INTO]));
            ndn_charbuf_putf(b, "<td>%9u / %u</td>",
                                 ndnd_meter_rate(h, face->meter[FM_DATO]),
                                 ndnd_meter_rate(h, face->meter[FM_INTI]));
            ndn_charbuf_putf(b, "</tr>" NL);
        }
    }
    ndn_charbuf_putf(b, "</tbody>");
    ndn_charbuf_putf(b, "</table>");
}

static void
collect_forwarding_html(struct ndnd_handle *h, struct ndn_charbuf *b)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_forwarding *f;
    int res;
    struct ndn_charbuf *name = ndn_charbuf_create();
    
    ndn_charbuf_putf(b, "<h4>Forwarding</h4>" NL);
    ndn_charbuf_putf(b, "<ul>");
    hashtb_start(h->nameprefix_tab, e);
    for (; e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *ipe = e->data;
        ndn_name_init(name);
        res = ndn_name_append_components(name, e->key, 0, e->keysize);
        if (res < 0)
            abort();
        if (0) {
            ndn_charbuf_putf(b, " <li>");
            ndn_uri_append(b, name->buf, name->length, 1);
            ndn_charbuf_putf(b, "</li>" NL);
        }
        for (f = ipe->forwarding; f != NULL; f = f->next) {
            if ((f->flags & (NDN_FORW_ACTIVE | NDN_FORW_PFXO)) != 0) {
                ndn_name_init(name);
                ndn_name_append_components(name, e->key, 0, e->keysize);
                ndn_charbuf_putf(b, " <li>");
                ndn_uri_append(b, name->buf, name->length, 1);
                ndn_charbuf_putf(b,
                                 " <b>face:</b> %u"
                                 " <b>flags:</b> 0x%x"
                                 " <b>expires:</b> %d",
                                 f->faceid,
                                 f->flags & NDN_FORW_PUBMASK,
                                 f->expires);
                ndn_charbuf_putf(b, "</li>" NL);
            }
        }
    }
    hashtb_end(e);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_putf(b, "</ul>");
}

static unsigned
ndnd_colorhash(struct ndnd_handle *h)
{
    unsigned const char *a = h->ndnd_id;
    unsigned v;
    
    v = (a[0] << 16) + (a[1] << 8) + a[2];
    return (v | 0xC0C0C0);
}

static struct ndn_charbuf *
collect_stats_html(struct ndnd_handle *h)
{
    struct ndnd_stats stats = {0};
    struct ndn_charbuf *b = ndn_charbuf_create();
    int pid;
    struct utsname un;
    const char *portstr;
    
    portstr = getenv(NDN_LOCAL_PORT_ENVNAME);
    if (portstr == NULL || portstr[0] == 0 || strlen(portstr) > 10)
        portstr = NDN_DEFAULT_UNICAST_PORT;
    uname(&un);
    pid = getpid();
    
    ndnd_collect_stats(h, &stats);
    ndn_charbuf_putf(b,
        "<html xmlns='http://www.w3.org/1999/xhtml'>"
        "<head>"
        "<title>%s ndnd[%d]</title>"
        //"<meta http-equiv='refresh' content='3'>"
        "<style type='text/css'>"
        "/*<![CDATA[*/"
        "p.header {color: white; background-color: blue; width: 100%%} "
        "table.tbl {border-style: solid; border-width: 1.0px 1.0px 1.0px 1.0px; border-color: black} "
        "td {border-style: solid; "
            "border-width: 1.0px 1.0px 1.0px 1.0px; "
            "border-color: #808080 #808080 #808080 #808080; "
            "padding: 6px 6px 6px 6px; "
            "margin-left: auto; margin-right: auto; "
            "text-align: center"
            "} "
        "td.left {text-align: left} "
        "/*]]>*/"
        "</style>"
        "</head>" NL
        "<body bgcolor='#%06X'>"
        "<p class='header'>%s ndnd[%d] local port %s api %d start %ld.%06u now %ld.%06u</p>" NL
        "<div><b>Content items:</b> %llu accessioned,"
        " %d stored, %lu stale, %d sparse, %lu duplicate, %lu sent</div>" NL
        "<div><b>Interests:</b> %d names,"
        " %ld pending, %d propagating, %d noted</div>" NL
        "<div><b>Interest totals:</b> %lu accepted,"
        " %lu dropped, %lu sent, %lu stuffed</div>" NL,
        un.nodename,
        pid,
        ndnd_colorhash(h),
        un.nodename,
        pid,
        portstr,
        (int)NDN_API_VERSION,
        h->starttime, h->starttime_usec,
        h->sec,
        h->usec,
        (unsigned long long)h->accession,
        hashtb_n(h->content_tab),
        h->n_stale,
        hashtb_n(h->sparse_straggler_tab),
        h->content_dups_recvd,
        h->content_items_sent,
        hashtb_n(h->nameprefix_tab), stats.total_interest_counts,
        hashtb_n(h->interest_tab),
        hashtb_n(h->nonce_tab),
        h->interests_accepted, h->interests_dropped,
        h->interests_sent, h->interests_stuffed);
    if (0)
        ndn_charbuf_putf(b,
                         "<div><b>Active faces and listeners:</b> %d</div>" NL,
                         hashtb_n(h->faces_by_fd) + hashtb_n(h->dgram_faces));
    collect_faces_html(h, b);
    collect_face_meter_html(h, b);
    collect_forwarding_html(h, b);
    ndn_charbuf_putf(b,
        "</body>"
        "</html>" NL);
    return(b);
}

/* XML formatting */

static void
collect_meter_xml(struct ndnd_handle *h, struct ndn_charbuf *b, struct ndnd_meter *m)
{
    uintmax_t total;
    unsigned rate;
    
    if (m == NULL)
        return;
    total = ndnd_meter_total(m);
    rate = ndnd_meter_rate(h, m);
    ndn_charbuf_putf(b, "<%s><total>%ju</total><persec>%u</persec></%s>",
        m->what, total, rate, m->what);
}

static void
collect_faces_xml(struct ndnd_handle *h, struct ndn_charbuf *b)
{
    int i;
    int m;
    int port;
    struct ndn_charbuf *nodebuf;
    
    nodebuf = ndn_charbuf_create();
    ndn_charbuf_putf(b, "<faces>");
    for (i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL && (face->flags & NDN_FACE_UNDECIDED) == 0) {
            ndn_charbuf_putf(b, "<face>");
            ndn_charbuf_putf(b,
                             "<faceid>%u</faceid>"
                             "<faceflags>%04x</faceflags>",
                             face->faceid, face->flags);
            ndn_charbuf_putf(b, "<pending>%d</pending>",
                             face->pending_interests);
            ndn_charbuf_putf(b, "<recvcount>%d</recvcount>",
                             face->recvcount);
            nodebuf->length = 0;
            port = ndn_charbuf_append_sockaddr(nodebuf, face->addr);
            if (port > 0) {
                const char *node = ndn_charbuf_as_string(nodebuf);
                ndn_charbuf_putf(b, "<ip>%s:%d</ip>", node, port);
            }
            if (face->sendface != face->faceid &&
                face->sendface != NDN_NOFACEID)
                ndn_charbuf_putf(b, "<via>%u</via>", face->sendface);
            if (face != NULL && (face->flags & NDN_FACE_PASSIVE) == 0) {
                ndn_charbuf_putf(b, "<meters>");
                for (m = 0; m < NDND_FACE_METER_N; m++)
                    collect_meter_xml(h, b, face->meter[m]);
                ndn_charbuf_putf(b, "</meters>");
            }
            ndn_charbuf_putf(b, "</face>" NL);
        }
    }
    ndn_charbuf_putf(b, "</faces>");
    ndn_charbuf_destroy(&nodebuf);
}

static void
collect_forwarding_xml(struct ndnd_handle *h, struct ndn_charbuf *b)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_forwarding *f;
    int res;
    struct ndn_charbuf *name = ndn_charbuf_create();
    
    ndn_charbuf_putf(b, "<forwarding>");
    hashtb_start(h->nameprefix_tab, e);
    for (; e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *ipe = e->data;
        for (f = ipe->forwarding, res = 0; f != NULL && !res; f = f->next) {
            if ((f->flags & (NDN_FORW_ACTIVE | NDN_FORW_PFXO)) != 0)
                res = 1;
        }
        if (res) {
            ndn_name_init(name);
            ndn_name_append_components(name, e->key, 0, e->keysize);
            ndn_charbuf_putf(b, "<fentry>");
            ndn_charbuf_putf(b, "<prefix>");
            ndn_uri_append(b, name->buf, name->length, 1);
            ndn_charbuf_putf(b, "</prefix>");
            for (f = ipe->forwarding; f != NULL; f = f->next) {
                if ((f->flags & (NDN_FORW_ACTIVE | NDN_FORW_PFXO)) != 0) {
                    ndn_charbuf_putf(b,
                                     "<dest>"
                                     "<faceid>%u</faceid>"
                                     "<flags>%x</flags>"
                                     "<expires>%d</expires>"
                                     "</dest>",
                                     f->faceid,
                                     f->flags & NDN_FORW_PUBMASK,
                                     f->expires);
                }
            }
            ndn_charbuf_putf(b, "</fentry>");
        }
    }
    hashtb_end(e);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_putf(b, "</forwarding>");
}

static struct ndn_charbuf *
collect_stats_xml(struct ndnd_handle *h)
{
    struct ndnd_stats stats = {0};
    struct ndn_charbuf *b = ndn_charbuf_create();
    int i;
        
    ndnd_collect_stats(h, &stats);
    ndn_charbuf_putf(b,
        "<ndnd>"
        "<identity>"
        "<ndndid>");
    for (i = 0; i < sizeof(h->ndnd_id); i++)
        ndn_charbuf_putf(b, "%02X", h->ndnd_id[i]);
    ndn_charbuf_putf(b, "</ndndid>"
        "<apiversion>%d</apiversion>"
        "<starttime>%ld.%06u</starttime>"
        "<now>%ld.%06u</now>"
        "</identity>",
        (int)NDN_API_VERSION,
        h->starttime, h->starttime_usec,
        h->sec,
        h->usec);
    ndn_charbuf_putf(b,
        "<cobs>"
        "<accessioned>%llu</accessioned>"
        "<stored>%d</stored>"
        "<stale>%lu</stale>"
        "<sparse>%d</sparse>"
        "<duplicate>%lu</duplicate>"
        "<sent>%lu</sent>"
        "</cobs>"
        "<interests>"
        "<names>%d</names>"
        "<pending>%ld</pending>"
        "<propagating>%d</propagating>"
        "<noted>%d</noted>"
        "<accepted>%lu</accepted>"
        "<dropped>%lu</dropped>"
        "<sent>%lu</sent>"
        "<stuffed>%lu</stuffed>"
        "</interests>",
        (unsigned long long)h->accession,
        hashtb_n(h->content_tab),
        h->n_stale,
        hashtb_n(h->sparse_straggler_tab),
        h->content_dups_recvd,
        h->content_items_sent,
        hashtb_n(h->nameprefix_tab), stats.total_interest_counts,
        hashtb_n(h->interest_tab),
        hashtb_n(h->nonce_tab),
        h->interests_accepted, h->interests_dropped,
        h->interests_sent, h->interests_stuffed);
    collect_faces_xml(h, b);
    collect_forwarding_xml(h, b);
    ndn_charbuf_putf(b, "</ndnd>" NL);
    return(b);
}

/**
 * create and initialize separately allocated meter.
 */
struct ndnd_meter *
ndnd_meter_create(struct ndnd_handle *h, const char *what)
{
    struct ndnd_meter *m;
    m = calloc(1, sizeof(*m));
    if (m == NULL)
        return(NULL);
    ndnd_meter_init(h, m, what);
    return(m);
}

/**
 * Destroy a separately allocated meter.
 */
void
ndnd_meter_destroy(struct ndnd_meter **pm)
{
    if (*pm != NULL) {
        free(*pm);
        *pm = NULL;
    }
}

/**
 * Initialize a meter.
 */
void
ndnd_meter_init(struct ndnd_handle *h, struct ndnd_meter *m, const char *what)
{
    if (m == NULL)
        return;
    memset(m, 0, sizeof(*m));
    if (what != NULL)
        strncpy(m->what, what, sizeof(m->what)-1);
    ndnd_meter_bump(h, m, 0);
}

static const unsigned meterHz = 7; /* 1/ln(8/7) would give RC const of 1 sec */

/**
 * Count something (messages, packets, bytes), and roll up some kind of
 * statistics on it.
 */
void
ndnd_meter_bump(struct ndnd_handle *h, struct ndnd_meter *m, unsigned amt)
{
    unsigned now; /* my ticks, wrap OK */
    unsigned t;
    unsigned r;
    if (m == NULL)
        return;
    now = (((unsigned)(h->sec)) * meterHz) + (h->usec * meterHz / 1000000U);
    t = m->lastupdate;
    m->total += amt;
    if (now - t > 166U)
        m->rate = amt; /* history has decayed away */
    else {
        /* Decay the old rate exponentially based on time since last sample. */
        for (r = m->rate; t != now && r != 0; t++)
            r = r - ((r + 7U) / 8U); /* multiply by 7/8, truncating */
        m->rate = r + amt;
    }
    m->lastupdate = now;
}

/**
 * Return the average rate (units per second) of a metered quantity.
 *
 * m may be NULL.
 */
unsigned
ndnd_meter_rate(struct ndnd_handle *h, struct ndnd_meter *m)
{
    unsigned denom = 8;
    if (m == NULL)
        return(0);
    ndnd_meter_bump(h, m, 0);
    if (m->rate > 0x0FFFFFFF)
        return(m->rate / denom * meterHz);
    return ((m->rate * meterHz + (denom - 1)) / denom);
}

/**
 * Return the grand total for a metered quantity.
 *
 * m may be NULL.
 */
uintmax_t
ndnd_meter_total(struct ndnd_meter *m)
{
    if (m == NULL)
        return(0);
    return (m->total);
}
