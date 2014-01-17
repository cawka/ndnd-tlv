/**
 * @file ndn_client.c
 * @brief Support for ndn clients.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2013 Palo Alto Research Center, Inc.
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/evp.h>

#include <ndn-tlv/ndn.h>
#include <ndn-tlv/ndn_private.h>
#include <ndn-tlv/ndnd.h>
#include <ndn-tlv/charbuf.h>
#include <ndn-tlv/coding.h>
#include <ndn-tlv/digest.h>
#include <ndn-tlv/hashtb.h>
#include <ndn-tlv/reg_mgmt.h>
#include <ndn-tlv/schedule.h>
#include <ndn-tlv/signing.h>
#include <ndn-tlv/keystore.h>
#include <ndn-tlv/uri.h>

/* Forward struct declarations */
struct interests_by_prefix;
struct expressed_interest;
struct interest_filter;
struct ndn_reg_closure;

/**
 * Handle representing a connection to ndnd
 */
struct ndn {
    int sock;
    size_t outbufindex;
    struct ndn_charbuf *connect_type;   /* text representing connection to ndnd */
    struct ndn_charbuf *interestbuf;
    struct ndn_charbuf *inbuf;
    struct ndn_charbuf *outbuf;
    struct ndn_charbuf *ndndid;
    struct hashtb *interests_by_prefix;
    struct hashtb *interest_filters;
    struct ndn_skeleton_decoder decoder;
    struct ndn_indexbuf *scratch_indexbuf;
    struct hashtb *keys;    /* public keys, by pubid */
    struct hashtb *keystores;   /* unlocked private keys */
    struct ndn_charbuf *default_pubid;
    struct ndn_schedule *schedule;
    struct timeval now;
    int timeout;
    int refresh_us;
    int err;                    /* pos => errno value, neg => other */
    int errline;
    int verbose_error;
    int tap;
    int running;
    int defer_verification;     /* Client wants to do its own verification */
};

struct interests_by_prefix { /* keyed by components of name prefix */
    struct expressed_interest *list;
};

struct expressed_interest {
    int magic;                   /* for sanity checking */
    struct timeval lasttime;     /* time most recently expressed */
    struct ndn_closure *action;  /* handler for incoming content */
    unsigned char *interest_msg; /* the interest message as sent */
    size_t size;                 /* its size in bytes */
    int target;                  /* how many we want outstanding (0 or 1) */
    int outstanding;             /* number currently outstanding (0 or 1) */
    int lifetime_us;             /* interest lifetime in microseconds */
    struct ndn_charbuf *wanted_pub; /* waiting for this pub to arrive */
    struct expressed_interest *next; /* link to next in list */
};

/**
 * Data field for entries in the interest_filters hash table
 */
struct interest_filter { /* keyed by components of name */
    struct ndn_closure *action;
    struct ndn_reg_closure *ndn_reg_closure;
    struct timeval expiry;       /* Time that refresh will be needed */
    int flags;
};
#define NDN_FORW_WAITING_NDNDID (1<<30)

struct ndn_reg_closure {
    struct ndn_closure action;
    struct interest_filter *interest_filter; /* Backlink */
};

/* Macros */

#define NOTE_ERR(h, e) (h->err = (e), h->errline = __LINE__, ndn_note_err(h))
#define NOTE_ERRNO(h) NOTE_ERR(h, errno)

#define THIS_CANNOT_HAPPEN(h) \
    do { NOTE_ERR(h, -73); ndn_perror(h, "Can't happen");} while (0)

#define XXX \
    do { NOTE_ERR(h, -76); ndn_perror(h, "Please write some more code here"); } while (0)

/* Prototypes */

static void ndn_refresh_interest(struct ndn *, struct expressed_interest *);
static void ndn_initiate_prefix_reg(struct ndn *,
                                    const void *, size_t,
                                    struct interest_filter *);
static void finalize_pkey(struct hashtb_enumerator *e);
static void finalize_keystore(struct hashtb_enumerator *e);
static int ndn_pushout(struct ndn *h);
static void update_ifilt_flags(struct ndn *, struct interest_filter *, int);
static int update_multifilt(struct ndn *,
                            struct interest_filter *,
                            struct ndn_closure *,
                            int);
/**
 * Compare two timvals
 */
static int
tv_earlier(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec > b->tv_sec)
        return(0);
    if (a->tv_sec < b->tv_sec)
        return(1);
    return(a->tv_usec < b->tv_usec);
}

/**
 * Produce message on standard error output describing the last
 * error encountered during a call using the given handle.
 * @param h is the ndn handle - may not be NULL.
 * @param s is a client-supplied message; if NULL a message will be supplied
 *        where available.
 */
void
ndn_perror(struct ndn *h, const char *s)
{
    const char *dlm = ": ";
    if (s == NULL) {
        if (h->err > 0)
            s = strerror(h->err);
        else
            dlm = s = "";
    }
    // XXX - time stamp
    fprintf(stderr, "ndn_client.c:%d[%d] - error %d%s%s\n",
                        h->errline, (int)getpid(), h->err, dlm, s);
}

static int
ndn_note_err(struct ndn *h)
{
    if (h->verbose_error)
        ndn_perror(h, NULL);
    return(-1);
}

/**
 * Set the error code in a ndn handle.
 * @param h is the ndn handle - may be NULL.
 * @param error_code is the code to set.
 * @returns -1 in all cases.
 */
int
ndn_seterror(struct ndn *h, int error_code)
{
    if (h == NULL)
        return(-1);
    h->err = error_code;
    h->errline = 0;
    if (error_code != 0)
        ndn_note_err(h);
    return(-1);
}

/**
 * Recover last error code.
 * @param h is the ndn handle - may be NULL.
 * @returns the most recently set error code, or 0 if h is NULL.
 */
int
ndn_geterror(struct ndn *h)
{
    if (h == NULL)
        return(0);
    return(h->err);
}

static struct ndn_indexbuf *
ndn_indexbuf_obtain(struct ndn *h)
{
    struct ndn_indexbuf *c = h->scratch_indexbuf;
    if (c == NULL)
        return(ndn_indexbuf_create());
    h->scratch_indexbuf = NULL;
    c->n = 0;
    return(c);
}

static void
ndn_indexbuf_release(struct ndn *h, struct ndn_indexbuf *c)
{
    c->n = 0;
    if (h->scratch_indexbuf == NULL)
        h->scratch_indexbuf = c;
    else
        ndn_indexbuf_destroy(&c);
}

/**
 * Do the refcount updating for closure instances on assignment
 *
 * When the refcount drops to 0, the closure is told to finalize itself.
 */
static void
ndn_replace_handler(struct ndn *h,
                    struct ndn_closure **dstp,
                    struct ndn_closure *src)
{
    struct ndn_closure *old = *dstp;
    if (src == old)
        return;
    if (src != NULL)
        src->refcount++;
    *dstp = src;
    if (old != NULL && (--(old->refcount)) == 0) {
        struct ndn_upcall_info info = { 0 };
        info.h = h;
        (old->p)(old, NDN_UPCALL_FINAL, &info);
    }
}

/**
 * Create a client handle.
 * The new handle is not yet connected.
 * On error, returns NULL and sets errno.
 * Errors: ENOMEM
 */
struct ndn *
ndn_create(void)
{
    struct ndn *h;
    const char *s;
    struct hashtb_param param = {0};

    h = calloc(1, sizeof(*h));
    if (h == NULL)
        return(h);
    param.finalize_data = h;
    h->sock = -1;
    h->interestbuf = ndn_charbuf_create();
    param.finalize = &finalize_pkey;
    h->keys = hashtb_create(sizeof(struct ndn_pkey *), &param);
    param.finalize = &finalize_keystore;
    h->keystores = hashtb_create(sizeof(struct ndn_keystore *), &param);
    s = getenv("NDN_DEBUG");
    h->verbose_error = (s != NULL && s[0] != 0);
    s = getenv("NDN_TAP");
    if (s != NULL && s[0] != 0) {
    char tap_name[255];
    struct timeval tv;
    gettimeofday(&tv, NULL);
        if (snprintf(tap_name, 255, "%s-%d-%d-%d", s, (int)getpid(),
                     (int)tv.tv_sec, (int)tv.tv_usec) >= 255) {
            fprintf(stderr, "NDN_TAP path is too long: %s\n", s);
        } else {
            h->tap = open(tap_name, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU);
            if (h->tap == -1) {
                NOTE_ERRNO(h);
                ndn_perror(h, "Unable to open NDN_TAP file");
            }
            else
                fprintf(stderr, "NDN_TAP writing to %s\n", tap_name);
        }
    } else
        h->tap = -1;
    h->defer_verification = 0;
    OpenSSL_add_all_algorithms();
    return(h);
}

/**
 * Tell the library to defer verification.
 *
 * For some specialized applications (performance testing being an example),
 * the normal verification done within the library may be undesirable.
 * Setting the "defer validation" flag will cause the library to pass content
 * to the application without attempting to verify it. In this case,
 * the NDN_UPCALL_CONTENT_RAW upcall kind will be passed instead of
 * NDN_UPCALL_CONTENT, and NDN_UPCALL_CONTENT_KEYMISSING instead of
 * NDN_UPCALL_CONTENT_UNVERIFIED.  If the application wants do still do
 * key fetches, it may use the NDN_UPCALL_RESULT_FETCHKEY response instead
 * of NDN_UPCALL_RESULT_VERIFY.
 *
 * Calling this while there are interests outstanding is not recommended.
 *
 * This call is available beginning with NDN_API_VERSION 4004.
 *
 * @param h is the ndn handle
 * @param defer is 0 to verify, 1 to defer, -1 to leave unchanged.
 * @returns previous value, or -1 in case of error.
 */
int
ndn_defer_verification(struct ndn *h, int defer)
{
    int old;

    if (h == NULL || defer > 1 || defer < -1)
        return(-1);
    old = h->defer_verification;
    if (defer >= 0)
        h->defer_verification = defer;
    return(old);
}

/**
 * Connect to local ndnd.
 * @param h is a ndn library handle
 * @param name is the name of the unix-domain socket to connect to,
 *      or the string "tcp[4|6][:port]" to indicate a TCP connection
 *      using either IPv4 (default) or IPv6 on the optional port;
 *      use NULL to get the default, which is affected by the
 *      environment variables NDN_LOCAL_TRANSPORT, interpreted as is name,
 *      and NDN_LOCAL_PORT if there is no port specified,
 *      or NDN_LOCAL_SOCKNAME and NDN_LOCAL_PORT.
 * @returns the fd for the connection, or -1 for error.
 */
int
ndn_connect(struct ndn *h, const char *name)
{
    struct sockaddr_storage sockaddr = {0};
    struct sockaddr_un *un_addr = (struct sockaddr_un *)&sockaddr;
    struct sockaddr_in *in_addr = (struct sockaddr_in *)&sockaddr;
    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)&sockaddr;
    struct sockaddr *addr = (struct sockaddr *)&sockaddr;
    int addr_size;
    int res;
#ifndef NDN_LOCAL_TCP
    const char *s;
#endif
    if (h == NULL)
        return(-1);
    h->err = 0;
    if (h->sock != -1)
        return(NOTE_ERR(h, EINVAL));
#ifdef NDN_LOCAL_TCP
    res = ndn_setup_sockaddr_in("tcp", addr, sizeof(sockaddr));
#else
    if (name != NULL && name[0] != 0) {
        if (strncasecmp(name, "tcp", 3) == 0) {
            res = ndn_setup_sockaddr_in(name, addr, sizeof(sockaddr));
            if (res == -1)
                return(NOTE_ERR(h, EINVAL));
        } else {
            un_addr->sun_family = AF_UNIX;
            strncpy(un_addr->sun_path, name, sizeof(un_addr->sun_path));
        }
        ndn_set_connect_type(h, name);
    } else {
        s = getenv("NDN_LOCAL_TRANSPORT");
        if (s != NULL && strncasecmp(s, "tcp", 3) == 0) {
            res = ndn_setup_sockaddr_in(s, addr, sizeof(sockaddr));
            if (res == -1)
                return(NOTE_ERR(h, EINVAL));
            ndn_set_connect_type(h, s);
        } else if (s == NULL || strcasecmp(s, "unix")) {
            ndn_setup_sockaddr_un(NULL, un_addr);
            ndn_set_connect_type(h, un_addr->sun_path);
        } else {
            return(NOTE_ERR(h, EINVAL));
        }
    }
#endif
    h->sock = socket(sockaddr.ss_family, SOCK_STREAM, 0);
    if (h->sock == -1)
        return(NOTE_ERRNO(h));
    switch (sockaddr.ss_family) {
        case AF_UNIX: addr_size = sizeof(*un_addr); break;
        case AF_INET: addr_size = sizeof(*in_addr); break;
        case AF_INET6: addr_size = sizeof(*in6_addr); break;
        default: addr_size = 0;
    }
    res = connect(h->sock, addr, addr_size);
    if (res == -1)
        return(NOTE_ERRNO(h));
    res = fcntl(h->sock, F_SETFL, O_NONBLOCK);
    if (res == -1)
        return(NOTE_ERRNO(h));
    return(h->sock);
}

int
ndn_get_connection_fd(struct ndn *h)
{
    return(h->sock);
}


void
ndn_set_connect_type(struct ndn *h, const char *name)
{
    if (h->connect_type == NULL) {
        h->connect_type = ndn_charbuf_create();
    } else {
        ndn_charbuf_reset(h->connect_type);
    }
    ndn_charbuf_append_string(h->connect_type, name);
}

const char *
ndn_get_connect_type(struct ndn *h)
{
    if (h->connect_type == NULL || h->connect_type->length == 0)
        return (NULL);
    return (ndn_charbuf_as_string(h->connect_type));
}

int
ndn_disconnect(struct ndn *h)
{
    int res;
    res = ndn_pushout(h);
    if (res == 1) {
        res = fcntl(h->sock, F_SETFL, 0); /* clear O_NONBLOCK */
        if (res == 0)
            ndn_pushout(h);
    }
    ndn_charbuf_destroy(&h->inbuf);
    ndn_charbuf_destroy(&h->outbuf);
    /* a stored ndndid may no longer be valid */
    ndn_charbuf_destroy(&h->ndndid);
    /* all interest filters expire */
    if (h->interest_filters != NULL) {
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;
        for (hashtb_start(h->interest_filters, e); e->data != NULL; hashtb_next(e)) {
            struct interest_filter *i = e->data;
            i->expiry = h->now;
        }
        hashtb_end(e);
    }
    /* all pending interests are no longer outstanding */
    if (h->interests_by_prefix != NULL) {
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;
        for (hashtb_start(h->interests_by_prefix, e); e->data != NULL; hashtb_next(e)) {
            struct interests_by_prefix *entry = e->data;
            if (entry->list != NULL) {
                struct expressed_interest *ie;
                for (ie = entry->list; ie != NULL; ie = ie->next) {
                    ie->outstanding = 0;                
                }
            }
        }
        hashtb_end(e);
    }

    res = close(h->sock);
    h->sock = -1;
    if (res == -1)
        return(NOTE_ERRNO(h));
    return(0);
}

static void
ndn_gripe(struct expressed_interest *i)
{
    fprintf(stderr, "BOTCH - (struct expressed_interest *)%p has bad magic value\n", (void *)i);
}

static void
replace_interest_msg(struct expressed_interest *interest,
                     struct ndn_charbuf *cb)
{
    if (interest->magic != 0x7059e5f4) {
        ndn_gripe(interest);
        return;
    }
    if (interest->interest_msg != NULL)
        free(interest->interest_msg);
    interest->interest_msg = NULL;
    interest->size = 0;
    if (cb != NULL && cb->length > 0) {
        interest->interest_msg = calloc(1, cb->length);
        if (interest->interest_msg != NULL) {
            memcpy(interest->interest_msg, cb->buf, cb->length);
            interest->size = cb->length;
        }
    }
}

static struct expressed_interest *
ndn_destroy_interest(struct ndn *h, struct expressed_interest *i)
{
    struct expressed_interest *ans = i->next;
    if (i->magic != 0x7059e5f4) {
        ndn_gripe(i);
        return(NULL);
    }
    ndn_replace_handler(h, &(i->action), NULL);
    replace_interest_msg(i, NULL);
    ndn_charbuf_destroy(&i->wanted_pub);
    i->magic = -1;
    free(i);
    return(ans);
}

void
ndn_check_interests(struct expressed_interest *list)
{
    struct expressed_interest *ie;
    for (ie = list; ie != NULL; ie = ie->next) {
        if (ie->magic != 0x7059e5f4) {
            ndn_gripe(ie);
            abort();
        }
    }
}

void
ndn_clean_interests_by_prefix(struct ndn *h, struct interests_by_prefix *entry)
{
    struct expressed_interest *ie;
    struct expressed_interest *next;
    struct expressed_interest **ip;
    ndn_check_interests(entry->list);
    ip = &(entry->list);
    for (ie = entry->list; ie != NULL; ie = next) {
        next = ie->next;
        if (ie->action == NULL)
            ndn_destroy_interest(h, ie);
        else {
            (*ip) = ie;
            ip = &(ie->next);
        }
    }
    (*ip) = NULL;
    ndn_check_interests(entry->list);
}

void
ndn_destroy(struct ndn **hp)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn *h = *hp;
    if (h == NULL)
        return;
    ndn_schedule_destroy(&h->schedule);
    ndn_disconnect(h);
    if (h->interests_by_prefix != NULL) {
        for (hashtb_start(h->interests_by_prefix, e); e->data != NULL; hashtb_next(e)) {
            struct interests_by_prefix *entry = e->data;
            while (entry->list != NULL)
                entry->list = ndn_destroy_interest(h, entry->list);
        }
        hashtb_end(e);
        hashtb_destroy(&(h->interests_by_prefix));
    }
    if (h->interest_filters != NULL) {
        for (hashtb_start(h->interest_filters, e); e->data != NULL; hashtb_next(e)) {
            struct interest_filter *i = e->data;
            ndn_replace_handler(h, &(i->action), NULL);
        }
        hashtb_end(e);
        hashtb_destroy(&(h->interest_filters));
    }
    hashtb_destroy(&(h->keys));
    hashtb_destroy(&(h->keystores));
    ndn_charbuf_destroy(&h->interestbuf);
    ndn_charbuf_destroy(&h->inbuf);
    ndn_charbuf_destroy(&h->outbuf);
    ndn_indexbuf_destroy(&h->scratch_indexbuf);
    ndn_charbuf_destroy(&h->default_pubid);
    ndn_charbuf_destroy(&h->ndndid);
    ndn_charbuf_destroy(&h->connect_type);
    if (h->tap != -1)
        close(h->tap);
    free(h);
    *hp = NULL;
}

/*
 * ndn_check_namebuf: check that name is valid
 * Returns the byte offset of the end of prefix portion,
 * as given by prefix_comps, or -1 for error.
 * prefix_comps = -1 means the whole name is the prefix.
 * If omit_possible_digest, chops off a potential digest name at the end
 */
static int
ndn_check_namebuf(struct ndn *h, struct ndn_charbuf *namebuf, int prefix_comps,
                  int omit_possible_digest)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    int i = 0;
    int ans = 0;
    int prev_ans = 0;
    if (namebuf == NULL || namebuf->length < 2)
        return(-1);
    d = ndn_buf_decoder_start(&decoder, namebuf->buf, namebuf->length);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        ndn_buf_advance(d);
        prev_ans = ans = d->decoder.token_index;
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, NULL, NULL)) {
                ndn_buf_advance(d);
            }
            ndn_buf_check_close(d);
            i += 1;
            if (prefix_comps < 0 || i <= prefix_comps) {
                prev_ans = ans;
                ans = d->decoder.token_index;
            }
        }
        ndn_buf_check_close(d);
    }
    if (d->decoder.state < 0 || ans < prefix_comps)
        return(-1);
    if (omit_possible_digest && ans == prev_ans + 36 && ans == namebuf->length - 1)
        return(prev_ans);
    return(ans);
}

static void
ndn_construct_interest(struct ndn *h,
                       struct ndn_charbuf *name_prefix,
                       struct ndn_charbuf *interest_template,
                       struct expressed_interest *dest)
{
    struct ndn_charbuf *c = h->interestbuf;
    size_t start;
    size_t size;
    int res;

    dest->lifetime_us = NDN_INTEREST_LIFETIME_MICROSEC;
    c->length = 0;
    ndn_charbuf_append_tt(c, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append(c, name_prefix->buf, name_prefix->length);
    res = 0;
    if (interest_template != NULL) {
        struct ndn_parsed_interest pi = { 0 };
        res = ndn_parse_interest(interest_template->buf,
                                 interest_template->length, &pi, NULL);
        if (res >= 0) {
            intmax_t lifetime = ndn_interest_lifetime(interest_template->buf, &pi);
            // XXX - for now, don't try to handle lifetimes over 30 seconds.
            if (lifetime < 1 || lifetime > (30 << 12))
                NOTE_ERR(h, EINVAL);
            else
                dest->lifetime_us = (lifetime * 1000000) >> 12;
            start = pi.offset[NDN_PI_E_Name];
            size = pi.offset[NDN_PI_B_Nonce] - start;
            ndn_charbuf_append(c, interest_template->buf + start, size);
            start = pi.offset[NDN_PI_B_OTHER];
            size = pi.offset[NDN_PI_E_OTHER] - start;
            if (size != 0)
                ndn_charbuf_append(c, interest_template->buf + start, size);
        }
        else
            NOTE_ERR(h, EINVAL);
    }
    ndn_charbuf_append_closer(c);
    replace_interest_msg(dest, (res >= 0 ? c : NULL));
}

int
ndn_express_interest(struct ndn *h,
                     struct ndn_charbuf *namebuf,
                     struct ndn_closure *action,
                     struct ndn_charbuf *interest_template)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int res;
    int prefixend;
    struct expressed_interest *interest = NULL;
    struct interests_by_prefix *entry = NULL;
    if (h->interests_by_prefix == NULL) {
        h->interests_by_prefix = hashtb_create(sizeof(struct interests_by_prefix), NULL);
        if (h->interests_by_prefix == NULL)
            return(NOTE_ERRNO(h));
    }
    prefixend = ndn_check_namebuf(h, namebuf, -1, 1);
    if (prefixend < 0)
        return(prefixend);
    /*
     * To make it easy to lookup prefixes of names, we keep only
     * the prefix name components as the key in the hash table.
     */
    hashtb_start(h->interests_by_prefix, e);
    res = hashtb_seek(e, namebuf->buf + 1, prefixend - 1, 0);
    entry = e->data;
    if (entry == NULL) {
        NOTE_ERRNO(h);
        hashtb_end(e);
        return(res);
    }
    if (res == HT_NEW_ENTRY)
        entry->list = NULL;
    interest = calloc(1, sizeof(*interest));
    if (interest == NULL) {
        NOTE_ERRNO(h);
        hashtb_end(e);
        return(-1);
    }
    interest->magic = 0x7059e5f4;
    ndn_construct_interest(h, namebuf, interest_template, interest);
    if (interest->interest_msg == NULL) {
        free(interest);
        hashtb_end(e);
        return(-1);
    }
    ndn_replace_handler(h, &(interest->action), action);
    interest->target = 1;
    interest->next = entry->list;
    entry->list = interest;
    hashtb_end(e);
    /* Actually send the interest out right away */
    ndn_refresh_interest(h, interest);
    return(0);
}

static void
finalize_interest_filter(struct hashtb_enumerator *e)
{
    struct interest_filter *i = e->data;
    if (i->ndn_reg_closure != NULL) {
        i->ndn_reg_closure->interest_filter = NULL;
        i->ndn_reg_closure = NULL;
    }
}

/**
 * Register to receive interests on a prefix, with forwarding flags
 *
 * See ndn_set_interest_filter for a description of the basic operation.
 *
 * The additional forw_flags argument offers finer control of which
 * interests are forward to the application.
 * Refer to doc/technical/Registration for details.
 *
 * There may be multiple actions associated with the prefix.  They will be
 * called in an unspecified order.  The flags passed to ndnd will be
 * the inclusive-or of the flags associated with each action.
 *
 * Passing a value of 0 for forw_flags will unregister just this specific action,
 * leaving other actions untouched.
 *
 * @returns -1 in case of error, non-negative for success.
 */
int
ndn_set_interest_filter_with_flags(struct ndn *h, struct ndn_charbuf *namebuf,
                        struct ndn_closure *action, int forw_flags)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int res;
    struct interest_filter *entry;

    if (h->interest_filters == NULL) {
        struct hashtb_param param = {0};
        param.finalize = &finalize_interest_filter;
        h->interest_filters = hashtb_create(sizeof(struct interest_filter), &param);
        if (h->interest_filters == NULL)
            return(NOTE_ERRNO(h));
    }
    res = ndn_check_namebuf(h, namebuf, -1, 0);
    if (res < 0)
        return(res);
    hashtb_start(h->interest_filters, e);
    res = hashtb_seek(e, namebuf->buf + 1, namebuf->length - 2, 0);
    if (res >= 0) {
        entry = e->data;
        if (entry->action != NULL && action != NULL && action != entry->action)
            res = update_multifilt(h, entry, action, forw_flags);
        else {
            update_ifilt_flags(h, entry, forw_flags);
            ndn_replace_handler(h, &(entry->action), action);
        }
        if (entry->action == NULL)
            hashtb_delete(e);
    }
    hashtb_end(e);
    return(res);
}

/**
 * Register to receive interests on a prefix
 *
 * The action will be called upon the arrival of an interest that
 * has the given name as a prefix.
 *
 * If action is NULL, any existing filter for the prefix is removed.
 * Note that this may have undesirable effects in applications that share
 * the same handle for independently operating subcomponents.
 * See ndn_set_interest_filter_with_flags() for a way to deal with this.
 *
 * The contents of namebuf are copied as needed.
 *
 * The handler should return NDN_UPCALL_RESULT_INTEREST_CONSUMED as a
 * promise that it has produced, or will soon produce, a matching content
 * object.
 *
 * The upcall kind passed to the handler will be NDN_UPCALL_INTEREST
 * if no other handler has claimed to produce content, or else
 * NDN_UPCALL_CONSUMED_INTEREST.
 *
 * This call is equivalent to a call to ndn_set_interest_filter_with_flags,
 * passing the forwarding flags (NDN_FORW_ACTIVE | NDN_FORW_CHILD_INHERIT).
 *
 * @returns -1 in case of error, non-negative for success.
 */
int
ndn_set_interest_filter(struct ndn *h, struct ndn_charbuf *namebuf,
                        struct ndn_closure *action)
{
    int forw_flags = NDN_FORW_ACTIVE | NDN_FORW_CHILD_INHERIT;
    return(ndn_set_interest_filter_with_flags(h, namebuf, action, forw_flags));
}

/**
 * Change forwarding flags, triggering a refresh as needed.
 */
static void
update_ifilt_flags(struct ndn *h, struct interest_filter *f, int forw_flags)
{
    if (f->flags != forw_flags) {
        memset(&f->expiry, 0, sizeof(f->expiry));
        f->flags = forw_flags;
    }
}

/* * * multifilt * * */

/**
 * Item in the array of interest filters associated with one prefix
 */
struct multifilt_item {
    struct ndn_closure *action;
    int forw_flags;
};

/**
 * Data for the multifilt case
 *
 * This wraps multiple interest filters up as a single one, so they
 * can share the single slot in a struct interest_filter.
 */
struct multifilt {
    struct ndn_closure me;
    int n;                      /**< Number of elements in a */
    struct multifilt_item *a;   /**< The filters that are to be combined */
};

/* Prototypes */
static enum ndn_upcall_res handle_multifilt(struct ndn_closure *selfp,
                                            enum ndn_upcall_kind kind,
                                            struct ndn_upcall_info *info);
static int build_multifilt_array(struct ndn *h,
                                 struct multifilt_item **ap,
                                 int n,
                                 struct ndn_closure *action,
                                 int forw_flags);
static void destroy_multifilt_array(struct ndn *h,
                                    struct multifilt_item **ap,
                                    int n);

/**
 * Take care of the case of multiple filters registered on one prefix
 *
 * Avoid calling when either action or f->action is NULL.
 */
static int
update_multifilt(struct ndn *h,
                 struct interest_filter *f,
                 struct ndn_closure *action,
                 int forw_flags)
{
    struct multifilt *md = NULL;
    struct multifilt_item *a = NULL;
    int flags;
    int i;
    int n = 0;

    if (action->p == &handle_multifilt) {
        /* This should never happen. */
        abort();
    }
    if (f->action->p == &handle_multifilt) {
        /* Already have a multifilt */
        md = f->action->data;
        if (md->me.data != md)
            abort();
        a = md->a;
    }
    else {
        /* Make a new multifilt, with 2 slots */
        a = calloc(2, sizeof(*a));
        if (a == NULL)
            return(NOTE_ERRNO(h));
        md = calloc(1, sizeof(*md));
        if (md == NULL) {
            free(a);
            return(NOTE_ERRNO(h));
        }
        md->me.p = &handle_multifilt;
        md->me.data = md;
        md->n = 2;
        md->a = a;
        ndn_replace_handler(h, &(a[0].action), f->action);
        a[0].forw_flags = f->flags;
        ndn_replace_handler(h, &(a[1].action), action);
        a[1].forw_flags = 0; /* Actually set these below */
        ndn_replace_handler(h, &f->action, &md->me);
    }
    /* Search for the action */
    for (i = 0; i < n; i++) {
        if (a[i].action == action) {
            a[i].forw_flags = forw_flags;
            if (forw_flags == 0) {
                ndn_replace_handler(h, &(a[i].action), NULL);
                action = NULL;
            }
            goto Finish;
        }
    }
    /* Not there, but if the flags are 0 we do not need to remember action */
    if (forw_flags == 0) {
        action->refcount++;
        ndn_replace_handler(h, &action, NULL);
        goto Finish;
    }
    /* Need to build a new array */
    n = build_multifilt_array(h, &a, n, action, forw_flags);
    if (n < 0)
        return(n);
    destroy_multifilt_array(h, &md->a, md->n);
    md->a = a;
    md->n = n;
Finish:
    /* The only thing left to do is to combine the forwarding flags */
    for (i = 0, flags = 0; i < n; i++)
        flags |= a[i].forw_flags;
    update_ifilt_flags(h, f, flags);
    return(0);
}

/**
 * Replace *ap with a copy, perhaps with one additional element
 *
 * The old array is not modified.  Empty slots are not copied.
 *
 * @returns new count, or -1 in case of an error.
 */
static int
build_multifilt_array(struct ndn *h,
                      struct multifilt_item **ap,
                      int n,
                      struct ndn_closure *action,
                      int forw_flags)
{
    struct multifilt_item *a = NULL; /* old array */
    struct multifilt_item *c = NULL; /* new array */
    int i, j, m;

    a = *ap;
    /* Determine how many slots we will need */
    for (m = 0, i = 0; i < n; i++) {
        if (a[i].action != NULL)
            m++;
    }
    if (action != NULL)
        m++;
    if (m == 0) {
        *ap = NULL;
        return(0);
    }
    c = calloc(m, sizeof(*c));
    if (c == NULL)
        return(NOTE_ERRNO(h));
    for (i = 0, j = 0; i < n; i++) {
        if (a[i].action != NULL) {
            ndn_replace_handler(h, &(c[j].action), a[i].action);
            c[j].forw_flags = a[i].forw_flags;
            j++;
        }
    }
    if (j < m) {
        ndn_replace_handler(h, &(c[j].action), action);
        c[j].forw_flags = forw_flags;
    }
    *ap = c;
    return(m);
}

/**
 * Destroy a multifilt_array
 */
static void
destroy_multifilt_array(struct ndn *h, struct multifilt_item **ap, int n)
{
    struct multifilt_item *a;
    int i;

    a = *ap;
    if (a != NULL) {
        for (i = 0; i < n; i++)
            ndn_replace_handler(h, &(a[i].action), NULL);
        free(a);
        *ap = NULL;
    }
}

/**
 * Upcall to handle multifilt
 */
static enum ndn_upcall_res
handle_multifilt(struct ndn_closure *selfp,
                 enum ndn_upcall_kind kind,
                 struct ndn_upcall_info *info)
{
    struct multifilt *md;
    struct multifilt_item *a;
    enum ndn_upcall_res ans;
    enum ndn_upcall_res res;
    int i, n;

    md = selfp->data;
    if (kind == NDN_UPCALL_FINAL) {
        destroy_multifilt_array(info->h, &md->a, md->n);
        free(md);
        return(NDN_UPCALL_RESULT_OK);
    }
    /*
     * Since the upcalls might be changing registrations on the fly,
     * we need to make a copy of the array (updating the refcounts).
     * Forget md and selfp, since they could go away during upcalls.
     */
    a = md->a;
    n = build_multifilt_array(info->h, &a, md->n, NULL, 0);
    ans = NDN_UPCALL_RESULT_OK;
    md = NULL;
    selfp = NULL;
    for (i = 0; i < n; i++) {
        if ((a[i].forw_flags & NDN_FORW_ACTIVE) != 0) {
            res = (a[i].action->p)(a[i].action, kind, info);
            if (res == NDN_UPCALL_RESULT_INTEREST_CONSUMED) {
                ans = res;
                if (kind == NDN_UPCALL_INTEREST)
                    kind = NDN_UPCALL_CONSUMED_INTEREST;
            }
        }
    }
    destroy_multifilt_array(info->h, &a, n);
    return(ans);
}

/* end of multifilt */

static int
ndn_pushout(struct ndn *h)
{
    ssize_t res;
    size_t size;
    if (h->outbuf != NULL && h->outbufindex < h->outbuf->length) {
        if (h->sock < 0)
            return(1);
        size = h->outbuf->length - h->outbufindex;
        res = write(h->sock, h->outbuf->buf + h->outbufindex, size);
        if (res == size) {
            h->outbuf->length = h->outbufindex = 0;
            return(0);
        }
        if (res == -1)
            return ((errno == EAGAIN) ? 1 : NOTE_ERRNO(h));
        h->outbufindex += res;
        return(1);
    }
    return(0);
}

int
ndn_put(struct ndn *h, const void *p, size_t length)
{
    struct ndn_skeleton_decoder dd = {0};
    ssize_t res;
    if (h == NULL)
        return(-1);
    if (p == NULL || length == 0)
        return(NOTE_ERR(h, EINVAL));
    res = ndn_skeleton_decode(&dd, p, length);
    if (!(res == length && dd.state == 0))
        return(NOTE_ERR(h, EINVAL));
    if (h->tap != -1) {
        res = write(h->tap, p, length);
        if (res == -1) {
            NOTE_ERRNO(h);
            (void)close(h->tap);
            h->tap = -1;
        }
    }
    if (h->outbuf != NULL && h->outbufindex < h->outbuf->length) {
        // XXX - should limit unbounded growth of h->outbuf
        ndn_charbuf_append(h->outbuf, p, length); // XXX - check res
        return (ndn_pushout(h));
    }
    if (h->sock == -1)
        res = 0;
    else
        res = write(h->sock, p, length);
    if (res == length)
        return(0);
    if (res == -1) {
        if (errno != EAGAIN)
            return(NOTE_ERRNO(h));
        res = 0;
    }
    if (h->outbuf == NULL) {
        h->outbuf = ndn_charbuf_create();
        h->outbufindex = 0;
    }
    ndn_charbuf_append(h->outbuf, ((const unsigned char *)p)+res, length-res);
    return(1);
}

int
ndn_output_is_pending(struct ndn *h)
{
    return(h != NULL && h->outbuf != NULL && h->outbufindex < h->outbuf->length);
}

struct ndn_charbuf *
ndn_grab_buffered_output(struct ndn *h)
{
    if (ndn_output_is_pending(h) && h->outbufindex == 0) {
        struct ndn_charbuf *ans = h->outbuf;
        h->outbuf = NULL;
        return(ans);
    }
    return(NULL);
}

static void
ndn_refresh_interest(struct ndn *h, struct expressed_interest *interest)
{
    int res;
    if (interest->magic != 0x7059e5f4) {
        ndn_gripe(interest);
        return;
    }
    if (interest->outstanding < interest->target) {
        res = ndn_put(h, interest->interest_msg, interest->size);
        if (res >= 0) {
            interest->outstanding += 1;
            if (h->now.tv_sec == 0)
                gettimeofday(&h->now, NULL);
            interest->lasttime = h->now;
        }
    }
}

static int
ndn_get_content_type(const unsigned char *ndnb,
                     const struct ndn_parsed_ContentObject *pco)
{
    enum ndn_content_type type = pco->type;
    (void)ndnb; // XXX - don't need now
    switch (type) {
        case NDN_CONTENT_DATA:
        case NDN_CONTENT_ENCR:
        case NDN_CONTENT_GONE:
        case NDN_CONTENT_KEY:
        case NDN_CONTENT_LINK:
        case NDN_CONTENT_NACK:
            return (type);
        default:
            return (-1);
    }
}

/**
 * Compute the digest of just the Content portion of content_object.
 */
static void
ndn_digest_Content(const unsigned char *content_object,
                   struct ndn_parsed_ContentObject *pc,
                   unsigned char *digest,
                   size_t digest_bytes)
{
    int res;
    struct ndn_digest *d = NULL;
    const unsigned char *content = NULL;
    size_t content_bytes = 0;

    if (pc->magic < 20080000) abort();
    if (digest_bytes == sizeof(digest))
        return;
    d = ndn_digest_create(NDN_DIGEST_SHA256);
    ndn_digest_init(d);
    res = ndn_ref_tagged_BLOB(NDN_DTAG_Content, content_object,
                              pc->offset[NDN_PCO_B_Content],
                              pc->offset[NDN_PCO_E_Content],
                              &content, &content_bytes);
    if (res < 0) abort();
    res = ndn_digest_update(d, content, content_bytes);
    if (res < 0) abort();
    res = ndn_digest_final(d, digest, digest_bytes);
    if (res < 0) abort();
    ndn_digest_destroy(&d);
}

static int
ndn_cache_key(struct ndn *h,
              const unsigned char *ndnb, size_t size,
              struct ndn_parsed_ContentObject *pco)
{
    int type;
    struct ndn_pkey **entry;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int res;
    unsigned char digest[32];

    type = ndn_get_content_type(ndnb, pco);
    if (type != NDN_CONTENT_KEY) {
        return (0);
    }

    ndn_digest_Content(ndnb, pco, digest, sizeof(digest));

    hashtb_start(h->keys, e);
    res = hashtb_seek(e, (void *)digest, sizeof(digest), 0);
    if (res < 0) {
        hashtb_end(e);
        return(NOTE_ERRNO(h));
    }
    entry = e->data;
    if (res == HT_NEW_ENTRY) {
        struct ndn_pkey *pkey;
        const unsigned char *data = NULL;
        size_t data_size = 0;

        res = ndn_content_get_value(ndnb, size, pco, &data, &data_size);
        if (res < 0) {
            hashtb_delete(e);
            hashtb_end(e);
            return(NOTE_ERRNO(h));
        }
        pkey = ndn_d2i_pubkey(data, data_size);
        if (pkey == NULL) {
            hashtb_delete(e);
            hashtb_end(e);
            return(NOTE_ERRNO(h));
        }
        *entry = pkey;
    }
    hashtb_end(e);
    return (0);
}

static void
finalize_pkey(struct hashtb_enumerator *e)
{
    struct ndn_pkey **entry = e->data;
    if (*entry != NULL)
        ndn_pubkey_free(*entry);
}

/**
 * Examine a ContentObject and try to find the public key needed to
 * verify it.  It might be present in our cache of keys, or in the
 * object itself; in either of these cases, we can satisfy the request
 * right away. Or there may be an indirection (a KeyName), in which case
 * return without the key. The final possibility is that there is no key
 * locator we can make sense of.
 * @returns negative for error, 0 when pubkey is filled in,
 *         or 1 if the key needs to be requested.
 */
static int
ndn_locate_key(struct ndn *h,
               const unsigned char *msg,
               struct ndn_parsed_ContentObject *pco,
               struct ndn_pkey **pubkey)
{
    int res;
    const unsigned char *pkeyid;
    size_t pkeyid_size;
    struct ndn_pkey **entry;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;

    if (h->keys == NULL) {
        return (NOTE_ERR(h, EINVAL));
    }

    res = ndn_ref_tagged_BLOB(NDN_DTAG_PublisherPublicKeyDigest, msg,
                              pco->offset[NDN_PCO_B_PublisherPublicKeyDigest],
                              pco->offset[NDN_PCO_E_PublisherPublicKeyDigest],
                              &pkeyid, &pkeyid_size);
    if (res < 0)
        return (NOTE_ERR(h, res));
    entry = hashtb_lookup(h->keys, pkeyid, pkeyid_size);
    if (entry != NULL) {
        *pubkey = *entry;
        return (0);
    }
    /* Is a key locator present? */
    if (pco->offset[NDN_PCO_B_KeyLocator] == pco->offset[NDN_PCO_E_KeyLocator])
        return (-1);
    /* Use the key locator */
    d = ndn_buf_decoder_start(&decoder, msg + pco->offset[NDN_PCO_B_Key_Certificate_KeyName],
                              pco->offset[NDN_PCO_E_Key_Certificate_KeyName] -
                              pco->offset[NDN_PCO_B_Key_Certificate_KeyName]);
    if (ndn_buf_match_dtag(d, NDN_DTAG_KeyName)) {
        return(1);
    }
    else if (ndn_buf_match_dtag(d, NDN_DTAG_Key)) {
        const unsigned char *dkey;
        size_t dkey_size;
        struct ndn_digest *digest = NULL;
        unsigned char *key_digest = NULL;
        size_t key_digest_size;
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;

        res = ndn_ref_tagged_BLOB(NDN_DTAG_Key, msg,
                                  pco->offset[NDN_PCO_B_Key_Certificate_KeyName],
                                  pco->offset[NDN_PCO_E_Key_Certificate_KeyName],
                                  &dkey, &dkey_size);
        *pubkey = ndn_d2i_pubkey(dkey, dkey_size);
        digest = ndn_digest_create(NDN_DIGEST_SHA256);
        ndn_digest_init(digest);
        key_digest_size = ndn_digest_size(digest);
        key_digest = calloc(1, key_digest_size);
        if (key_digest == NULL) abort();
        res = ndn_digest_update(digest, dkey, dkey_size);
        if (res < 0) abort();
        res = ndn_digest_final(digest, key_digest, key_digest_size);
        if (res < 0) abort();
        ndn_digest_destroy(&digest);
        hashtb_start(h->keys, e);
        res = hashtb_seek(e, (void *)key_digest, key_digest_size, 0);
        free(key_digest);
        key_digest = NULL;
        if (res < 0) {
            hashtb_end(e);
            return(NOTE_ERRNO(h));
        }
        entry = e->data;
        if (res == HT_NEW_ENTRY) {
            *entry = *pubkey;
        }
        else
            THIS_CANNOT_HAPPEN(h);
        hashtb_end(e);
        return (0);
    }
    else if (ndn_buf_match_dtag(d, NDN_DTAG_Certificate)) {
        XXX; // what should we really do in this case?
    }

    return (-1);
}

/**
 * Get the name out of a Link.
 *
 * XXX - this needs a better home.
 */
static int
ndn_append_link_name(struct ndn_charbuf *name, const unsigned char *data, size_t data_size)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    size_t start = 0;
    size_t end = 0;

    d = ndn_buf_decoder_start(&decoder, data, data_size);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Link)) {
        ndn_buf_advance(d);
        start = d->decoder.token_index;
        ndn_parse_Name(d, NULL);
        end = d->decoder.token_index;
        ndn_buf_check_close(d);
        if (d->decoder.state < 0)
            return (d->decoder.state);
        ndn_charbuf_append(name, data + start, end - start);
        return(0);
        }
    return(-1);
}

/**
 * Called when we get an answer to a KeyLocator fetch issued by
 * ndn_initiate_key_fetch.  This does not really have to do much,
 * since the main content handling logic picks up the keys as they
 * go by.
 */
static enum ndn_upcall_res
handle_key(struct ndn_closure *selfp,
           enum ndn_upcall_kind kind,
           struct ndn_upcall_info *info)
{
    struct ndn *h = info->h;
    (void)h;
    int type = 0;
    const unsigned char *msg = NULL;
    const unsigned char *data = NULL;
    size_t size;
    size_t data_size;
    int res;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *templ = NULL;

    switch(kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            return(NDN_UPCALL_RESULT_OK);
        case NDN_UPCALL_INTEREST_TIMED_OUT:
            /* Don't keep trying */
            return(NDN_UPCALL_RESULT_OK);
        case NDN_UPCALL_CONTENT_UNVERIFIED:
            /* This is not exactly right, but trying to follow the KeyLocator could be worse trouble. */
        case NDN_UPCALL_CONTENT_KEYMISSING:
        case NDN_UPCALL_CONTENT_RAW:
        case NDN_UPCALL_CONTENT:
            type = ndn_get_content_type(msg, info->pco);
            if (type == NDN_CONTENT_KEY)
                return(NDN_UPCALL_RESULT_OK);
            if (type == NDN_CONTENT_LINK) {
                /* resolve the link */
                /* Limit how much we work at this. */
                if (selfp->intdata <= 0)
                    return(NOTE_ERR(h, ELOOP));
                selfp->intdata -= 1;
                msg = info->content_ndnb;
                size = info->pco->offset[NDN_PCO_E];
                res = ndn_content_get_value(info->content_ndnb, size, info->pco,
                                            &data, &data_size);
                if (res < 0)
                    return (NDN_UPCALL_RESULT_ERR);
                templ = ndn_charbuf_create();
                ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
                ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
                ndn_charbuf_append_closer(templ); /* </Name> */
                ndnb_tagged_putf(templ, NDN_DTAG_MinSuffixComponents, "%d", 1);
                ndnb_tagged_putf(templ, NDN_DTAG_MaxSuffixComponents, "%d", 3);
                ndn_charbuf_append_closer(templ); /* </Interest> */
                name = ndn_charbuf_create();
                res = ndn_append_link_name(name, data, data_size);
                if (res < 0) {
                    NOTE_ERR(h, EINVAL);
                    res = NDN_UPCALL_RESULT_ERR;
                }
                else
                    res = ndn_express_interest(h, name, selfp, templ);
                ndn_charbuf_destroy(&name);
                ndn_charbuf_destroy(&templ);
                return(res);
            }
            return (NDN_UPCALL_RESULT_ERR);
        default:
            return (NDN_UPCALL_RESULT_ERR);
    }
}

/**
 * This is the maximum number of links in we are willing to traverse
 * when resolving a key locator.
 */
#ifndef NDN_MAX_KEY_LINK_CHAIN
#define NDN_MAX_KEY_LINK_CHAIN 7
#endif

static int
ndn_initiate_key_fetch(struct ndn *h,
                       unsigned char *msg,
                       struct ndn_parsed_ContentObject *pco,
                       struct expressed_interest *trigger_interest)
{
    /* 
     * Create a new interest in the key name, set up a callback that will
     * insert the key into the h->keys hashtb for the calling handle and
     * cause the trigger_interest to be re-expressed.
     */
    int res;
    int namelen;
    struct ndn_charbuf *key_name = NULL;
    struct ndn_closure *key_closure = NULL;
    const unsigned char *pkeyid = NULL;
    size_t pkeyid_size = 0;
    struct ndn_charbuf *templ = NULL;

    if (trigger_interest != NULL) {
        /* Arrange a wakeup when the key arrives */
        if (trigger_interest->wanted_pub == NULL)
            trigger_interest->wanted_pub = ndn_charbuf_create();
        res = ndn_ref_tagged_BLOB(NDN_DTAG_PublisherPublicKeyDigest, msg,
                                  pco->offset[NDN_PCO_B_PublisherPublicKeyDigest],
                                  pco->offset[NDN_PCO_E_PublisherPublicKeyDigest],
                                  &pkeyid, &pkeyid_size);
        if (trigger_interest->wanted_pub != NULL && res >= 0) {
            trigger_interest->wanted_pub->length = 0;
            ndn_charbuf_append(trigger_interest->wanted_pub, pkeyid, pkeyid_size);
        }
        trigger_interest->target = 0;
    }

    namelen = (pco->offset[NDN_PCO_E_KeyName_Name] -
               pco->offset[NDN_PCO_B_KeyName_Name]);
    /*
     * If there is no KeyName provided, we can't ask, but we might win if the
     * key arrives along with some other content.
     */
    if (namelen == 0)
        return(-1);
    key_closure = calloc(1, sizeof(*key_closure));
    if (key_closure == NULL)
        return (NOTE_ERRNO(h));
    key_closure->p = &handle_key;
    key_closure->intdata = NDN_MAX_KEY_LINK_CHAIN; /* to limit how many links we will resolve */

    key_name = ndn_charbuf_create();
    res = ndn_charbuf_append(key_name,
                             msg + pco->offset[NDN_PCO_B_KeyName_Name],
                             namelen);
    templ = ndn_charbuf_create();
    ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
    ndn_charbuf_append_closer(templ); /* </Name> */
    ndnb_tagged_putf(templ, NDN_DTAG_MinSuffixComponents, "%d", 1);
    ndnb_tagged_putf(templ, NDN_DTAG_MaxSuffixComponents, "%d", 3);
    if (pco->offset[NDN_PCO_B_KeyName_Pub] < pco->offset[NDN_PCO_E_KeyName_Pub]) {
        ndn_charbuf_append(templ,
                           msg + pco->offset[NDN_PCO_B_KeyName_Pub],
                           (pco->offset[NDN_PCO_E_KeyName_Pub] - 
                            pco->offset[NDN_PCO_B_KeyName_Pub]));
    }
    ndn_charbuf_append_closer(templ); /* </Interest> */
    res = ndn_express_interest(h, key_name, key_closure, templ);
    ndn_charbuf_destroy(&key_name);
    ndn_charbuf_destroy(&templ);
    return(res);
}

/**
 * If we were waiting for a key and it has arrived,
 * refresh the interest.
 */
static void
ndn_check_pub_arrival(struct ndn *h, struct expressed_interest *interest)
{
    struct ndn_charbuf *want = interest->wanted_pub;
    if (want == NULL)
        return;
    if (hashtb_lookup(h->keys, want->buf, want->length) != NULL) {
        ndn_charbuf_destroy(&interest->wanted_pub);
        interest->target = 1;
        ndn_refresh_interest(h, interest);
    }
}

/**
 * Dispatch a message through the registered upcalls.
 * This is not used by normal ndn clients, but is made available for use when
 * ndnd needs to communicate with its internal client.
 * @param h is the ndn handle.
 * @param msg is the ndnb-encoded Interest or ContentObject.
 * @param size is its size in bytes.
 */
void
ndn_dispatch_message(struct ndn *h, unsigned char *msg, size_t size)
{
    struct ndn_parsed_interest pi = {0};
    struct ndn_upcall_info info = {0};
    int i;
    int res;
    enum ndn_upcall_res ures;

    h->running++;
    info.h = h;
    info.pi = &pi;
    info.interest_comps = ndn_indexbuf_obtain(h);
    res = ndn_parse_interest(msg, size, &pi, info.interest_comps);
    if (res >= 0) {
        /* This message is an Interest */
        enum ndn_upcall_kind upcall_kind = NDN_UPCALL_INTEREST;
        info.interest_ndnb = msg;
        if (h->interest_filters != NULL && info.interest_comps->n > 0) {
            struct ndn_indexbuf *comps = info.interest_comps;
            size_t keystart = comps->buf[0];
            unsigned char *key = msg + keystart;
            struct interest_filter *entry;
            for (i = comps->n - 1; i >= 0; i--) {
                entry = hashtb_lookup(h->interest_filters, key, comps->buf[i] - keystart);
                if (entry != NULL) {
                    info.matched_comps = i;
                    ures = (entry->action->p)(entry->action, upcall_kind, &info);
                    if (ures == NDN_UPCALL_RESULT_INTEREST_CONSUMED)
                        upcall_kind = NDN_UPCALL_CONSUMED_INTEREST;
                }
            }
        }
    }
    else {
        /* This message should be a ContentObject. */
        struct ndn_parsed_ContentObject obj = {0};
        info.pco = &obj;
        info.content_comps = ndn_indexbuf_create();
        res = ndn_parse_ContentObject(msg, size, &obj, info.content_comps);
        if (res >= 0) {
            info.content_ndnb = msg;
            if (h->interests_by_prefix != NULL) {
                struct ndn_indexbuf *comps = info.content_comps;
                size_t keystart = comps->buf[0];
                unsigned char *key = msg + keystart;
                struct expressed_interest *interest = NULL;
                struct interests_by_prefix *entry = NULL;
                for (i = comps->n - 1; i >= 0; i--) {
                    entry = hashtb_lookup(h->interests_by_prefix, key, comps->buf[i] - keystart);
                    if (entry != NULL) {
                        for (interest = entry->list; interest != NULL; interest = interest->next) {
                            if (interest->magic != 0x7059e5f4) {
                                ndn_gripe(interest);
                            }
                            if (interest->target > 0 && interest->outstanding > 0) {
                                res = ndn_parse_interest(interest->interest_msg,
                                                         interest->size,
                                                         info.pi,
                                                         info.interest_comps);
                                if (res >= 0 &&
                                    ndn_content_matches_interest(msg, size,
                                                                 1, info.pco,
                                                                 interest->interest_msg,
                                                                 interest->size,
                                                                 info.pi)) {
                                    enum ndn_upcall_kind upcall_kind = NDN_UPCALL_CONTENT;
                                    struct ndn_pkey *pubkey = NULL;
                                    int type = ndn_get_content_type(msg, info.pco);
                                    if (type == NDN_CONTENT_KEY)
                                        res = ndn_cache_key(h, msg, size, info.pco);
                                    res = ndn_locate_key(h, msg, info.pco, &pubkey);
                                    if (h->defer_verification) {
                                        if (res == 0)
                                            upcall_kind = NDN_UPCALL_CONTENT_RAW;
                                        else
                                            upcall_kind = NDN_UPCALL_CONTENT_KEYMISSING;
                                    }
                                    else if (res == 0) {
                                        /* we have the pubkey, use it to verify the msg */
                                        res = ndn_verify_signature(msg, size, info.pco, pubkey);
                                        upcall_kind = (res == 1) ? NDN_UPCALL_CONTENT : NDN_UPCALL_CONTENT_BAD;
                                    } else
                                        upcall_kind = NDN_UPCALL_CONTENT_UNVERIFIED;
                                    interest->outstanding -= 1;
                                    info.interest_ndnb = interest->interest_msg;
                                    info.matched_comps = i;
                                    ures = (interest->action->p)(interest->action,
                                                                 upcall_kind,
                                                                 &info);
                                    if (interest->magic != 0x7059e5f4)
                                        ndn_gripe(interest);
                                    if (ures == NDN_UPCALL_RESULT_REEXPRESS)
                                        ndn_refresh_interest(h, interest);
                                    else if ((ures == NDN_UPCALL_RESULT_VERIFY ||
                                              ures == NDN_UPCALL_RESULT_FETCHKEY) &&
                                             (upcall_kind == NDN_UPCALL_CONTENT_UNVERIFIED ||
                                              upcall_kind == NDN_UPCALL_CONTENT_KEYMISSING)) { /* KEYS */
                                        ndn_initiate_key_fetch(h, msg, info.pco, interest);
                                    }
                                    else if (ures == NDN_UPCALL_RESULT_VERIFY &&
                                             upcall_kind == NDN_UPCALL_CONTENT_RAW) {
                                        /* For now, call this a client bug. */
                                        abort();
                                    }
                                    else {
                                        interest->target = 0;
                                        replace_interest_msg(interest, NULL);
                                        ndn_replace_handler(h, &(interest->action), NULL);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } // XXX whew, what a lot of right braces!
    ndn_indexbuf_release(h, info.interest_comps);
    ndn_indexbuf_destroy(&info.content_comps);
    h->running--;
}

static int
ndn_process_input(struct ndn *h)
{
    ssize_t res;
    ssize_t msgstart;
    unsigned char *buf;
    struct ndn_skeleton_decoder *d = &h->decoder;
    struct ndn_charbuf *inbuf = h->inbuf;
    if (inbuf == NULL)
        h->inbuf = inbuf = ndn_charbuf_create();
    if (inbuf->length == 0)
        memset(d, 0, sizeof(*d));
    buf = ndn_charbuf_reserve(inbuf, 8800);
    res = read(h->sock, buf, inbuf->limit - inbuf->length);
    if (res == 0) {
        ndn_disconnect(h);
        return(-1);
    }
    if (res == -1) {
        if (errno == EAGAIN)
            res = 0;
        else
            return(NOTE_ERRNO(h));
    }
    inbuf->length += res;
    msgstart = 0;
    ndn_skeleton_decode(d, buf, res);
    while (d->state == 0) {
        ndn_dispatch_message(h, inbuf->buf + msgstart, 
                              d->index - msgstart);
        msgstart = d->index;
        if (msgstart == inbuf->length) {
            inbuf->length = 0;
            return(0);
        }
        ndn_skeleton_decode(d, inbuf->buf + d->index,
                            inbuf->length - d->index);
    }
    if (msgstart < inbuf->length && msgstart > 0) {
        /* move partial message to start of buffer */
        memmove(inbuf->buf, inbuf->buf + msgstart,
                inbuf->length - msgstart);
        inbuf->length -= msgstart;
        d->index -= msgstart;
    }
    return(0);
}

static void
ndn_update_refresh_us(struct ndn *h, struct timeval *tv)
{
    int delta;
    if (tv->tv_sec < h->now.tv_sec)
        return;
    if (tv->tv_sec > h->now.tv_sec + NDN_INTEREST_LIFETIME_SEC)
        return;
    delta = (tv->tv_sec  - h->now.tv_sec)*1000000 +
            (tv->tv_usec - h->now.tv_usec);
    if (delta < 0)
        delta = 0;
    if (delta < h->refresh_us)
        h->refresh_us = delta;
}

static void
ndn_age_interest(struct ndn *h,
                 struct expressed_interest *interest,
                 const unsigned char *key, size_t keysize)
{
    struct ndn_parsed_interest pi = {0};
    struct ndn_upcall_info info = {0};
    int delta;
    int res;
    enum ndn_upcall_res ures;
    int firstcall;
    if (interest->magic != 0x7059e5f4)
        ndn_gripe(interest);
    info.h = h;
    info.pi = &pi;
    firstcall = (interest->lasttime.tv_sec == 0);
    if (interest->lasttime.tv_sec + 30 < h->now.tv_sec) {
        /* fixup so that delta does not overflow */
        interest->outstanding = 0;
        interest->lasttime = h->now;
        interest->lasttime.tv_sec -= 30;
    }
    delta = (h->now.tv_sec  - interest->lasttime.tv_sec)*1000000 +
            (h->now.tv_usec - interest->lasttime.tv_usec);
    if (delta >= interest->lifetime_us) {
        interest->outstanding = 0;
        delta = 0;
    }
    else if (delta < 0)
        delta = 0;
    if (interest->lifetime_us - delta < h->refresh_us)
        h->refresh_us = interest->lifetime_us - delta;
    interest->lasttime = h->now;
    while (delta > interest->lasttime.tv_usec) {
        delta -= 1000000;
        interest->lasttime.tv_sec -= 1;
    }
    interest->lasttime.tv_usec -= delta;
    if (interest->target > 0 && interest->outstanding == 0) {
        ures = NDN_UPCALL_RESULT_REEXPRESS;
        if (!firstcall) {
            info.interest_ndnb = interest->interest_msg;
            info.interest_comps = ndn_indexbuf_obtain(h);
            res = ndn_parse_interest(interest->interest_msg,
                                     interest->size,
                                     info.pi,
                                     info.interest_comps);
            if (res >= 0) {
                ures = (interest->action->p)(interest->action,
                                             NDN_UPCALL_INTEREST_TIMED_OUT,
                                             &info);
                if (interest->magic != 0x7059e5f4)
                    ndn_gripe(interest);
            }
            else {
                int i;
                fprintf(stderr, "URP!! interest has been corrupted ndn_client.c:%d\n", __LINE__);
                for (i = 0; i < 120; i++)
                    sleep(1);
                ures = NDN_UPCALL_RESULT_ERR;
            }
            ndn_indexbuf_release(h, info.interest_comps);
        }
        if (ures == NDN_UPCALL_RESULT_REEXPRESS)
            ndn_refresh_interest(h, interest);
        else
            interest->target = 0;
    }
}

static void
ndn_clean_all_interests(struct ndn *h)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct interests_by_prefix *entry;
    for (hashtb_start(h->interests_by_prefix, e); e->data != NULL;) {
        entry = e->data;
        ndn_clean_interests_by_prefix(h, entry);
        if (entry->list == NULL)
            hashtb_delete(e);
        else
            hashtb_next(e);
    }
    hashtb_end(e);
}

static void
ndn_notify_ndndid_changed(struct ndn *h)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    if (h->interest_filters != NULL) {
        for (hashtb_start(h->interest_filters, e); e->data != NULL; hashtb_next(e)) {
            struct interest_filter *i = e->data;
            if ((i->flags & NDN_FORW_WAITING_NDNDID) != 0) {
                i->expiry = h->now;
                i->flags &= ~NDN_FORW_WAITING_NDNDID;
            }
        }
        hashtb_end(e);
    }
}

/**
 * Get the previously set event schedule from a ndn handle
 * @param h is the ndn handle
 * @returns pointer to the event schedule
 */
struct ndn_schedule *
ndn_get_schedule(struct ndn *h)
{
    return(h->schedule);
}

/**
 * Set the event schedule in a ndn handle
 * @param h is the ndn handle
 * @param schedule is the new event schedule to be set in the handle
 * @returns pointer to the previous event schedule (or NULL)
 */
struct ndn_schedule *
ndn_set_schedule(struct ndn *h, struct ndn_schedule *schedule)
{
    struct ndn_schedule *old = h->schedule;
    h->schedule = schedule;
    return(old);
}

/**
 * Process any scheduled operations that are due.
 * This is not used by normal ndn clients, but is made available for use
 * by ndnd to run its internal client.
 * @param h is the ndn handle.
 * @returns the number of microseconds until the next thing needs to happen.
 */
int
ndn_process_scheduled_operations(struct ndn *h)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct interests_by_prefix *entry;
    struct expressed_interest *ie;
    int need_clean = 0;
    h->refresh_us = 5 * NDN_INTEREST_LIFETIME_MICROSEC;
    gettimeofday(&h->now, NULL);
    if (ndn_output_is_pending(h))
        return(h->refresh_us);
    h->running++;
    if (h->interest_filters != NULL) {
        for (hashtb_start(h->interest_filters, e); e->data != NULL; hashtb_next(e)) {
            struct interest_filter *i = e->data;
            if (tv_earlier(&i->expiry, &h->now)) {
                /* registration is expiring, refresh it */
                ndn_initiate_prefix_reg(h, e->key, e->keysize, i);
            }
            else
                ndn_update_refresh_us(h, &i->expiry);
        }
        hashtb_end(e);
    }
    if (h->interests_by_prefix != NULL) {
        for (hashtb_start(h->interests_by_prefix, e); e->data != NULL; hashtb_next(e)) {
            entry = e->data;
            ndn_check_interests(entry->list);
            if (entry->list == NULL)
                need_clean = 1;
            else {
                for (ie = entry->list; ie != NULL; ie = ie->next) {
                    ndn_check_pub_arrival(h, ie);
                    if (ie->target != 0)
                        ndn_age_interest(h, ie, e->key, e->keysize);
                    if (ie->target == 0 && ie->wanted_pub == NULL) {
                        ndn_replace_handler(h, &(ie->action), NULL);
                        replace_interest_msg(ie, NULL);
                        need_clean = 1;
                    }
                }
            }
        }
        hashtb_end(e);
        if (need_clean)
            ndn_clean_all_interests(h);
    }
    h->running--;
    return(h->refresh_us);
}

/**
 * Modify ndn_run timeout.
 *
 * This may be called from an upcall to change the timeout value.
 * Most often this will be used to set the timeout to zero so that
 * ndn_run() will return control to the client.
 * @param h is the ndn handle.
 * @param timeout is in milliseconds.
 * @returns old timeout value.
 */
int
ndn_set_run_timeout(struct ndn *h, int timeout)
{
    int ans = h->timeout;
    h->timeout = timeout;
    return(ans);
}

/**
 * Run the ndn client event loop.
 * This may serve as the main event loop for simple apps by passing 
 * a timeout value of -1.
 * @param h is the ndn handle.
 * @param timeout is in milliseconds.
 * @returns a negative value for error, zero for success.
 */
int
ndn_run(struct ndn *h, int timeout)
{
    struct timeval start;
    struct pollfd fds[1];
    int microsec;
    int s_microsec = -1;
    int millisec;
    int res = -1;
    if (h->running != 0)
        return(NOTE_ERR(h, EBUSY));
    memset(fds, 0, sizeof(fds));
    memset(&start, 0, sizeof(start));
    h->timeout = timeout;
    for (;;) {
        if (h->sock == -1) {
            res = -1;
            break;
        }
        if (h->schedule != NULL) {
            s_microsec = ndn_schedule_run(h->schedule);
        }
        microsec = ndn_process_scheduled_operations(h);
        if (s_microsec >= 0 && s_microsec < microsec)
            microsec = s_microsec;
        timeout = h->timeout;
        if (start.tv_sec == 0)
            start = h->now;
        else if (timeout >= 0) {
            millisec = (h->now.tv_sec  - start.tv_sec) *1000 +
            (h->now.tv_usec - start.tv_usec)/1000;
            if (millisec >= timeout) {
                res = 0;
                break;
            }
        }
        fds[0].fd = h->sock;
        fds[0].events = POLLIN;
        if (ndn_output_is_pending(h))
            fds[0].events |= POLLOUT;
        millisec = microsec / 1000;
        if (timeout >= 0 && timeout < millisec)
            millisec = timeout;
        res = poll(fds, 1, millisec);
        if (res < 0 && errno != EINTR) {
            res = NOTE_ERRNO(h);
            break;
        }
        if (res > 0) {
            if ((fds[0].revents | POLLOUT) != 0)
                ndn_pushout(h);
            if ((fds[0].revents | POLLIN) != 0)
                ndn_process_input(h);
        }
        if (h->err == ENOTCONN)
            ndn_disconnect(h);
        if (h->timeout == 0)
            break;
    }
    if (h->running != 0)
        abort();
    return((res < 0) ? res : 0);
}

/**
 * Instance data associated with handle_simple_incoming_content()
 */
struct simple_get_data {
    struct ndn_closure closure;
    struct ndn_charbuf *resultbuf;
    struct ndn_parsed_ContentObject *pcobuf;
    struct ndn_indexbuf *compsbuf;
    int flags;
    int res;
};

/**
 * Upcall for implementing ndn_get()
 */
static enum ndn_upcall_res
handle_simple_incoming_content(
    struct ndn_closure *selfp,
    enum ndn_upcall_kind kind,
    struct ndn_upcall_info *info)
{
    struct simple_get_data *md = selfp->data;
    struct ndn *h = info->h;

    if (kind == NDN_UPCALL_FINAL) {
        if (selfp != &md->closure)
            abort();
        free(md);
        return(NDN_UPCALL_RESULT_OK);
    }
    if (kind == NDN_UPCALL_INTEREST_TIMED_OUT)
        return(selfp->intdata ? NDN_UPCALL_RESULT_REEXPRESS : NDN_UPCALL_RESULT_OK);
    if (kind == NDN_UPCALL_CONTENT_UNVERIFIED) {
        if ((md->flags & NDN_GET_NOKEYWAIT) == 0)
            return(NDN_UPCALL_RESULT_VERIFY);
    }
    else if (kind == NDN_UPCALL_CONTENT_KEYMISSING) {
        if ((md->flags & NDN_GET_NOKEYWAIT) == 0)
            return(NDN_UPCALL_RESULT_FETCHKEY);
    }
    else if (kind != NDN_UPCALL_CONTENT && kind != NDN_UPCALL_CONTENT_RAW)
        return(NDN_UPCALL_RESULT_ERR);
    if (md->resultbuf != NULL) {
        md->resultbuf->length = 0;
        ndn_charbuf_append(md->resultbuf,
                           info->content_ndnb, info->pco->offset[NDN_PCO_E]);
    }
    if (md->pcobuf != NULL)
        memcpy(md->pcobuf, info->pco, sizeof(*md->pcobuf));
    if (md->compsbuf != NULL) {
        md->compsbuf->n = 0;
        ndn_indexbuf_append(md->compsbuf,
                            info->content_comps->buf, info->content_comps->n);
    }
    md->res = 0;
    ndn_set_run_timeout(h, 0);
    return(NDN_UPCALL_RESULT_OK);
}

/**
 * Get a single matching ContentObject
 * This is a convenience for getting a single matching ContentObject.
 * Blocks until a matching ContentObject arrives or there is a timeout.
 * @param h is the ndn handle. If NULL or ndn_get is called from inside
 *        an upcall, a new connection will be used and upcalls from other
 *        requests will not be processed while ndn_get is active.
 * @param name holds a ndnb-encoded Name
 * @param interest_template conveys other fields to be used in the interest
 *        (may be NULL).
 * @param timeout_ms limits the time spent waiting for an answer (milliseconds).
 * @param resultbuf is updated to contain the ndnb-encoded ContentObject.
 * @param pcobuf may be supplied to save the client the work of re-parsing the
 *        ContentObject; may be NULL if this information is not actually needed.
 * @param compsbuf works similarly.
 * @param flags - NDN_GET_NOKEYWAIT means that it is permitted to return
 *        unverified data.
 * @returns 0 for success, -1 for an error.
 */
int
ndn_get(struct ndn *h,
        struct ndn_charbuf *name,
        struct ndn_charbuf *interest_template,
        int timeout_ms,
        struct ndn_charbuf *resultbuf,
        struct ndn_parsed_ContentObject *pcobuf,
        struct ndn_indexbuf *compsbuf,
        int flags)
{
    struct ndn *orig_h = h;
    struct hashtb *saved_keys = NULL;
    int res;
    struct simple_get_data *md;

    if ((flags & ~((int)NDN_GET_NOKEYWAIT)) != 0)
        return(-1);
    if (h == NULL || h->running) {
        h = ndn_create();
        if (h == NULL)
            return(-1);
        if (orig_h != NULL) { /* Dad, can I borrow the keys? */
            saved_keys = h->keys;
            h->keys = orig_h->keys;
        }
        res = ndn_connect(h, ndn_get_connect_type(orig_h));
        if (res < 0) {
            ndn_destroy(&h);
            return(-1);
        }
    }
    md = calloc(1, sizeof(*md));
    md->resultbuf = resultbuf;
    md->pcobuf = pcobuf;
    md->compsbuf = compsbuf;
    md->flags = flags;
    md->res = -1;
    md->closure.p = &handle_simple_incoming_content;
    md->closure.data = md;
    md->closure.intdata = 1; /* tell upcall to re-express if needed */
    md->closure.refcount = 1;
    res = ndn_express_interest(h, name, &md->closure, interest_template);
    if (res >= 0)
        res = ndn_run(h, timeout_ms);
    if (res >= 0)
        res = md->res;
    md->resultbuf = NULL;
    md->pcobuf = NULL;
    md->compsbuf = NULL;
    md->closure.intdata = 0;
    md->closure.refcount--;
    if (md->closure.refcount == 0)
        free(md);
    if (h != orig_h) {
        if (saved_keys != NULL)
            h->keys = saved_keys;
        ndn_destroy(&h);
    }
    return(res);
}

/**
 * Upcall to handle response to fetch a ndndid
 */
static enum ndn_upcall_res
handle_ndndid_response(struct ndn_closure *selfp,
                     enum ndn_upcall_kind kind,
                     struct ndn_upcall_info *info)
{
    int res;
    const unsigned char *ndndid = NULL;
    size_t size = 0;
    struct ndn *h = info->h;

    if (kind == NDN_UPCALL_FINAL) {
        free(selfp);
        return(NDN_UPCALL_RESULT_OK);
    }
    if (kind == NDN_UPCALL_CONTENT_UNVERIFIED)
        return(NDN_UPCALL_RESULT_VERIFY);
    if (kind == NDN_UPCALL_CONTENT_KEYMISSING)
        return(NDN_UPCALL_RESULT_FETCHKEY);
    if (kind == NDN_UPCALL_CONTENT_RAW) {
        if (ndn_verify_content(h, info->content_ndnb, info->pco) == 0)
            kind = NDN_UPCALL_CONTENT;
    }
    if (kind != NDN_UPCALL_CONTENT) {
        NOTE_ERR(h, -1000 - kind);
        return(NDN_UPCALL_RESULT_ERR);
    }
    res = ndn_ref_tagged_BLOB(NDN_DTAG_PublisherPublicKeyDigest,
                              info->content_ndnb,
                              info->pco->offset[NDN_PCO_B_PublisherPublicKeyDigest],
                              info->pco->offset[NDN_PCO_E_PublisherPublicKeyDigest],
                              &ndndid,
                              &size);
    if (res < 0) {
        NOTE_ERR(h, -1);
        return(NDN_UPCALL_RESULT_ERR);
    }
    if (h->ndndid == NULL) {
        h->ndndid = ndn_charbuf_create_n(size);
        if (h->ndndid == NULL)
            return(NOTE_ERRNO(h));
    }
    ndn_charbuf_reset(h->ndndid);
    ndn_charbuf_append(h->ndndid, ndndid, size);
    ndn_notify_ndndid_changed(h);
    return(NDN_UPCALL_RESULT_OK);
}

static void
ndn_initiate_ndndid_fetch(struct ndn *h)
{
    struct ndn_charbuf *name = NULL;
    struct ndn_closure *action = NULL;

    name = ndn_charbuf_create();
    ndn_name_from_uri(name, "ndn:/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY");
    action = calloc(1, sizeof(*action));
    action->p = &handle_ndndid_response;
    ndn_express_interest(h, name, action, NULL);
    ndn_charbuf_destroy(&name);
}

/**
 * Handle reply to a prefix registration request
 */
static enum ndn_upcall_res
handle_prefix_reg_reply(
    struct ndn_closure *selfp,
    enum ndn_upcall_kind kind,
    struct ndn_upcall_info *info)
{
    struct ndn_reg_closure *md = selfp->data;
    struct ndn *h = info->h;
    int lifetime = 10;
    struct ndn_forwarding_entry *fe = NULL;
    int res;
    const unsigned char *fe_ndnb = NULL;
    size_t fe_ndnb_size = 0;

    if (kind == NDN_UPCALL_FINAL) {
        // fprintf(stderr, "GOT TO handle_prefix_reg_reply FINAL\n");
        if (selfp != &md->action)
            abort();
        if (md->interest_filter != NULL)
            md->interest_filter->ndn_reg_closure = NULL;
        selfp->data = NULL;
        free(md);
        return(NDN_UPCALL_RESULT_OK);
    }
    if (kind == NDN_UPCALL_INTEREST_TIMED_OUT)
        return(NDN_UPCALL_RESULT_REEXPRESS);
    if (kind == NDN_UPCALL_CONTENT_UNVERIFIED)
        return(NDN_UPCALL_RESULT_VERIFY);
    if (kind == NDN_UPCALL_CONTENT_KEYMISSING)
        return(NDN_UPCALL_RESULT_FETCHKEY);
    if (kind == NDN_UPCALL_CONTENT_RAW) {
        if (ndn_verify_content(h, info->content_ndnb, info->pco) == 0)
            kind = NDN_UPCALL_CONTENT;
    }
    if (kind != NDN_UPCALL_CONTENT) {
        NOTE_ERR(h, -1000 - kind);
        return(NDN_UPCALL_RESULT_ERR);
    }
    res = ndn_content_get_value(info->content_ndnb,
                                info->pco->offset[NDN_PCO_E],
                                info->pco,
                                &fe_ndnb, &fe_ndnb_size);
    if (res == 0)
        fe = ndn_forwarding_entry_parse(fe_ndnb, fe_ndnb_size);
    if (fe == NULL) {
        XXX;
        lifetime = 30;
    }
    else
        lifetime = fe->lifetime;
    if (lifetime < 0)
        lifetime = 0;
    else if (lifetime > 3600)
        lifetime = 3600;
    if (md->interest_filter != NULL) {
        md->interest_filter->expiry = h->now;
        md->interest_filter->expiry.tv_sec += lifetime;
    }
    ndn_forwarding_entry_destroy(&fe);
    return(NDN_UPCALL_RESULT_OK);
}

static void
ndn_initiate_prefix_reg(struct ndn *h,
                        const void *prefix, size_t prefix_size,
                        struct interest_filter *i)
{
    struct ndn_reg_closure *p = NULL;
    struct ndn_charbuf *reqname = NULL;
    struct ndn_charbuf *templ = NULL;
    struct ndn_forwarding_entry fe_store = { 0 };
    struct ndn_forwarding_entry *fe = &fe_store;
    struct ndn_charbuf *reg_request = NULL;
    struct ndn_charbuf *signed_reg_request = NULL;
    struct ndn_charbuf *empty = NULL;

    i->expiry = h->now;
    i->expiry.tv_sec += 60;
    /* This test is mainly for the benefit of the ndnd internal client */
    if (h->sock == -1)
        return;
    // fprintf(stderr, "GOT TO STUB ndn_initiate_prefix_reg()\n");
    if (h->ndndid == NULL) {
        ndn_initiate_ndndid_fetch(h);
        i->flags |= NDN_FORW_WAITING_NDNDID;
        return;
    }
    if (i->ndn_reg_closure != NULL)
        return;
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        NOTE_ERRNO(h);
        return;
    }
    p->action.data = p;
    p->action.p = &handle_prefix_reg_reply;
    p->interest_filter = i;
    i->ndn_reg_closure = p;
    reqname = ndn_charbuf_create();
    ndn_name_from_uri(reqname, "ndn:/ndnx");
    ndn_name_append(reqname, h->ndndid->buf, h->ndndid->length);
    ndn_name_append_str(reqname, "selfreg");
    fe->action = "selfreg";
    fe->ndnd_id = h->ndndid->buf;
    fe->ndnd_id_size = h->ndndid->length;
    fe->faceid = ~0; // XXX - someday explicit faceid may be required
    fe->name_prefix = ndn_charbuf_create();
    fe->flags = i->flags & 0xFF;
    fe->lifetime = -1; /* Let ndnd decide */
    ndn_name_init(fe->name_prefix);
    ndn_name_append_components(fe->name_prefix, prefix, 0, prefix_size);
    reg_request = ndn_charbuf_create();
    ndnb_append_forwarding_entry(reg_request, fe);
    empty = ndn_charbuf_create();
    ndn_name_init(empty);
    signed_reg_request = ndn_charbuf_create();
    ndn_sign_content(h, signed_reg_request, empty, NULL,
                     reg_request->buf, reg_request->length);
    ndn_name_append(reqname,
                    signed_reg_request->buf, signed_reg_request->length);
    // XXX - should set up templ for scope 1
    ndn_express_interest(h, reqname, &p->action, templ);
    ndn_charbuf_destroy(&fe->name_prefix);
    ndn_charbuf_destroy(&reqname);
    ndn_charbuf_destroy(&templ);
    ndn_charbuf_destroy(&reg_request);
    ndn_charbuf_destroy(&signed_reg_request);
    ndn_charbuf_destroy(&empty);
}

/**
 * Verify a ContentObject using the public key from either the object
 * itself or our cache of keys.
 *
 * This routine does not attempt to fetch the public key if it is not
 * at hand.
 * @returns negative for error, 0 verification success,
 *         or 1 if the key needs to be requested.
 */
int
ndn_verify_content(struct ndn *h,
                   const unsigned char *msg,
                   struct ndn_parsed_ContentObject *pco)
{
    struct ndn_pkey *pubkey = NULL;
    int res;
    unsigned char *buf = (unsigned char *)msg; /* XXX - discard const */

    res = ndn_locate_key(h, msg, pco, &pubkey);
    if (res == 0) {
        /* we have the pubkey, use it to verify the msg */
        res = ndn_verify_signature(buf, pco->offset[NDN_PCO_E], pco, pubkey);
        res = (res == 1) ? 0 : -1;
    }
    return(res);
}

/**
 * Load a private key from a keystore file.
 *
 * This call is only required for applications that use something other
 * than the user's default signing key.
 * @param h is the ndn handle
 * @param keystore_path is the pathname of the keystore file
 * @param keystore_passphrase is the passphase needed to unlock the keystore
 * @param pubid_out if not NULL, is loaded with the digest of the public key
 * @result is 0 for success, negative for error.
 */
int
ndn_load_private_key(struct ndn *h,
                     const char *keystore_path,
                     const char *keystore_passphrase,
                     struct ndn_charbuf *pubid_out)
{
    struct ndn_keystore *keystore = NULL;
    int res = 0;
    struct ndn_charbuf *pubid = pubid_out;
    struct ndn_charbuf *pubid_store = NULL;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    if (pubid == NULL)
        pubid = pubid_store = ndn_charbuf_create();
    if (pubid == NULL) {
        res = NOTE_ERRNO(h);
        goto Cleanup;
    }
    keystore = ndn_keystore_create();
    if (keystore == NULL) {
        res = NOTE_ERRNO(h);
        goto Cleanup;
    }
    res = ndn_keystore_init(keystore,
                           (char *)keystore_path,
                           (char *)keystore_passphrase);
    if (res != 0) {
        res = NOTE_ERRNO(h);
        goto Cleanup;
    }
    pubid->length = 0;
    ndn_charbuf_append(pubid,
                       ndn_keystore_public_key_digest(keystore),
                       ndn_keystore_public_key_digest_length(keystore));
    hashtb_start(h->keystores, e);
    res = hashtb_seek(e, pubid->buf, pubid->length, 0);
    if (res == HT_NEW_ENTRY) {
        struct ndn_keystore **p = e->data;
        *p = keystore;
        keystore = NULL;
        res = 0;
    }
    else if (res == HT_OLD_ENTRY)
        res = 0;
    else
        res = NOTE_ERRNO(h);
    hashtb_end(e);
Cleanup:
    ndn_charbuf_destroy(&pubid_store);
    ndn_keystore_destroy(&keystore);
    return(res);
}

/**
 * Load the handle's default signing key from a keystore.
 *
 * This call is only required for applications that use something other
 * than the user's default signing key as the handle's default.  It should
 * be called early and at most once.
 * @param h is the ndn handle
 * @param keystore_path is the pathname of the keystore file
 * @param keystore_passphrase is the passphase needed to unlock the keystore
 * @result is 0 for success, negative for error.
 */
int
ndn_load_default_key(struct ndn *h,
                     const char *keystore_path,
                     const char *keystore_passphrase)
{
    struct ndn_charbuf *default_pubid = NULL;
    int res;

    if (h->default_pubid != NULL)
        return(NOTE_ERR(h, EINVAL));
    default_pubid = ndn_charbuf_create();
    if (default_pubid == NULL)
        return(NOTE_ERRNO(h));
    res = ndn_load_private_key(h,
                               keystore_path,
                               keystore_passphrase,
                               default_pubid);
    if (res == 0)
        h->default_pubid = default_pubid;
    else
        ndn_charbuf_destroy(&default_pubid);
    return(res);
}

static void
finalize_keystore(struct hashtb_enumerator *e)
{
    struct ndn_keystore **p = e->data;
    ndn_keystore_destroy(p);
}

/**
 * Place the public key associated with the params into result
 * buffer, and its digest into digest_result.
 *
 * This is for one of our signing keys, not just any key.
 * Result buffers may be NULL if the corresponding result is not wanted.
 *
 * @returns 0 for success, negative for error
 */
int
ndn_get_public_key(struct ndn *h,
                   const struct ndn_signing_params *params,
                   struct ndn_charbuf *digest_result,
                   struct ndn_charbuf *result)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_keystore *keystore = NULL;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int res;
    res = ndn_chk_signing_params(h, params, &sp, NULL, NULL, NULL, NULL);
    if (res < 0)
        return(res);
    hashtb_start(h->keystores, e);
    if (hashtb_seek(e, sp.pubid, sizeof(sp.pubid), 0) == HT_OLD_ENTRY) {
        struct ndn_keystore **pk = e->data;
        keystore = *pk;
        if (digest_result != NULL) {
            digest_result->length = 0;
            ndn_charbuf_append(digest_result,
                               ndn_keystore_public_key_digest(keystore),
                               ndn_keystore_public_key_digest_length(keystore));
        }
        if (result != NULL) {
            struct ndn_buf_decoder decoder;
            struct ndn_buf_decoder *d;
            const unsigned char *p;
            size_t size;
            result->length = 0;
            ndn_append_pubkey_blob(result, ndn_keystore_public_key(keystore));
            d = ndn_buf_decoder_start(&decoder, result->buf, result->length);
            res = ndn_buf_match_blob(d, &p, &size);
            if (res >= 0) {
                memmove(result->buf, p, size);
                result->length = size;
                res = 0;
            }
        }
    }
    else {
        res = NOTE_ERR(h, -1);
        hashtb_delete(e);
    }
    hashtb_end(e);
    return(res);
}

int
ndn_get_public_key_and_name(struct ndn *h,
                            const struct ndn_signing_params *params,
                            struct ndn_charbuf *digest_result,
                            struct ndn_charbuf *pubkey_data,
                            struct ndn_charbuf *pubkey_name)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_keystore *keystore = NULL;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int res;
    res = ndn_chk_signing_params(h, params, &sp, NULL, NULL, NULL, NULL);
    if (res < 0)
        return(res);
    hashtb_start(h->keystores, e);
    if (hashtb_seek(e, sp.pubid, sizeof(sp.pubid), 0) == HT_OLD_ENTRY) {
        struct ndn_keystore **pk = e->data;
        keystore = *pk;
        if (digest_result != NULL) {
            digest_result->length = 0;
            ndn_charbuf_append(digest_result,
                               ndn_keystore_public_key_digest(keystore),
                               ndn_keystore_public_key_digest_length(keystore));
        }
        if (pubkey_data != NULL) {
            struct ndn_buf_decoder decoder;
            struct ndn_buf_decoder *d;
            const unsigned char *p;
            size_t size;
            pubkey_data->length = 0;
            ndn_append_pubkey_blob(pubkey_data, ndn_keystore_public_key(keystore));
            d = ndn_buf_decoder_start(&decoder, pubkey_data->buf, pubkey_data->length);
            res = ndn_buf_match_blob(d, &p, &size);
            if (res >= 0) {
                memmove(pubkey_data->buf, p, size);
                pubkey_data->length = size;
                res = 0;
            }
        }
        if (pubkey_name != NULL) {
            const struct ndn_charbuf *name = ndn_keystore_get_pubkey_name (keystore);

            if (name != NULL) {
                ndn_charbuf_append_charbuf (pubkey_name, name);
            }
        }
    }
    else {
        res = NOTE_ERR(h, -1);
        hashtb_delete(e);
    }
    hashtb_end(e);
    return(res);
}


static int
ndn_load_or_create_key(struct ndn *h,
                       const char *keystore,
                       struct ndn_charbuf *pubid)
{
    const char *password;
    int res;
    
    password = getenv("NDNX_KEYSTORE_PASSWORD");
    if (password == 0)
        password = "Th1s1sn0t8g00dp8ssw0rd.";
    res = ndn_load_private_key(h, keystore, password, pubid);
    if (res != 0) {
        /* Either file exists and password is wrong or file does not exist */
        if (access(keystore, R_OK) == 0) {
            fprintf(stderr,
               "Keystore file [%s] exists, but private key cannot be loaded.\n"
               "Check if NDNX_KEYSTORE_PASSWORD is set to a correct password,\n"
               "otherwise remove [%s] and it will be automatically created.\n",
               keystore, keystore);
            return(res);
        }
        fprintf(stderr,
            "Keystore [%s] does not exist and will be automatically created\n",
            keystore);
        res = ndn_keystore_file_init((char*)keystore, (char*)password,
                "ndnxuser", 0, 3650); /* create a key valid for 10 years */
        if (res != 0) {
            fprintf(stderr, "Cannot create keystore [%s]\n", keystore);
            res = NOTE_ERRNO(h);
            return(res);
        }
        res = ndn_load_private_key(h, keystore, password, pubid);
    }
    return(res);
}

static int
ndn_load_or_create_default_key(struct ndn *h)
{
    const char *s = NULL;
    struct ndn_charbuf *path = NULL;
    struct ndn_charbuf *default_pubid = NULL;
    int res = 0;
    
    if (h->default_pubid != NULL)
        return(0);
    
    path = ndn_charbuf_create();
    default_pubid = ndn_charbuf_create();
    if (default_pubid == NULL || path == NULL)
        return(NOTE_ERRNO(h));
    s = getenv("NDNX_DIR");
    if (s != NULL && s[0] != 0)
        ndn_charbuf_putf(path, "%s", s);
    else {
        s = getenv("HOME");
        if (s != NULL && s[0] != 0) {
            ndn_charbuf_putf(path, "%s/.ndnx", s);
            res = mkdir(ndn_charbuf_as_string(path), S_IRWXU);
            if (res == -1) {
                if (errno == EEXIST)
                    res = 0;
                else
                    res = NOTE_ERRNO(h);
            }
        }
        else
            res = NOTE_ERR(h, -1);
    }
    ndn_charbuf_putf(path, "/%s", ".ndnx_keystore");
    res = ndn_load_or_create_key(h,
                                 ndn_charbuf_as_string(path),
                                 default_pubid);
    if (res == 0) {
        h->default_pubid = default_pubid;
        default_pubid = NULL;
    }
    ndn_charbuf_destroy(&default_pubid);
    ndn_charbuf_destroy(&path);
    return(res);
}

/**
 * This is mostly for use within the library,
 * but may be useful for some clients.
 */
int
ndn_chk_signing_params(struct ndn *h,
                       const struct ndn_signing_params *params,
                       struct ndn_signing_params *result,
                       struct ndn_charbuf **ptimestamp,
                       struct ndn_charbuf **pfinalblockid,
                       struct ndn_charbuf **pkeylocator,
                       struct ndn_charbuf **pextopt)
{
    int res = 0;
    int i;
    int conflicting;
    int needed;

    if (params != NULL)
        *result = *params;
    if ((result->sp_flags & ~(NDN_SP_TEMPL_TIMESTAMP      |
                              NDN_SP_TEMPL_FINAL_BLOCK_ID |
                              NDN_SP_TEMPL_FRESHNESS      |
                              NDN_SP_TEMPL_KEY_LOCATOR    |
                              NDN_SP_FINAL_BLOCK          |
                              NDN_SP_OMIT_KEY_LOCATOR     |
                              NDN_SP_TEMPL_EXT_OPT
                              )) != 0)
        return(NOTE_ERR(h, EINVAL));
    conflicting = NDN_SP_TEMPL_FINAL_BLOCK_ID | NDN_SP_FINAL_BLOCK;
    if ((result->sp_flags & conflicting) == conflicting)
        return(NOTE_ERR(h, EINVAL));
    conflicting = NDN_SP_TEMPL_KEY_LOCATOR | NDN_SP_OMIT_KEY_LOCATOR;
        if ((result->sp_flags & conflicting) == conflicting)
        return(NOTE_ERR(h, EINVAL));
    for (i = 0; i < sizeof(result->pubid) && result->pubid[i] == 0; i++)
        continue;
    if (i == sizeof(result->pubid)) {
        if (h->default_pubid == NULL) {
            res = ndn_load_or_create_default_key(h);
            if (res < 0)
                return(res);
        }
        memcpy(result->pubid, h->default_pubid->buf, sizeof(result->pubid));
    }
    needed = result->sp_flags & (NDN_SP_TEMPL_TIMESTAMP      |
                                 NDN_SP_TEMPL_FINAL_BLOCK_ID |
                                 NDN_SP_TEMPL_FRESHNESS      |
                                 NDN_SP_TEMPL_KEY_LOCATOR    |
                                 NDN_SP_TEMPL_EXT_OPT        );
    if (result->template_ndnb != NULL) {
        struct ndn_buf_decoder decoder;
        struct ndn_buf_decoder *d;
        size_t start;
        size_t stop;
        size_t size;
        const unsigned char *ptr = NULL;
        d = ndn_buf_decoder_start(&decoder,
                                  result->template_ndnb->buf,
                                  result->template_ndnb->length);
        if (ndn_buf_match_dtag(d, NDN_DTAG_SignedInfo)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_dtag(d, NDN_DTAG_PublisherPublicKeyDigest))
                ndn_parse_required_tagged_BLOB(d,
                    NDN_DTAG_PublisherPublicKeyDigest, 16, 64);
            start = d->decoder.token_index;
            ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_Timestamp, 1, -1);
            stop = d->decoder.token_index;
            if ((needed & NDN_SP_TEMPL_TIMESTAMP) != 0) {
                i = ndn_ref_tagged_BLOB(NDN_DTAG_Timestamp,
                                        d->buf,
                                        start, stop,
                                        &ptr, &size);
                if (i == 0) {
                    if (ptimestamp != NULL) {
                        *ptimestamp = ndn_charbuf_create();
                        ndn_charbuf_append(*ptimestamp, ptr, size);
                    }
                    needed &= ~NDN_SP_TEMPL_TIMESTAMP;
                }
            }
            ndn_parse_optional_tagged_BLOB(d, NDN_DTAG_Type, 1, -1);
            i = ndn_parse_optional_tagged_nonNegativeInteger(d,
                    NDN_DTAG_FreshnessSeconds);
            if ((needed & NDN_SP_TEMPL_FRESHNESS) != 0 && i >= 0) {
                result->freshness = i;
                needed &= ~NDN_SP_TEMPL_FRESHNESS;
            }
            if (ndn_buf_match_dtag(d, NDN_DTAG_FinalBlockID)) {
                ndn_buf_advance(d);
                start = d->decoder.token_index;
                if (ndn_buf_match_some_blob(d))
                    ndn_buf_advance(d);
                stop = d->decoder.token_index;
                ndn_buf_check_close(d);
                if ((needed & NDN_SP_TEMPL_FINAL_BLOCK_ID) != 0 && 
                    d->decoder.state >= 0 && stop > start) {
                    if (pfinalblockid != NULL) {
                        *pfinalblockid = ndn_charbuf_create();
                        ndn_charbuf_append(*pfinalblockid,
                                           d->buf + start, stop - start);
                    }
                    needed &= ~NDN_SP_TEMPL_FINAL_BLOCK_ID;
                }
            }
            start = d->decoder.token_index;
            if (ndn_buf_match_dtag(d, NDN_DTAG_KeyLocator))
                ndn_buf_advance_past_element(d);
            stop = d->decoder.token_index;
            if ((needed & NDN_SP_TEMPL_KEY_LOCATOR) != 0 && 
                d->decoder.state >= 0 && stop > start) {
                if (pkeylocator != NULL) {
                    *pkeylocator = ndn_charbuf_create();
                    ndn_charbuf_append(*pkeylocator,
                                       d->buf + start, stop - start);
                }
                needed &= ~NDN_SP_TEMPL_KEY_LOCATOR;
            }
            start = d->decoder.token_index;
            if (ndn_buf_match_dtag(d, NDN_DTAG_ExtOpt))
                ndn_buf_advance_past_element(d);
            stop = d->decoder.token_index;
            if ((needed & NDN_SP_TEMPL_EXT_OPT) != 0 && 
                d->decoder.state >= 0 && stop > start) {
                if (pextopt != NULL) {
                    *pextopt = ndn_charbuf_create();
                    ndn_charbuf_append(*pextopt,
                                       d->buf + start, stop - start);
                }
                needed &= ~NDN_SP_TEMPL_EXT_OPT;
            }
            ndn_buf_check_close(d);
        }
        if (d->decoder.state < 0)
            res = NOTE_ERR(h, EINVAL);
    }
    if (needed != 0)
        res = NOTE_ERR(h, EINVAL);
    return(res);
}

/**
 * Create a signed ContentObject.
 *
 * @param h is the ndn handle
 * @param resultbuf - result buffer to which the ContentObject will be appended
 * @param name_prefix contains the ndnb-encoded name
 * @param params describe the ancillary information needed
 * @param data points to the raw content
 * @param size is the size of the raw content, in bytes
 * @returns 0 for success, -1 for error
 */
int
ndn_sign_content(struct ndn *h,
                 struct ndn_charbuf *resultbuf,
                 const struct ndn_charbuf *name_prefix,
                 const struct ndn_signing_params *params,
                 const void *data, size_t size)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_signing_params p = NDN_SIGNING_PARAMS_INIT;
    struct ndn_charbuf *signed_info = NULL;
    struct ndn_keystore *keystore = NULL;
    struct ndn_charbuf *timestamp = NULL;
    struct ndn_charbuf *finalblockid = NULL;
    struct ndn_charbuf *keylocator = NULL;
    struct ndn_charbuf *extopt = NULL;
    int res;

    res = ndn_chk_signing_params(h, params, &p,
                                 &timestamp, &finalblockid, &keylocator, &extopt);
    if (res < 0)
        return(res);
    hashtb_start(h->keystores, e);
    if (hashtb_seek(e, p.pubid, sizeof(p.pubid), 0) == HT_OLD_ENTRY) {
        struct ndn_keystore **pk = e->data;
        keystore = *pk;
        signed_info = ndn_charbuf_create();
        if (keylocator == NULL && (p.sp_flags & NDN_SP_OMIT_KEY_LOCATOR) == 0) {
            /* Construct a key locator containing the key itself */
            keylocator = ndn_charbuf_create();
            ndn_charbuf_append_tt(keylocator, NDN_DTAG_KeyLocator, NDN_DTAG);
            ndn_charbuf_append_tt(keylocator, NDN_DTAG_Key, NDN_DTAG);
            res = ndn_append_pubkey_blob(keylocator,
                                         ndn_keystore_public_key(keystore));
            ndn_charbuf_append_closer(keylocator); /* </Key> */
            ndn_charbuf_append_closer(keylocator); /* </KeyLocator> */
        }
        if (res >= 0 && (p.sp_flags & NDN_SP_FINAL_BLOCK) != 0) {
            int ncomp;
            struct ndn_indexbuf *ndx;
            const unsigned char *comp = NULL;
            size_t size = 0;

            ndx = ndn_indexbuf_create();
            ncomp = ndn_name_split(name_prefix, ndx);
            if (ncomp < 0)
                res = NOTE_ERR(h, EINVAL);
            else {
                finalblockid = ndn_charbuf_create();
                ndn_name_comp_get(name_prefix->buf,
                                  ndx, ncomp - 1, &comp, &size);
                ndn_charbuf_append_tt(finalblockid, size, NDN_BLOB);
                ndn_charbuf_append(finalblockid, comp, size);
            }
            ndn_indexbuf_destroy(&ndx);
        }
        if (res >= 0)
            res = ndn_signed_info_create(signed_info,
                                         ndn_keystore_public_key_digest(keystore),
                                         ndn_keystore_public_key_digest_length(keystore),
                                         timestamp,
                                         p.type,
                                         p.freshness,
                                         finalblockid,
                                         keylocator);
        if (res >= 0 && extopt != NULL) {
            /* ExtOpt not currently part of ndn_signed_info_create */
            if (signed_info->length > 0 &&
                signed_info->buf[signed_info->length - 1] == 0) {
                signed_info->length -= 1; /* remove closer */
                ndn_charbuf_append_charbuf(signed_info, extopt);
                ndn_charbuf_append_closer(signed_info);
            }
            else
                NOTE_ERR(h, -1);
        }
        if (res >= 0)
            res = ndn_encode_ContentObject(resultbuf,
                                           name_prefix,
                                           signed_info,
                                           data,
                                           size,
                                           ndn_keystore_digest_algorithm(keystore),
                                           ndn_keystore_private_key(keystore));
    }
    else {
        res = NOTE_ERR(h, -1);
        hashtb_delete(e);
    }
    hashtb_end(e);
    ndn_charbuf_destroy(&timestamp);
    ndn_charbuf_destroy(&keylocator);
    ndn_charbuf_destroy(&finalblockid);
    ndn_charbuf_destroy(&signed_info);
    return(res);
}
/**
 * Check whether content described by info is final block.
 *
 * @param info - the ndn_upcall_info describing the ContentObject
 * @returns 1 for final block, 0 for not final, -1 if an error occurs
 */
int
ndn_is_final_block(struct ndn_upcall_info *info)
{
    return (ndn_is_final_pco(info->content_ndnb, info->pco, info->content_comps));
}

/**
 * Given a ndnb encoded content object, the parsed form, and name components
 * report whether this is the last (FinalBlockID) segment of a stream.
 * @param ndnb - a ndnb encoded content object
 * @param pco - the parsed content object
 * @param comps - an indexbuf locating the components of the name
 * @returns 1 for final block, 0 for not final, or -1 for error.
 */
int
ndn_is_final_pco(const unsigned char *ndnb,
                    struct ndn_parsed_ContentObject *pco,
                    struct ndn_indexbuf *comps)
{
    if (ndnb == NULL || pco == NULL)
        return(0);
    if (pco->offset[NDN_PCO_B_FinalBlockID] !=
        pco->offset[NDN_PCO_E_FinalBlockID]) {
        const unsigned char *finalid = NULL;
        size_t finalid_size = 0;
        const unsigned char *nameid = NULL;
        size_t nameid_size = 0;
        ndn_ref_tagged_BLOB(NDN_DTAG_FinalBlockID, ndnb,
                            pco->offset[NDN_PCO_B_FinalBlockID],
                            pco->offset[NDN_PCO_E_FinalBlockID],
                            &finalid,
                            &finalid_size);
        if (comps->n < 2) return(-1);
        ndn_ref_tagged_BLOB(NDN_DTAG_Component, ndnb,
                            comps->buf[comps->n - 2],
                            comps->buf[comps->n - 1],
                            &nameid,
                            &nameid_size);
        if (finalid_size == nameid_size &&
            0 == memcmp(finalid, nameid, nameid_size))
            return(1);
    }
    return(0);
}

/**
 * Ask upstream for a guest prefix that will be routed to us.
 *
 * On success, the prefix is placed into result, in the form of a uri.
 * ms is the maximum time to wait for an answer.
 *
 * @result is 0 for success, or -1 for failure.
 */
int
ndn_guest_prefix(struct ndn *h, struct ndn_charbuf *result, int ms)
{
    struct ndn_parsed_ContentObject pco = {0};
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *templ = NULL;
    struct ndn_charbuf *cob = NULL;
    const unsigned char *p = NULL;
    unsigned char me[] = "\xC1.M.K\x00XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    size_t p_size;
    int res = -1;
    
    if (h->ndndid == NULL) {
        ndn_initiate_ndndid_fetch(h);
        ndn_run(h, (ms < 400) ? ms / 2 : 200);
    }
    if (h->ndndid == NULL)
        return(-1);
    name = ndn_charbuf_create();
    if (name == NULL)
        return(-1);
    cob = ndn_charbuf_create();
    if (cob == NULL)
        goto Bail;
    res = ndn_name_from_uri(name, "ndn:/%C1.M.S.neighborhood/guest");
    if (res < 0)
        goto Bail;
    memcpy(me + 6, h->ndndid->buf, 32);
    res = ndn_name_append(name, me, 6 + 32);
    if (res < 0)
        goto Bail;
    templ = ndn_charbuf_create();
    if (templ == NULL)
        goto Bail;
    ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
    ndn_charbuf_append_closer(templ); /* </Name> */
    ndnb_tagged_putf(templ, NDN_DTAG_Scope, "%d", 2);
    ndn_charbuf_append_closer(templ); /* </Interest> */
    res = ndn_resolve_version(h, name, NDN_V_HIGHEST, ms);
    if (res < 0)
        goto Bail;
    res = ndn_get(h, name, templ, ms, cob, &pco, NULL, 0);
    if (res < 0)
        goto Bail;
    if (result != NULL) {
        ndn_charbuf_reset(result);
        res = ndn_content_get_value(cob->buf, cob->length, &pco, &p, &p_size);
        if (res < 0)
            goto Bail;
        res = ndn_charbuf_append(result, p, p_size);
    }
Bail:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&cob);
    ndn_charbuf_destroy(&templ);
    return((res < 0) ? -1 : 0);
}
