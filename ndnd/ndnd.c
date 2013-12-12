/*
 * ndnd/ndnd.c
 *
 * Main program of ndnd - the NDNx Daemon
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

/**
 * Main program of ndnd - the NDNx Daemon
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

#if defined(NEED_GETADDRINFO_COMPAT)
    #include "getaddrinfo.h"
    #include "dummyin6.h"
#endif

#include <ndn/bloom.h>
#include <ndn/ndn.h>
#include <ndn/ndn_private.h>
#include <ndn/ndnd.h>
#include <ndn/charbuf.h>
#include <ndn/face_mgmt.h>
#include <ndn/hashtb.h>
#include <ndn/indexbuf.h>
#include <ndn/schedule.h>
#include <ndn/reg_mgmt.h>
#include <ndn/uri.h>

#include "ndnd_private.h"

/** Ops for strategy callout */
enum ndn_strategy_op {
    NDNST_NOP,      /* no-operation */
    NDNST_FIRST,    /* newly created interest entry (pit entry) */
    NDNST_TIMER,    /* wakeup used by strategy */
    NDNST_SATISFIED, /* matching content has arrived, pit entry will go away */
    NDNST_TIMEOUT,  /* all downstreams timed out, pit entry will go away */
};

static void cleanup_at_exit(void);
static void unlink_at_exit(const char *path);
static int create_local_listener(struct ndnd_handle *h, const char *sockname, int backlog);
static struct face *record_connection(struct ndnd_handle *h,
                                      int fd,
                                      struct sockaddr *who,
                                      socklen_t wholen,
                                      int setflags);
static void process_input_message(struct ndnd_handle *h, struct face *face,
                                  unsigned char *msg, size_t size, int pdu_ok);
static void process_input(struct ndnd_handle *h, int fd);
static int ndn_stuff_interest(struct ndnd_handle *h,
                              struct face *face, struct ndn_charbuf *c);
static void do_deferred_write(struct ndnd_handle *h, int fd);
static void clean_needed(struct ndnd_handle *h);
static struct face *get_dgram_source(struct ndnd_handle *h, struct face *face,
                                     struct sockaddr *addr, socklen_t addrlen,
                                     int why);
static void content_skiplist_insert(struct ndnd_handle *h,
                                    struct content_entry *content);
static void content_skiplist_remove(struct ndnd_handle *h,
                                    struct content_entry *content);
static void mark_stale(struct ndnd_handle *h,
                       struct content_entry *content);
static ndn_accession_t content_skiplist_next(struct ndnd_handle *h,
                                             struct content_entry *content);
static void reap_needed(struct ndnd_handle *h, int init_delay_usec);
static void check_comm_file(struct ndnd_handle *h);
static int nameprefix_seek(struct ndnd_handle *h,
                           struct hashtb_enumerator *e,
                           const unsigned char *msg,
                           struct ndn_indexbuf *comps,
                           int ncomps);
static void register_new_face(struct ndnd_handle *h, struct face *face);
static void update_forward_to(struct ndnd_handle *h,
                              struct nameprefix_entry *npe);
static void stuff_and_send(struct ndnd_handle *h, struct face *face,
                           const unsigned char *data1, size_t size1,
                           const unsigned char *data2, size_t size2,
                           const char *tag, int lineno);
static void ndn_link_state_init(struct ndnd_handle *h, struct face *face);
static void ndn_append_link_stuff(struct ndnd_handle *h,
                                  struct face *face,
                                  struct ndn_charbuf *c);
static int process_incoming_link_message(struct ndnd_handle *h,
                                         struct face *face, enum ndn_dtag dtag,
                                         unsigned char *msg, size_t size);
static void process_internal_client_buffer(struct ndnd_handle *h);
static int nonce_ok(struct ndnd_handle *h, struct face *face,
                    const unsigned char *interest_msg,
                    struct ndn_parsed_interest *pi,
                    const unsigned char *nonce, size_t noncesize);
static void
pfi_destroy(struct ndnd_handle *h, struct interest_entry *ie,
            struct pit_face_item *p);
static struct pit_face_item *
pfi_set_nonce(struct ndnd_handle *h, struct interest_entry *ie,
             struct pit_face_item *p,
             const unsigned char *nonce, size_t noncesize);
static int
pfi_nonce_matches(struct pit_face_item *p,
                  const unsigned char *nonce, size_t size);
static struct pit_face_item *
pfi_copy_nonce(struct ndnd_handle *h, struct interest_entry *ie,
             struct pit_face_item *p, const struct pit_face_item *src);
static int
pfi_unique_nonce(struct ndnd_handle *h, struct interest_entry *ie,
                 struct pit_face_item *p);
static int wt_compare(ndn_wrappedtime, ndn_wrappedtime);
static void
update_npe_children(struct ndnd_handle *h, struct nameprefix_entry *npe, unsigned faceid);
static void
pfi_set_expiry_from_lifetime(struct ndnd_handle *h, struct interest_entry *ie,
                             struct pit_face_item *p, intmax_t lifetime);
static void
pfi_set_expiry_from_micros(struct ndnd_handle *h, struct interest_entry *ie,
                           struct pit_face_item *p, unsigned micros);
static struct pit_face_item *
pfi_seek(struct ndnd_handle *h, struct interest_entry *ie,
         unsigned faceid, unsigned pfi_flag);
static void strategy_callout(struct ndnd_handle *h,
                             struct interest_entry *ie,
                             enum ndn_strategy_op op);

/**
 * Frequency of wrapped timer
 *
 * This should divide 1000000 evenly.  Making this too large reduces the
 * maximum supported interest lifetime, and making it too small makes the
 * timekeeping too coarse.
 */
#define WTHZ 500U

/**
 * Name of our unix-domain listener
 *
 * This tiny bit of global state is needed so that the unix-domain listener
 * can be removed at shutdown.
 */
static const char *unlink_this_at_exit = NULL;

static void
cleanup_at_exit(void)
{
    if (unlink_this_at_exit != NULL) {
        unlink(unlink_this_at_exit);
        unlink_this_at_exit = NULL;
    }
}

static void
handle_fatal_signal(int sig)
{
    cleanup_at_exit();
    _exit(sig);
}

/**
 * Record the name of the unix-domain listener
 *
 * Sets up signal handlers in case we are stopping due to a signal.
 */
static void
unlink_at_exit(const char *path)
{
    if (unlink_this_at_exit == NULL) {
        static char namstor[sizeof(struct sockaddr_un)];
        strncpy(namstor, path, sizeof(namstor));
        unlink_this_at_exit = namstor;
        signal(SIGTERM, &handle_fatal_signal);
        signal(SIGINT, &handle_fatal_signal);
        signal(SIGHUP, &handle_fatal_signal);
        atexit(&cleanup_at_exit);
    }
}

/**
 * Check to see if the unix-domain listener has been unlinked
 *
 * @returns 1 if the file is there, 0 if not.
 */
static int
comm_file_ok(void)
{
    struct stat statbuf;
    int res;
    if (unlink_this_at_exit == NULL)
        return(1);
    res = stat(unlink_this_at_exit, &statbuf);
    if (res == -1)
        return(0);
    return(1);
}

/**
 * Obtain a charbuf for short-term use
 */
static struct ndn_charbuf *
charbuf_obtain(struct ndnd_handle *h)
{
    struct ndn_charbuf *c = h->scratch_charbuf;
    if (c == NULL)
        return(ndn_charbuf_create());
    h->scratch_charbuf = NULL;
    c->length = 0;
    return(c);
}

/**
 * Release a charbuf for reuse
 */
static void
charbuf_release(struct ndnd_handle *h, struct ndn_charbuf *c)
{
    c->length = 0;
    if (h->scratch_charbuf == NULL)
        h->scratch_charbuf = c;
    else
        ndn_charbuf_destroy(&c);
}

/**
 * Obtain an indexbuf for short-term use
 */
static struct ndn_indexbuf *
indexbuf_obtain(struct ndnd_handle *h)
{
    struct ndn_indexbuf *c = h->scratch_indexbuf;
    if (c == NULL)
        return(ndn_indexbuf_create());
    h->scratch_indexbuf = NULL;
    c->n = 0;
    return(c);
}

/**
 * Release an indexbuf for reuse
 */
static void
indexbuf_release(struct ndnd_handle *h, struct ndn_indexbuf *c)
{
    c->n = 0;
    if (h->scratch_indexbuf == NULL)
        h->scratch_indexbuf = c;
    else
        ndn_indexbuf_destroy(&c);
}

/**
 * Looks up a face based on its faceid (private).
 */
static struct face *
face_from_faceid(struct ndnd_handle *h, unsigned faceid)
{
    unsigned slot = faceid & MAXFACES;
    struct face *face = NULL;
    if (slot < h->face_limit) {
        face = h->faces_by_faceid[slot];
        if (face != NULL && face->faceid != faceid)
            face = NULL;
    }
    return(face);
}

/**
 * Looks up a face based on its faceid.
 */
struct face *
ndnd_face_from_faceid(struct ndnd_handle *h, unsigned faceid)
{
    return(face_from_faceid(h, faceid));
}

/**
 * Assigns the faceid for a nacent face,
 * calls register_new_face() if successful.
 */
static int
enroll_face(struct ndnd_handle *h, struct face *face)
{
    unsigned i;
    unsigned n = h->face_limit;
    struct face **a = h->faces_by_faceid;
    for (i = h->face_rover; i < n; i++)
        if (a[i] == NULL) goto use_i;
    for (i = 0; i < n; i++)
        if (a[i] == NULL) {
            /* bump gen only if second pass succeeds */
            h->face_gen += MAXFACES + 1;
            goto use_i;
        }
    i = (n + 1) * 3 / 2;
    if (i > MAXFACES) i = MAXFACES;
    if (i <= n)
        return(-1); /* overflow */
    a = realloc(a, i * sizeof(struct face *));
    if (a == NULL)
        return(-1); /* ENOMEM */
    h->face_limit = i;
    while (--i > n)
        a[i] = NULL;
    h->faces_by_faceid = a;
use_i:
    a[i] = face;
    h->face_rover = i + 1;
    face->faceid = i | h->face_gen;
    face->meter[FM_BYTI] = ndnd_meter_create(h, "bytein");
    face->meter[FM_BYTO] = ndnd_meter_create(h, "byteout");
    face->meter[FM_INTI] = ndnd_meter_create(h, "intrin");
    face->meter[FM_INTO] = ndnd_meter_create(h, "introut");
    face->meter[FM_DATI] = ndnd_meter_create(h, "datain");
    face->meter[FM_DATO] = ndnd_meter_create(h, "dataout");
    register_new_face(h, face);
    return (face->faceid);
}

/**
 * Decide how much to delay the content sent out on a face.
 *
 * Units are microseconds. 
 */
static int
choose_face_delay(struct ndnd_handle *h, struct face *face, enum cq_delay_class c)
{
    int micros;
    int shift;
    
    if (c == NDN_CQ_ASAP)
        return(1);
    if ((face->flags & NDN_FACE_MCAST) != 0) {
        shift = (c == NDN_CQ_SLOW) ? 2 : 0;
        micros = (h->data_pause_microsec) << shift;
        return(micros); /* multicast, delay more */
    }
    return(1);
}

/**
 * Create a queue for sending content.
 */
static struct content_queue *
content_queue_create(struct ndnd_handle *h, struct face *face, enum cq_delay_class c)
{
    struct content_queue *q;
    unsigned usec;
    q = calloc(1, sizeof(*q));
    if (q != NULL) {
        usec = choose_face_delay(h, face, c);
        q->burst_nsec = (usec <= 500 ? 500 : 150000); // XXX - needs a knob
        q->min_usec = usec;
        q->rand_usec = 2 * usec;
        q->nrun = 0;
        q->send_queue = ndn_indexbuf_create();
        if (q->send_queue == NULL) {
            free(q);
            return(NULL);
        }
        q->sender = NULL;
    }
    return(q);
}

/**
 * Destroy a queue.
 */
static void
content_queue_destroy(struct ndnd_handle *h, struct content_queue **pq)
{
    struct content_queue *q;
    if (*pq != NULL) {
        q = *pq;
        ndn_indexbuf_destroy(&q->send_queue);
        if (q->sender != NULL) {
            ndn_schedule_cancel(h->sched, q->sender);
            q->sender = NULL;
        }
        free(q);
        *pq = NULL;
    }
}

/**
 * Close an open file descriptor quietly.
 */
static void
close_fd(int *pfd)
{
    if (*pfd != -1) {
        close(*pfd);
        *pfd = -1;
    }
}

/**
 * Close an open file descriptor, and grumble about it.
 */
static void
ndnd_close_fd(struct ndnd_handle *h, unsigned faceid, int *pfd)
{
    int res;
    
    if (*pfd != -1) {
        int linger = 0;
        setsockopt(*pfd, SOL_SOCKET, SO_LINGER,
                   &linger, sizeof(linger));
        res = close(*pfd);
        if (res == -1)
            ndnd_msg(h, "close failed for face %u fd=%d: %s (errno=%d)",
                     faceid, *pfd, strerror(errno), errno);
        else
            ndnd_msg(h, "closing fd %d while finalizing face %u", *pfd, faceid);
        *pfd = -1;
    }
}

/**
 * Associate a guid with a face.
 *
 * The same guid is shared among all the peers that communicate over the
 * face, and no two faces at a node should have the same guid.
 *
 * @returns 0 for success, -1 for error.
 */
int
ndnd_set_face_guid(struct ndnd_handle *h, struct face *face,
                   const unsigned char *guid, size_t size)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_charbuf *c = NULL;
    int res;
    
    if (size > 255)
        return(-1);
    if (face->guid != NULL)
        return(-1);
    if (h->faceid_by_guid == NULL)
        return(-1);
    c = ndn_charbuf_create();
    ndn_charbuf_append_value(c, size, 1);
    ndn_charbuf_append(c, guid, size);
    hashtb_start(h->faceid_by_guid, e);
    res = hashtb_seek(e, c->buf, c->length, 0);
    ndn_charbuf_destroy(&c);
    if (res < 0)
        return(-1);
    if (res == HT_NEW_ENTRY) {
        face->guid = e->key;
        *(unsigned *)(e->data) = face->faceid;
        res = 0;
    }
    else
        res = -1;
    hashtb_end(e);
    return(res);
}

/**
 * Return the faceid associated with the guid.
 */
unsigned
ndnd_faceid_from_guid(struct ndnd_handle *h,
                      const unsigned char *guid, size_t size)
{
    struct ndn_charbuf *c = NULL;
    unsigned *pfaceid = NULL;
    
    if (size > 255)
        return(NDN_NOFACEID);
    if (h->faceid_by_guid == NULL)
        return(NDN_NOFACEID);
    c = ndn_charbuf_create();
    ndn_charbuf_append_value(c, size, 1);
    ndn_charbuf_append(c, guid, size);
    pfaceid = hashtb_lookup(h->faceid_by_guid, c->buf, c->length);
    ndn_charbuf_destroy(&c);
    if (pfaceid == NULL)
        return(NDN_NOFACEID);
    return(*pfaceid);
}

/**
 * Append the guid associated with a face to a charbuf
 *
 * @returns the length of the appended guid, or -1 for error.
 */
int
ndnd_append_face_guid(struct ndnd_handle *h, struct ndn_charbuf *cb,
                      struct face *face)
{
    if (face == NULL || face->guid == NULL)
        return(-1);
    ndn_charbuf_append(cb, face->guid + 1, face->guid[0]);
    return(face->guid[0]);
}

/**
 * Forget the guid associated with a face.
 *
 * The first byte of face->guid is the length of the actual guid bytes.
 */
void
ndnd_forget_face_guid(struct ndnd_handle *h, struct face *face)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    const unsigned char *guid;
    int res;
    
    guid = face->guid;
    face->guid = NULL;
    ndn_charbuf_destroy(&face->guid_cob);
    if (guid == NULL)
        return;
    if (h->faceid_by_guid == NULL)
        return;
    hashtb_start(h->faceid_by_guid, e);
    res = hashtb_seek(e, guid, guid[0] + 1, 0);
    if (res < 0)
        return;
    hashtb_delete(e);
    hashtb_end(e);
}

/**
 * Generate a new guid for a face
 *
 * This guid is useful for routing agents, as it gives an unambiguous way
 * to talk about a connection between two nodes.
 *
 * lo and hi, if not NULL, are exclusive bounds for the generated guid.
 * The size is in bytes, and refers to both the bounds and the result.
 */
void
ndnd_generate_face_guid(struct ndnd_handle *h, struct face *face, int size,
                        const unsigned char *lo, const unsigned char *hi)
{
    int i;
    unsigned check = NDN_FACE_GG | NDN_FACE_UNDECIDED | NDN_FACE_PASSIVE;
    unsigned want = 0;
    uint_least64_t range;
    uint_least64_t r;
    struct ndn_charbuf *c = NULL;
    
    if ((face->flags & check) != want)
        return;
     /* XXX - This should be using higher-quality randomness */
    if (lo != NULL && hi != NULL) {
        /* Generate up to 64 additional random bits to augment guid */
        for (i = 0; i < size && lo[i] == hi[i];)
            i++;
        if (i == size || lo[i] > hi[i])
            return;
        if (size - i > sizeof(range))
            range = ~0;
        else {
            range = 0;
            for (; i < size; i++)
                range = (range << 8) + hi[i] - lo[i];
        }
        if (range < 2)
            return;
        c = ndn_charbuf_create();
        ndn_charbuf_append(c, lo, size);
        r = nrand48(h->seed);
        r = (r << 20) ^ nrand48(h->seed);
        r = (r << 20) ^ nrand48(h->seed);
        r = r % (range - 1) + 1;
        for (i = size - 1; r != 0 && i >= 0; i--) {
            r = r + c->buf[i];
            c->buf[i] = r & 0xff;
            r = r >> 8;
        }
    }
    else {
        for (i = 0; i < size; i++)
            ndn_charbuf_append_value(c, nrand48(h->seed) & 0xff, 1);
    }
    ndnd_set_face_guid(h, face, c->buf, c->length);
    ndn_charbuf_destroy(&c);
}

/**
 * Clean up when a face is being destroyed.
 *
 * This is called when an entry is deleted from one of the hash tables that
 * keep track of faces.
 */
static void
finalize_face(struct hashtb_enumerator *e)
{
    struct ndnd_handle *h = hashtb_get_param(e->ht, NULL);
    struct face *face = e->data;
    unsigned i = face->faceid & MAXFACES;
    enum cq_delay_class c;
    int recycle = 0;
    int m;
    
    if (i < h->face_limit && h->faces_by_faceid[i] == face) {
        if ((face->flags & NDN_FACE_UNDECIDED) == 0)
            ndnd_face_status_change(h, face->faceid);
        if (e->ht == h->faces_by_fd)
            ndnd_close_fd(h, face->faceid, &face->recv_fd);
        if ((face->guid) != NULL)
            ndnd_forget_face_guid(h, face);
        ndn_charbuf_destroy(&face->guid_cob);
        h->faces_by_faceid[i] = NULL;
        if ((face->flags & NDN_FACE_UNDECIDED) != 0 &&
              face->faceid == ((h->face_rover - 1) | h->face_gen)) {
            /* stream connection with no ndn traffic - safe to reuse */
            recycle = 1;
            h->face_rover--;
        }
        for (c = 0; c < NDN_CQ_N; c++)
            content_queue_destroy(h, &(face->q[c]));
        ndn_charbuf_destroy(&face->inbuf);
        ndn_charbuf_destroy(&face->outbuf);
        ndnd_msg(h, "%s face id %u (slot %u)",
            recycle ? "recycling" : "releasing",
            face->faceid, face->faceid & MAXFACES);
        /* Don't free face->addr; storage is managed by hash table */
    }
    else if (face->faceid != NDN_NOFACEID)
        ndnd_msg(h, "orphaned face %u", face->faceid);
    for (m = 0; m < NDND_FACE_METER_N; m++)
        ndnd_meter_destroy(&face->meter[m]);
}

/**
 * Convert an accession to its associated content handle.
 *
 * @returns content handle, or NULL if it is no longer available.
 */
static struct content_entry *
content_from_accession(struct ndnd_handle *h, ndn_accession_t accession)
{
    struct content_entry *ans = NULL;
    if (accession < h->accession_base) {
        struct sparse_straggler_entry *entry;
        entry = hashtb_lookup(h->sparse_straggler_tab,
                              &accession, sizeof(accession));
        if (entry != NULL)
            ans = entry->content;
    }
    else if (accession < h->accession_base + h->content_by_accession_window) {
        ans = h->content_by_accession[accession - h->accession_base];
        if (ans != NULL && ans->accession != accession)
            ans = NULL;
    }
    return(ans);
}

/**
 *  Sweep old entries out of the direct accession-to-content table
 */
static void
cleanout_stragglers(struct ndnd_handle *h)
{
    ndn_accession_t accession;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct sparse_straggler_entry *entry = NULL;
    struct content_entry **a = h->content_by_accession;
    unsigned n_direct;
    unsigned n_occupied;
    unsigned window;
    unsigned i;
    if (h->accession <= h->accession_base || a[0] == NULL)
        return;
    n_direct = h->accession - h->accession_base;
    if (n_direct < 1000)
        return;
    n_occupied = hashtb_n(h->content_tab) - hashtb_n(h->sparse_straggler_tab);
    if (n_occupied >= (n_direct / 8))
        return;
    /* The direct lookup table is too sparse, so sweep stragglers */
    hashtb_start(h->sparse_straggler_tab, e);
    window = h->content_by_accession_window;
    for (i = 0; i < window; i++) {
        if (a[i] != NULL) {
            if (n_occupied >= ((window - i) / 8))
                break;
            accession = h->accession_base + i;
            hashtb_seek(e, &accession, sizeof(accession), 0);
            entry = e->data;
            if (entry != NULL && entry->content == NULL) {
                entry->content = a[i];
                a[i] = NULL;
                n_occupied -= 1;
            }
        }
    }
    hashtb_end(e);
}

/**
 *  Prevent the direct accession-to-content table from becoming too sparse
 */
static int
cleanout_empties(struct ndnd_handle *h)
{
    unsigned i = 0;
    unsigned j = 0;
    struct content_entry **a = h->content_by_accession;
    unsigned window = h->content_by_accession_window;
    if (a == NULL)
        return(-1);
    cleanout_stragglers(h);
    while (i < window && a[i] == NULL)
        i++;
    if (i == 0)
        return(-1);
    h->accession_base += i;
    while (i < window)
        a[j++] = a[i++];
    while (j < window)
        a[j++] = NULL;
    return(0);
}

/**
 * Assign an accession number to a content object
 */
static void
enroll_content(struct ndnd_handle *h, struct content_entry *content)
{
    unsigned new_window;
    struct content_entry **new_array;
    struct content_entry **old_array;
    unsigned i = 0;
    unsigned j = 0;
    unsigned window = h->content_by_accession_window;
    if ((content->accession - h->accession_base) >= window &&
          cleanout_empties(h) < 0) {
        if (content->accession < h->accession_base)
            return;
        window = h->content_by_accession_window;
        old_array = h->content_by_accession;
        new_window = ((window + 20) * 3 / 2);
        if (new_window < window)
            return;
        new_array = calloc(new_window, sizeof(new_array[0]));
        if (new_array == NULL)
            return;
        while (i < h->content_by_accession_window && old_array[i] == NULL)
            i++;
        h->accession_base += i;
        h->content_by_accession = new_array;
        while (i < h->content_by_accession_window)
            new_array[j++] = old_array[i++];
        h->content_by_accession_window = new_window;
    free(old_array);
    }
    h->content_by_accession[content->accession - h->accession_base] = content;
}

// the hash table this is for is going away
static void
finalize_content(struct hashtb_enumerator *content_enumerator)
{
    struct ndnd_handle *h = hashtb_get_param(content_enumerator->ht, NULL);
    struct content_entry *entry = content_enumerator->data;
    unsigned i = entry->accession - h->accession_base;
    if (i < h->content_by_accession_window &&
          h->content_by_accession[i] == entry) {
        content_skiplist_remove(h, entry);
        h->content_by_accession[i] = NULL;
    }
    else {
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;
        hashtb_start(h->sparse_straggler_tab, e);
        if (hashtb_seek(e, &entry->accession, sizeof(entry->accession), 0) ==
              HT_NEW_ENTRY) {
            ndnd_msg(h, "orphaned content %llu",
                     (unsigned long long)(entry->accession));
            hashtb_delete(e);
            hashtb_end(e);
            return;
        }
        content_skiplist_remove(h, entry);
        hashtb_delete(e);
        hashtb_end(e);
    }
    if (entry->comps != NULL) {
        free(entry->comps);
        entry->comps = NULL;
    }
}

/**
 * Find the skiplist entries associated with the key.
 *
 * @returns the number of entries of ans that were filled in.
 */
static int
content_skiplist_findbefore(struct ndnd_handle *h,
                            const unsigned char *key,
                            size_t keysize,
                            struct content_entry *wanted_old,
                            struct ndn_indexbuf **ans)
{
    int i;
    int n = h->skiplinks->n;
    struct ndn_indexbuf *c;
    struct content_entry *content;
    int order;
    size_t start;
    size_t end;
    
    c = h->skiplinks;
    for (i = n - 1; i >= 0; i--) {
        for (;;) {
            if (c->buf[i] == 0)
                break;
            content = content_from_accession(h, c->buf[i]);
            if (content == NULL)
                abort();
            start = content->comps[0];
            end = content->comps[content->ncomps - 1];
            order = ndn_compare_names(content->key + start - 1, end - start + 2,
                                      key, keysize);
            if (order > 0)
                break;
            if (order == 0 && (wanted_old == content || wanted_old == NULL))
                break;
            if (content->skiplinks == NULL || i >= content->skiplinks->n)
                abort();
            c = content->skiplinks;
        }
        ans[i] = c;
    }
    return(n);
}

/**
 * Limit for how deep our skiplists can be
 */
#define NDN_SKIPLIST_MAX_DEPTH 30

/**
 * Insert a new entry into the skiplist.
 */
static void
content_skiplist_insert(struct ndnd_handle *h, struct content_entry *content)
{
    int d;
    int i;
    size_t start;
    size_t end;
    struct ndn_indexbuf *pred[NDN_SKIPLIST_MAX_DEPTH] = {NULL};
    if (content->skiplinks != NULL) abort();
    for (d = 1; d < NDN_SKIPLIST_MAX_DEPTH - 1; d++)
        if ((nrand48(h->seed) & 3) != 0) break;
    while (h->skiplinks->n < d)
        ndn_indexbuf_append_element(h->skiplinks, 0);
    start = content->comps[0];
    end = content->comps[content->ncomps - 1];
    i = content_skiplist_findbefore(h,
                                    content->key + start - 1,
                                    end - start + 2, NULL, pred);
    if (i < d)
        d = i; /* just in case */
    content->skiplinks = ndn_indexbuf_create();
    for (i = 0; i < d; i++) {
        ndn_indexbuf_append_element(content->skiplinks, pred[i]->buf[i]);
        pred[i]->buf[i] = content->accession;
    }
}

/**
 * Remove an entry from the skiplist.
 */
static void
content_skiplist_remove(struct ndnd_handle *h, struct content_entry *content)
{
    int i;
    int d;
    size_t start;
    size_t end;
    struct ndn_indexbuf *pred[NDN_SKIPLIST_MAX_DEPTH] = {NULL};
    if (content->skiplinks == NULL) abort();
    start = content->comps[0];
    end = content->comps[content->ncomps - 1];
    d = content_skiplist_findbefore(h,
                                    content->key + start - 1,
                                    end - start + 2, content, pred);
    if (d > content->skiplinks->n)
        d = content->skiplinks->n;
    for (i = 0; i < d; i++) {
        pred[i]->buf[i] = content->skiplinks->buf[i];
    }
    ndn_indexbuf_destroy(&content->skiplinks);
}

/**
 * Find the first candidate that might match the given interest.
 */
static struct content_entry *
find_first_match_candidate(struct ndnd_handle *h,
                           const unsigned char *interest_msg,
                           const struct ndn_parsed_interest *pi)
{
    int res;
    struct ndn_indexbuf *pred[NDN_SKIPLIST_MAX_DEPTH] = {NULL};
    size_t start = pi->offset[NDN_PI_B_Name];
    size_t end = pi->offset[NDN_PI_E_Name];
    struct ndn_charbuf *namebuf = NULL;
    if (pi->offset[NDN_PI_B_Exclude] < pi->offset[NDN_PI_E_Exclude]) {
        /* Check for <Exclude><Any/><Component>... fast case */
        struct ndn_buf_decoder decoder;
        struct ndn_buf_decoder *d;
        size_t ex1start;
        size_t ex1end;
        d = ndn_buf_decoder_start(&decoder,
                                  interest_msg + pi->offset[NDN_PI_B_Exclude],
                                  pi->offset[NDN_PI_E_Exclude] -
                                  pi->offset[NDN_PI_B_Exclude]);
        ndn_buf_advance(d);
        if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
            ndn_buf_advance(d);
            ndn_buf_check_close(d);
            if (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
                ex1start = pi->offset[NDN_PI_B_Exclude] + d->decoder.token_index;
                ndn_buf_advance_past_element(d);
                ex1end = pi->offset[NDN_PI_B_Exclude] + d->decoder.token_index;
                if (d->decoder.state >= 0) {
                    namebuf = ndn_charbuf_create();
                    ndn_charbuf_append(namebuf,
                                       interest_msg + start,
                                       end - start);
                    namebuf->length--;
                    ndn_charbuf_append(namebuf,
                                       interest_msg + ex1start,
                                       ex1end - ex1start);
                    ndn_charbuf_append_closer(namebuf);
                    if (h->debug & 8)
                        ndnd_debug_ndnb(h, __LINE__, "fastex", NULL,
                                        namebuf->buf, namebuf->length);
                }
            }
        }
    }
    if (namebuf == NULL) {
        res = content_skiplist_findbefore(h, interest_msg + start, end - start,
                                          NULL, pred);
    }
    else {
        res = content_skiplist_findbefore(h, namebuf->buf, namebuf->length,
                                          NULL, pred);
        ndn_charbuf_destroy(&namebuf);
    }
    if (res == 0)
        return(NULL);
    return(content_from_accession(h, pred[0]->buf[0]));
}

/**
 * Check for a prefix match.
 */
static int
content_matches_interest_prefix(struct ndnd_handle *h,
                                struct content_entry *content,
                                const unsigned char *interest_msg,
                                struct ndn_indexbuf *comps,
                                int prefix_comps)
{
    size_t prefixlen;
    if (prefix_comps < 0 || prefix_comps >= comps->n)
        abort();
    /* First verify the prefix match. */
    if (content->ncomps < prefix_comps + 1)
            return(0);
    prefixlen = comps->buf[prefix_comps] - comps->buf[0];
    if (content->comps[prefix_comps] - content->comps[0] != prefixlen)
        return(0);
    if (0 != memcmp(content->key + content->comps[0],
                    interest_msg + comps->buf[0],
                    prefixlen))
        return(0);
    return(1);
}

/**
 * Advance to the next entry in the skiplist.
 */
static ndn_accession_t
content_skiplist_next(struct ndnd_handle *h, struct content_entry *content)
{
    if (content == NULL)
        return(0);
    if (content->skiplinks == NULL || content->skiplinks->n < 1)
        return(0);
    return(content->skiplinks->buf[0]);
}

/**
 * Consume an interest.
 */
static void
consume_interest(struct ndnd_handle *h, struct interest_entry *ie)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int res;
    
    hashtb_start(h->interest_tab, e);
    res = hashtb_seek(e, ie->interest_msg, ie->size - 1, 1);
    if (res != HT_OLD_ENTRY)
        abort();
    hashtb_delete(e);
    hashtb_end(e);
}    

/**
 * Clean up a name prefix entry when it is removed from the hash table.
 */
static void
finalize_nameprefix(struct hashtb_enumerator *e)
{
    struct ndnd_handle *h = hashtb_get_param(e->ht, NULL);
    struct nameprefix_entry *npe = e->data;
    struct ielinks *head = &npe->ie_head;
    if (head->next != NULL) {
        while (head->next != head)
            consume_interest(h, (struct interest_entry *)(head->next));
    }
    ndn_indexbuf_destroy(&npe->forward_to);
    ndn_indexbuf_destroy(&npe->tap);
    while (npe->forwarding != NULL) {
        struct ndn_forwarding *f = npe->forwarding;
        npe->forwarding = f->next;
        free(f);
    }
}

/**
 * Link an interest to its name prefix entry.
 */
static void
link_interest_entry_to_nameprefix(struct ndnd_handle *h,
    struct interest_entry *ie, struct nameprefix_entry *npe)
{
    struct ielinks *head = &npe->ie_head;
    struct ielinks *ll = &ie->ll;
    ll->next = head;
    ll->prev = head->prev;
    ll->prev->next = ll->next->prev = ll;
    ll->npe = npe;
}

/**
 * Clean up an interest_entry when it is removed from its hash table.
 */
static void
finalize_interest(struct hashtb_enumerator *e)
{
    struct pit_face_item *p = NULL;
    struct pit_face_item *next = NULL;
    struct ndnd_handle *h = hashtb_get_param(e->ht, NULL);
    struct interest_entry *ie = e->data;
    struct face *face = NULL;

    if (ie->ev != NULL)
        ndn_schedule_cancel(h->sched, ie->ev);
    if (ie->strategy.ev != NULL)
        ndn_schedule_cancel(h->sched, ie->strategy.ev);
    if (ie->ll.next != NULL) {
        ie->ll.next->prev = ie->ll.prev;
        ie->ll.prev->next = ie->ll.next;
        ie->ll.next = ie->ll.prev = NULL;
        ie->ll.npe = NULL;
    }
    for (p = ie->pfl; p != NULL; p = next) {
        next = p->next;
        if ((p->pfi_flags & NDND_PFI_PENDING) != 0) {
            face = face_from_faceid(h, p->faceid);
            if (face != NULL)
                face->pending_interests -= 1;
        }
        free(p);
    }
    ie->pfl = NULL;
    ie->interest_msg = NULL; /* part of hashtb, don't free this */
}

/**
 *  Look for duplication of interest nonces
 *
 * If nonce is NULL and the interest message has a nonce, the latter will
 * be used.
 *
 * The nonce will be added to the nonce table if it is not already there.
 * Some expired entries may be trimmed.
 *
 * @returns 0 if a duplicate, unexpired nonce exists, 1 if nonce is new,
 *          2 if duplicate is from originating face, or 3 if the interest
 *          does not have a nonce.  Negative means error.
 */
static int
nonce_ok(struct ndnd_handle *h, struct face *face,
         const unsigned char *interest_msg, struct ndn_parsed_interest *pi,
         const unsigned char *nonce, size_t noncesize)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct nonce_entry *nce = NULL;
    int res;
    int i;
    
    if (nonce == NULL) {
        nonce = interest_msg + pi->offset[NDN_PI_B_Nonce];
        noncesize = pi->offset[NDN_PI_E_Nonce] - pi->offset[NDN_PI_B_Nonce];
        if (noncesize == 0)
            return(3);
        ndn_ref_tagged_BLOB(NDN_DTAG_Nonce, interest_msg,
                            pi->offset[NDN_PI_B_Nonce],
                            pi->offset[NDN_PI_E_Nonce],
                            &nonce, &noncesize);
    }
    hashtb_start(h->nonce_tab, e);
    /* Remove a few expired nonces */
    for (i = 0; i < 10; i++) {
        if (h->ncehead.next == &h->ncehead)
            break;
        nce = (void *)h->ncehead.next;
        if (wt_compare(nce->expiry, h->wtnow) >= 0)
            break;
        res = hashtb_seek(e, nce->key, nce->size, 0);
        if (res != HT_OLD_ENTRY) abort();
        hashtb_delete(e);
    }
    /* Look up or add the given nonce */
    res = hashtb_seek(e, nonce, noncesize, 0);
    if (res < 0)
        return(res);
    nce = e->data;
    if (res == HT_NEW_ENTRY) {
        nce->ll.next = NULL;
        nce->faceid = (face != NULL) ? face->faceid : NDN_NO_FACEID;
        nce->key = e->key;
        nce->size = e->keysize;
        res = 1;
    }
    else if (face != NULL && face->faceid == nce->faceid) {
        /* From same face as before, count as a refresh */
        res = 2;
    }
    else {
        if (wt_compare(nce->expiry, h->wtnow) < 0)
            res = 1; /* nonce's expiry has passed, count as new */
        else
            res = 0; /* nonce is duplicate */
    }
    /* Re-insert it at the end of the expiry queue */
    if (nce->ll.next != NULL) {
        nce->ll.next->prev = nce->ll.prev;
        nce->ll.prev->next = nce->ll.next;
        nce->ll.next = nce->ll.prev = NULL;
    }
    nce->ll.next = &h->ncehead;
    nce->ll.prev = h->ncehead.prev;
    nce->ll.next->prev = nce->ll.prev->next = &nce->ll;
    nce->expiry = h->wtnow + 6 * WTHZ; // XXX hardcoded 6 seconds
    hashtb_end(e);
    return(res);
}

/**
 * Clean up a nonce_entry when it is removed from its hash table.
 */
static void
finalize_nonce(struct hashtb_enumerator *e)
{
    struct nonce_entry *nce = e->data;
    
    /* If this entry is in the expiry queue, remove it. */
    if (nce->ll.next != NULL) {
        nce->ll.next->prev = nce->ll.prev;
        nce->ll.prev->next = nce->ll.next;
        nce->ll.next = nce->ll.prev = NULL;
    }
}

/**
 * Clean up a guest_entry when it is removed from its hash table.
 */
static void
finalize_guest(struct hashtb_enumerator *e)
{
    struct guest_entry *g = e->data;
    ndn_charbuf_destroy(&g->cob);
}

/**
 * Create a listener on a unix-domain socket.
 */
static int
create_local_listener(struct ndnd_handle *h, const char *sockname, int backlog)
{
    int res;
    int savedmask;
    int sock;
    struct sockaddr_un a = { 0 };
    res = unlink(sockname);
    if (res == 0) {
        ndnd_msg(NULL, "unlinked old %s, please wait", sockname);
        sleep(9); /* give old ndnd a chance to exit */
    }
    if (!(res == 0 || errno == ENOENT))
        ndnd_msg(NULL, "failed to unlink %s", sockname);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, sockname, sizeof(a.sun_path));
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
        return(sock);
    savedmask = umask(0111); /* socket should be R/W by anybody */
    res = bind(sock, (struct sockaddr *)&a, sizeof(a));
    umask(savedmask);
    if (res == -1) {
        close(sock);
        return(-1);
    }
    unlink_at_exit(sockname);
    res = listen(sock, backlog);
    if (res == -1) {
        close(sock);
        return(-1);
    }
    record_connection(h, sock, (struct sockaddr *)&a, sizeof(a),
                      (NDN_FACE_LOCAL | NDN_FACE_PASSIVE));
    return(sock);
}

/**
 * Adjust socket buffer limit
 */
static int
establish_min_recv_bufsize(struct ndnd_handle *h, int fd, int minsize)
{
    int res;
    int rcvbuf;
    socklen_t rcvbuf_sz;

    rcvbuf_sz = sizeof(rcvbuf);
    res = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbuf_sz);
    if (res == -1)
        return (res);
    if (rcvbuf < minsize) {
        rcvbuf = minsize;
        res = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        if (res == -1)
            return(res);
    }
    ndnd_msg(h, "SO_RCVBUF for fd %d is %d", fd, rcvbuf);
    return(rcvbuf);
}

/**
 * Initialize the face flags based upon the addr information
 * and the provided explicit setflags.
 */
static void
init_face_flags(struct ndnd_handle *h, struct face *face, int setflags)
{
    const struct sockaddr *addr = face->addr;
    const unsigned char *rawaddr = NULL;
    
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        face->flags |= NDN_FACE_INET6;
#ifdef IN6_IS_ADDR_LOOPBACK
        if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr))
            face->flags |= NDN_FACE_LOOPBACK;
#endif
    }
    else if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        rawaddr = (const unsigned char *)&addr4->sin_addr.s_addr;
        face->flags |= NDN_FACE_INET;
        if (rawaddr[0] == 127)
            face->flags |= NDN_FACE_LOOPBACK;
        else {
            /* If our side and the peer have the same address, consider it loopback */
            /* This is the situation inside of FreeBSD jail. */
            struct sockaddr_in myaddr;
            socklen_t myaddrlen = sizeof(myaddr);
            if (0 == getsockname(face->recv_fd, (struct sockaddr *)&myaddr, &myaddrlen)) {
                if (addr4->sin_addr.s_addr == myaddr.sin_addr.s_addr)
                    face->flags |= NDN_FACE_LOOPBACK;
            }
        }
    }
    else if (addr->sa_family == AF_UNIX)
        face->flags |= (NDN_FACE_GG | NDN_FACE_LOCAL);
    face->flags |= setflags;
}

/**
 * Make a new face entered in the faces_by_fd table.
 */
static struct face *
record_connection(struct ndnd_handle *h, int fd,
                  struct sockaddr *who, socklen_t wholen,
                  int setflags)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int res;
    struct face *face = NULL;
    unsigned char *addrspace;
    
    res = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (res == -1)
        ndnd_msg(h, "fcntl: %s", strerror(errno));
    hashtb_start(h->faces_by_fd, e);
    if (hashtb_seek(e, &fd, sizeof(fd), wholen) == HT_NEW_ENTRY) {
        face = e->data;
        face->recv_fd = fd;
        face->sendface = NDN_NOFACEID;
        face->addrlen = e->extsize;
        addrspace = ((unsigned char *)e->key) + e->keysize;
        face->addr = (struct sockaddr *)addrspace;
        memcpy(addrspace, who, e->extsize);
        init_face_flags(h, face, setflags);
        res = enroll_face(h, face);
        if (res == -1) {
            hashtb_delete(e);
            face = NULL;
        }
    }
    hashtb_end(e);
    return(face);
}

/**
 * Accept an incoming SOCK_STREAM connection, creating a new face.
 *
 * This could be, for example, a unix-domain socket, or TCP.
 *
 * @returns fd of new socket, or -1 for an error.
 */
static int
accept_connection(struct ndnd_handle *h, int listener_fd)
{
    struct sockaddr_storage who;
    socklen_t wholen = sizeof(who);
    int fd;
    struct face *face;

    fd = accept(listener_fd, (struct sockaddr *)&who, &wholen);
    if (fd == -1) {
        ndnd_msg(h, "accept: %s", strerror(errno));
        return(-1);
    }
    face = record_connection(h, fd,
                            (struct sockaddr *)&who, wholen,
                            NDN_FACE_UNDECIDED);
    if (face == NULL)
        close_fd(&fd);
    else
        ndnd_msg(h, "accepted client fd=%d id=%u", fd, face->faceid);
    return(fd);
}

/**
 * Make an outbound stream connection.
 */
static struct face *
make_connection(struct ndnd_handle *h,
                struct sockaddr *who, socklen_t wholen,
                int setflags)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int fd;
    int res;
    struct face *face;
    const int checkflags = NDN_FACE_LINK | NDN_FACE_DGRAM | NDN_FACE_LOCAL |
                           NDN_FACE_NOSEND | NDN_FACE_UNDECIDED;
    const int wantflags = 0;
    
    /* Check for an existing usable connection */
    for (hashtb_start(h->faces_by_fd, e); e->data != NULL; hashtb_next(e)) {
        face = e->data;
        if (face->addr != NULL && face->addrlen == wholen &&
            ((face->flags & checkflags) == wantflags) &&
            0 == memcmp(face->addr, who, wholen)) {
            hashtb_end(e);
            return(face);
        }
    }
    face = NULL;
    hashtb_end(e);
    /* No existing connection, try to make a new one. */
    fd = socket(who->sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        ndnd_msg(h, "socket: %s", strerror(errno));
        return(NULL);
    }
    res = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (res == -1)
        ndnd_msg(h, "connect fcntl: %s", strerror(errno));
    setflags &= ~NDN_FACE_CONNECTING;
    res = connect(fd, who, wholen);
    if (res == -1 && errno == EINPROGRESS) {
        res = 0;
        setflags |= NDN_FACE_CONNECTING;
    }
    if (res == -1) {
        ndnd_msg(h, "connect failed: %s (errno = %d)", strerror(errno), errno);
        close(fd);
        return(NULL);
    }
    face = record_connection(h, fd, who, wholen, setflags);
    if (face == NULL) {
        close(fd);
        return(NULL);
    }
    if ((face->flags & NDN_FACE_CONNECTING) != 0) {
        ndnd_msg(h, "connecting to client fd=%d id=%u", fd, face->faceid);
        face->outbufindex = 0;
        face->outbuf = ndn_charbuf_create();
    }
    else
        ndnd_msg(h, "connected client fd=%d id=%u", fd, face->faceid);
    return(face);
}

/**
 * Get a bound datagram socket.
 *
 * This is handed to ndn_setup_socket() when setting up a multicast face.
 */
static int
ndnd_getboundsocket(void *dat, struct sockaddr *who, socklen_t wholen)
{
    struct ndnd_handle *h = dat;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int yes = 1;
    int res;
    int ans = -1;
    int wantflags = (NDN_FACE_DGRAM | NDN_FACE_PASSIVE);
    for (hashtb_start(h->faces_by_fd, e); e->data != NULL; hashtb_next(e)) {
        struct face *face = e->data;
        if ((face->flags & wantflags) == wantflags &&
              wholen == face->addrlen &&
              0 == memcmp(who, face->addr, wholen)) {
            ans = face->recv_fd;
            break;
        }
    }
    hashtb_end(e);
    if (ans != -1)
        return(ans);
    ans = socket(who->sa_family, SOCK_DGRAM, 0);
    if (ans == -1)
        return(ans);
    setsockopt(ans, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    res = bind(ans, who, wholen);
    if (res == -1) {
        ndnd_msg(h, "bind failed: %s (errno = %d)", strerror(errno), errno);
        close(ans);
        return(-1);
    }
    record_connection(h, ans, who, wholen,
                      NDN_FACE_DGRAM | NDN_FACE_PASSIVE | NDN_FACE_NORECV);
    return(ans);
}

/**
 * Get the faceid associated with a file descriptor.
 *
 * @returns the faceid, or NDN_NOFACEID.
 */
static unsigned
faceid_from_fd(struct ndnd_handle *h, int fd)
{
    struct face *face = hashtb_lookup(h->faces_by_fd, &fd, sizeof(fd));
    if (face != NULL)
        return(face->faceid);
    return(NDN_NOFACEID);
}

typedef void (*loggerproc)(void *, const char *, ...);

/**
 * Set up a multicast face.
 */
static struct face *
setup_multicast(struct ndnd_handle *h, struct ndn_face_instance *face_instance,
                struct sockaddr *who, socklen_t wholen)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_sockets socks = { -1, -1 };
    int res;
    struct face *face = NULL;
    const int checkflags = NDN_FACE_LINK | NDN_FACE_DGRAM | NDN_FACE_MCAST |
                           NDN_FACE_LOCAL | NDN_FACE_NOSEND;
    const int wantflags = NDN_FACE_DGRAM | NDN_FACE_MCAST;

    /* See if one is already active */
    // XXX - should also compare and record additional mcast props.
    for (hashtb_start(h->faces_by_fd, e); e->data != NULL; hashtb_next(e)) {
        face = e->data;
        if (face->addr != NULL && face->addrlen == wholen &&
            ((face->flags & checkflags) == wantflags) &&
            0 == memcmp(face->addr, who, wholen)) {
            hashtb_end(e);
            return(face);
        }
    }
    face = NULL;
    hashtb_end(e);
    
    res = ndn_setup_socket(&face_instance->descr,
                           (loggerproc)&ndnd_msg, (void *)h,
                           &ndnd_getboundsocket, (void *)h,
                           &socks);
    if (res < 0)
        return(NULL);
    establish_min_recv_bufsize(h, socks.recving, 128*1024);
    face = record_connection(h, socks.recving, who, wholen,
                             (NDN_FACE_MCAST | NDN_FACE_DGRAM));
    if (face == NULL) {
        close(socks.recving);
        if (socks.sending != socks.recving)
            close(socks.sending); // XXX - could be problematic, but record_connection is unlikely to fail for other than ENOMEM
        return(NULL);
    }
    face->sendface = faceid_from_fd(h, socks.sending);
    ndnd_msg(h, "multicast on fd=%d id=%u, sending on face %u",
             face->recv_fd, face->faceid, face->sendface);
    return(face);
}

/**
 * Close a socket, destroying the associated face.
 */
static void
shutdown_client_fd(struct ndnd_handle *h, int fd)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct face *face = NULL;
    unsigned faceid = NDN_NOFACEID;
    hashtb_start(h->faces_by_fd, e);
    if (hashtb_seek(e, &fd, sizeof(fd), 0) == HT_OLD_ENTRY) {
        face = e->data;
        if (face->recv_fd != fd) abort();
        faceid = face->faceid;
        if (faceid == NDN_NOFACEID) {
            ndnd_msg(h, "error indication on fd %d ignored", fd);
            hashtb_end(e);
            return;
        }
        close(fd);
        face->recv_fd = -1;
        ndnd_msg(h, "shutdown client fd=%d id=%u", fd, faceid);
        ndn_charbuf_destroy(&face->inbuf);
        ndn_charbuf_destroy(&face->outbuf);
        face = NULL;
    }
    hashtb_delete(e);
    hashtb_end(e);
    check_comm_file(h);
}

/**
 * Send a ContentObject
 *
 * This is after it has worked its way through the queue; update the meters
 * and stuff the packet as appropriate.
 */
static void
send_content(struct ndnd_handle *h, struct face *face, struct content_entry *content)
{
    int n, a, b, size;
    if ((face->flags & NDN_FACE_NOSEND) != 0) {
        // XXX - should count this.
        return;
    }
    size = content->size;
    if (h->debug & 4)
        ndnd_debug_ndnb(h, __LINE__, "content_to", face,
                        content->key, size);
    /* Excise the message-digest name component */
    n = content->ncomps;
    if (n < 2) abort();
    a = content->comps[n - 2];
    b = content->comps[n - 1];
    if (b - a != 36)
        abort(); /* strange digest length */
    stuff_and_send(h, face, content->key, a, content->key + b, size - b, 0, 0);
    ndnd_meter_bump(h, face->meter[FM_DATO], 1);
    h->content_items_sent += 1;
}

/**
 * Select the output queue class for a piece of content
 */
static enum cq_delay_class
choose_content_delay_class(struct ndnd_handle *h, unsigned faceid, int content_flags)
{
    struct face *face = face_from_faceid(h, faceid);
    if (face == NULL)
        return(NDN_CQ_ASAP); /* Going nowhere, get it over with */
    if ((face->flags & (NDN_FACE_LINK | NDN_FACE_MCAST)) != 0) /* udplink or such, delay more */
        return((content_flags & NDN_CONTENT_ENTRY_SLOWSEND) ? NDN_CQ_SLOW : NDN_CQ_NORMAL);
    if ((face->flags & NDN_FACE_DGRAM) != 0)
        return(NDN_CQ_NORMAL); /* udp, delay just a little */
    if ((face->flags & (NDN_FACE_GG | NDN_FACE_LOCAL)) != 0)
        return(NDN_CQ_ASAP); /* localhost, answer quickly */
    return(NDN_CQ_NORMAL); /* default */
}

/**
 * Pick a randomized delay for sending
 *
 * This is primarily for multicast and similar broadcast situations, where we
 * may see the content being sent by somebody else.  If that is the case,
 * we will avoid sending our copy as well.
 *
 */
static unsigned
randomize_content_delay(struct ndnd_handle *h, struct content_queue *q)
{
    unsigned usec;
    
    usec = q->min_usec + q->rand_usec;
    if (usec < 2)
        return(1);
    if (usec <= 20 || q->rand_usec < 2) // XXX - what is a good value for this?
        return(usec); /* small value, don't bother to randomize */
    usec = q->min_usec + (nrand48(h->seed) % q->rand_usec);
    if (usec < 2)
        return(1);
    return(usec);
}

/**
 * Scheduled event for sending from a queue.
 */
static int
content_sender(struct ndn_schedule *sched,
    void *clienth,
    struct ndn_scheduled_event *ev,
    int flags)
{
    int i, j;
    int delay;
    int nsec;
    int burst_nsec;
    int burst_max;
    struct ndnd_handle *h = clienth;
    struct content_entry *content = NULL;
    unsigned faceid = ev->evint;
    struct face *face = NULL;
    struct content_queue *q = ev->evdata;
    (void)sched;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        goto Bail;
    face = face_from_faceid(h, faceid);
    if (face == NULL)
        goto Bail;
    if (q->send_queue == NULL)
        goto Bail;
    if ((face->flags & NDN_FACE_NOSEND) != 0)
        goto Bail;
    /* Send the content at the head of the queue */
    if (q->ready > q->send_queue->n ||
        (q->ready == 0 && q->nrun >= 12 && q->nrun < 120))
        q->ready = q->send_queue->n;
    nsec = 0;
    burst_nsec = q->burst_nsec;
    burst_max = 2;
    if (q->ready < burst_max)
        burst_max = q->ready;
    if (burst_max == 0)
        q->nrun = 0;
    for (i = 0; i < burst_max && nsec < 1000000; i++) {
        content = content_from_accession(h, q->send_queue->buf[i]);
        if (content == NULL)
            q->nrun = 0;
        else {
            send_content(h, face, content);
            /* face may have vanished, bail out if it did */
            if (face_from_faceid(h, faceid) == NULL)
                goto Bail;
            nsec += burst_nsec * (unsigned)((content->size + 1023) / 1024);
            q->nrun++;
        }
    }
    if (q->ready < i) abort();
    q->ready -= i;
    /* Update queue */
    for (j = 0; i < q->send_queue->n; i++, j++)
        q->send_queue->buf[j] = q->send_queue->buf[i];
    q->send_queue->n = j;
    /* Do a poll before going on to allow others to preempt send. */
    delay = (nsec + 499) / 1000 + 1;
    if (q->ready > 0) {
        if (h->debug & 8)
            ndnd_msg(h, "face %u ready %u delay %i nrun %u",
                     faceid, q->ready, delay, q->nrun, face->surplus);
        return(delay);
    }
    q->ready = j;
    if (q->nrun >= 12 && q->nrun < 120) {
        /* We seem to be a preferred provider, forgo the randomized delay */
        if (j == 0)
            delay += burst_nsec / 50;
        if (h->debug & 8)
            ndnd_msg(h, "face %u ready %u delay %i nrun %u surplus %u",
                    (unsigned)ev->evint, q->ready, delay, q->nrun, face->surplus);
        return(delay);
    }
    /* Determine when to run again */
    for (i = 0; i < q->send_queue->n; i++) {
        content = content_from_accession(h, q->send_queue->buf[i]);
        if (content != NULL) {
            q->nrun = 0;
            delay = randomize_content_delay(h, q);
            if (h->debug & 8)
                ndnd_msg(h, "face %u queued %u delay %i",
                         (unsigned)ev->evint, q->ready, delay);
            return(delay);
        }
    }
    q->send_queue->n = q->ready = 0;
Bail:
    q->sender = NULL;
    return(0);
}

/**
 * Queue a ContentObject to be sent on a face.
 */
static int
face_send_queue_insert(struct ndnd_handle *h,
                       struct face *face, struct content_entry *content)
{
    int ans;
    int delay;
    enum cq_delay_class c;
    enum cq_delay_class k;
    struct content_queue *q;
    if (face == NULL || content == NULL || (face->flags & NDN_FACE_NOSEND) != 0)
        return(-1);
    c = choose_content_delay_class(h, face->faceid, content->flags);
    if (face->q[c] == NULL)
        face->q[c] = content_queue_create(h, face, c);
    q = face->q[c];
    if (q == NULL)
        return(-1);
    /* Check the other queues first, it might be in one of them */
    for (k = 0; k < NDN_CQ_N; k++) {
        if (k != c && face->q[k] != NULL) {
            ans = ndn_indexbuf_member(face->q[k]->send_queue, content->accession);
            if (ans >= 0) {
                if (h->debug & 8)
                    ndnd_debug_ndnb(h, __LINE__, "content_otherq", face,
                                    content->key, content->size);
                return(ans);
            }
        }
    }
    ans = ndn_indexbuf_set_insert(q->send_queue, content->accession);
    if (q->sender == NULL) {
        delay = randomize_content_delay(h, q);
        q->ready = q->send_queue->n;
        q->sender = ndn_schedule_event(h->sched, delay,
                                       content_sender, q, face->faceid);
        if (h->debug & 8)
            ndnd_msg(h, "face %u q %d delay %d usec", face->faceid, c, delay);
    }
    return (ans);
}

/**
 * Return true iff the interest is pending on the given face
 */
static int
is_pending_on(struct ndnd_handle *h, struct interest_entry *ie, unsigned faceid)
{
    struct pit_face_item *x;
    
    for (x = ie->pfl; x != NULL; x = x->next) {
        if (x->faceid == faceid && (x->pfi_flags & NDND_PFI_PENDING) != 0)
            return(1);
        // XXX - depending on how list is ordered, an early out might be possible
        // For now, we assume no particular ordering
    }
    return(0);
}

/**
 * Consume matching interests
 * given a nameprefix_entry and a piece of content.
 *
 * If face is not NULL, pay attention only to interests from that face.
 * It is allowed to pass NULL for pc, but if you have a (valid) one it
 * will avoid a re-parse.
 * @returns number of matches found.
 */
static int
consume_matching_interests(struct ndnd_handle *h,
                           struct nameprefix_entry *npe,
                           struct content_entry *content,
                           struct ndn_parsed_ContentObject *pc,
                           struct face *face)
{
    int matches = 0;
    struct ielinks *head;
    struct ielinks *next;
    struct ielinks *pl;
    struct interest_entry *p;
    struct pit_face_item *x;
    const unsigned char *content_msg;
    size_t content_size;
    
    head = &npe->ie_head;
    content_msg = content->key;
    content_size = content->size;
    for (pl = head->next; pl != head; pl = next) {
        next = pl->next;
        p = (struct interest_entry *)pl;
        if (p->interest_msg == NULL)
            continue;
        if (face != NULL && is_pending_on(h, p, face->faceid) == 0)
            continue;
        if (ndn_content_matches_interest(content_msg, content_size, 0, pc,
                                         p->interest_msg, p->size, NULL)) {
            for (x = p->pfl; x != NULL; x = x->next) {
                if ((x->pfi_flags & NDND_PFI_PENDING) != 0)
                    face_send_queue_insert(h, face_from_faceid(h, x->faceid),
                                           content);
            }
            matches += 1;
            strategy_callout(h, p, NDNST_SATISFIED);
            consume_interest(h, p);
        }
    }
    return(matches);
}

/**
 * Adjust the predicted response associated with a name prefix entry.
 *
 * It is decreased by a small fraction if we get content within our
 * previous predicted value, and increased by a larger fraction if not.
 *
 */
static void
adjust_npe_predicted_response(struct ndnd_handle *h,
                              struct nameprefix_entry *npe, int up)
{
    unsigned t = npe->usec;
    if (up)
        t = t + (t >> 3);
    else
        t = t - (t >> 7);
    if (t < 127)
        t = 127;
    else if (t > h->predicted_response_limit)
        t = h->predicted_response_limit;
    npe->usec = t;
}

/**
 * Adjust the predicted responses for an interest.
 *
 * We adjust two npes, so that the parents are informed about activity
 * at the leaves.
 *
 */
static void
adjust_predicted_response(struct ndnd_handle *h,
                          struct interest_entry *ie, int up)
{
    struct nameprefix_entry *npe;
        
    npe = ie->ll.npe;
    if (npe == NULL)
        return;
    adjust_npe_predicted_response(h, npe, up);
    if (npe->parent != NULL)
        adjust_npe_predicted_response(h, npe->parent, up);
}

/**
 * Keep a little history about where matching content comes from.
 */
static void
note_content_from(struct ndnd_handle *h,
                  struct nameprefix_entry *npe,
                  unsigned from_faceid,
                  int prefix_comps)
{
    if (npe->src == from_faceid)
        adjust_npe_predicted_response(h, npe, 0);
    else if (npe->src == NDN_NOFACEID)
        npe->src = from_faceid;
    else {
        npe->osrc = npe->src;
        npe->src = from_faceid;
    }
    if (h->debug & 8)
        ndnd_msg(h, "sl.%d %u ci=%d osrc=%u src=%u usec=%d", __LINE__,
                 from_faceid, prefix_comps, npe->osrc, npe->src, npe->usec);
}

/**
 * Find and consume interests that match given content.
 *
 * Schedules the sending of the content.
 * If face is not NULL, pay attention only to interests from that face.
 * It is allowed to pass NULL for pc, but if you have a (valid) one it
 * will avoid a re-parse.
 * For new content, from_face is the source; for old content, from_face is NULL.
 * @returns number of matches, or -1 if the new content should be dropped.
 */
static int
match_interests(struct ndnd_handle *h, struct content_entry *content,
                           struct ndn_parsed_ContentObject *pc,
                           struct face *face, struct face *from_face)
{
    int n_matched = 0;
    int new_matches;
    int ci;
    int cm = 0;
    unsigned c0 = content->comps[0];
    const unsigned char *key = content->key + c0;
    struct nameprefix_entry *npe = NULL;
    for (ci = content->ncomps - 1; ci >= 0; ci--) {
        int size = content->comps[ci] - c0;
        npe = hashtb_lookup(h->nameprefix_tab, key, size);
        if (npe != NULL)
            break;
    }
    for (; npe != NULL; npe = npe->parent, ci--) {
        if (npe->fgen != h->forward_to_gen)
            update_forward_to(h, npe);
        if (from_face != NULL && (npe->flags & NDN_FORW_LOCAL) != 0 &&
            (from_face->flags & NDN_FACE_GG) == 0)
            return(-1);
        new_matches = consume_matching_interests(h, npe, content, pc, face);
        if (from_face != NULL && (new_matches != 0 || ci + 1 == cm))
            note_content_from(h, npe, from_face->faceid, ci);
        if (new_matches != 0) {
            cm = ci; /* update stats for this prefix and one shorter */
            n_matched += new_matches;
        }
    }
    return(n_matched);
}

/**
 * Send a message in a PDU, possibly stuffing other interest messages into it.
 * The message may be in two pieces.
 */
static void
stuff_and_send(struct ndnd_handle *h, struct face *face,
               const unsigned char *data1, size_t size1,
               const unsigned char *data2, size_t size2,
               const char *tag, int lineno) {
    struct ndn_charbuf *c = NULL;
    
    if ((face->flags & NDN_FACE_LINK) != 0) {
        c = charbuf_obtain(h);
        ndn_charbuf_reserve(c, size1 + size2 + 5 + 8);
        ndn_charbuf_append_tt(c, NDN_DTAG_NDNProtocolDataUnit, NDN_DTAG);
        ndn_charbuf_append(c, data1, size1);
        if (size2 != 0)
            ndn_charbuf_append(c, data2, size2);
        if (tag != NULL)
            ndnd_debug_ndnb(h, lineno, tag, face, c->buf + 4, c->length - 4);
        ndn_stuff_interest(h, face, c);
        ndn_append_link_stuff(h, face, c);
        ndn_charbuf_append_closer(c);
    }
    else if (size2 != 0 || h->mtu > size1 + size2 ||
             (face->flags & (NDN_FACE_SEQOK | NDN_FACE_SEQPROBE)) != 0 ||
             face->recvcount == 0) {
        c = charbuf_obtain(h);
        ndn_charbuf_append(c, data1, size1);
        if (size2 != 0)
            ndn_charbuf_append(c, data2, size2);
        if (tag != NULL)
            ndnd_debug_ndnb(h, lineno, tag, face, c->buf, c->length);
        ndn_stuff_interest(h, face, c);
        ndn_append_link_stuff(h, face, c);
    }
    else {
        /* avoid a copy in this case */
        if (tag != NULL)
            ndnd_debug_ndnb(h, lineno, tag, face, data1, size1);
        ndnd_send(h, face, data1, size1);
        return;
    }
    ndnd_send(h, face, c->buf, c->length);
    charbuf_release(h, c);
    return;
}

/**
 * Append a link-check interest if appropriate.
 *
 * @returns the number of messages that were stuffed.
 */
static int
stuff_link_check(struct ndnd_handle *h,
                   struct face *face, struct ndn_charbuf *c)
{
    int checkflags = NDN_FACE_DGRAM | NDN_FACE_MCAST | NDN_FACE_GG | NDN_FACE_LC;
    int wantflags = NDN_FACE_DGRAM;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *ibuf = NULL;
    int res;
    int ans = 0;
    if (face->recvcount > 0)
        return(0);
    if ((face->flags & checkflags) != wantflags)
        return(0);
    name = ndn_charbuf_create();
    if (name == NULL) goto Bail;
    ndn_name_init(name);
    res = ndn_name_from_uri(name, NDNDID_NEIGHBOR_URI);
    if (res < 0) goto Bail;
    ibuf = ndn_charbuf_create();
    if (ibuf == NULL) goto Bail;
    ndn_charbuf_append_tt(ibuf, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append(ibuf, name->buf, name->length);
    ndnb_tagged_putf(ibuf, NDN_DTAG_Scope, "2");
    // XXX - ought to generate a nonce
    ndn_charbuf_append_closer(ibuf);
    ndn_charbuf_append(c, ibuf->buf, ibuf->length);
    ndnd_meter_bump(h, face->meter[FM_INTO], 1);
    h->interests_stuffed++;
    face->flags |= NDN_FACE_LC;
    if (h->debug & 2)
        ndnd_debug_ndnb(h, __LINE__, "stuff_interest_to", face,
                        ibuf->buf, ibuf->length);
    ans = 1;
Bail:
    ndn_charbuf_destroy(&ibuf);
    ndn_charbuf_destroy(&name);
    return(ans);
}

/**
 * Stuff a PDU with interest messages that will fit.
 *
 * @returns the number of messages that were stuffed.
 */
static int
ndn_stuff_interest(struct ndnd_handle *h,
                   struct face *face, struct ndn_charbuf *c)
{
    int n_stuffed = 0;
    
    n_stuffed += stuff_link_check(h, face, c);
    return(n_stuffed);
}

/**
 * Set up to send one sequence number to see it the other side wants to play.
 *
 * If we don't hear a number from the other side, we won't keep sending them.
 */
static void
ndn_link_state_init(struct ndnd_handle *h, struct face *face)
{
    int checkflags;
    int matchflags;
    
    matchflags = NDN_FACE_DGRAM;
    checkflags = matchflags | NDN_FACE_MCAST | NDN_FACE_GG | NDN_FACE_SEQOK | \
                 NDN_FACE_PASSIVE;
    if ((face->flags & checkflags) != matchflags)
        return;
    /* Send one sequence number to see if the other side wants to play. */
    face->pktseq = nrand48(h->seed);
    face->flags |= NDN_FACE_SEQPROBE;
}

/**
 * Append a sequence number if appropriate.
 */
static void
ndn_append_link_stuff(struct ndnd_handle *h,
                      struct face *face,
                      struct ndn_charbuf *c)
{
    if ((face->flags & (NDN_FACE_SEQOK | NDN_FACE_SEQPROBE)) == 0)
        return;
    ndn_charbuf_append_tt(c, NDN_DTAG_SequenceNumber, NDN_DTAG);
    ndn_charbuf_append_tt(c, 2, NDN_BLOB);
    ndn_charbuf_append_value(c, face->pktseq, 2);
    ndnb_element_end(c);
    if (0)
        ndnd_msg(h, "debug.%d pkt_to %u seq %u",
                 __LINE__, face->faceid, (unsigned)face->pktseq);
    face->pktseq++;
    face->flags &= ~NDN_FACE_SEQPROBE;
}

/**
 * Process an incoming link message.
 */
static int
process_incoming_link_message(struct ndnd_handle *h,
                              struct face *face, enum ndn_dtag dtag,
                              unsigned char *msg, size_t size)
{
    uintmax_t s;
    int checkflags;
    int matchflags;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, msg, size);

    switch (dtag) {
        case NDN_DTAG_SequenceNumber:
            s = ndn_parse_required_tagged_binary_number(d, dtag, 1, 6);
            if (d->decoder.state < 0)
                return(d->decoder.state);
            /*
             * If the other side is unicast and sends sequence numbers,
             * then it is OK for us to send numbers as well.
             */
            matchflags = NDN_FACE_DGRAM;
            checkflags = matchflags | NDN_FACE_MCAST | NDN_FACE_SEQOK;
            if ((face->flags & checkflags) == matchflags)
                face->flags |= NDN_FACE_SEQOK;
            if (face->rrun == 0) {
                face->rseq = s;
                face->rrun = 1;
                return(0);
            }
            if (s == face->rseq + 1) {
                face->rseq = s;
                if (face->rrun < 255)
                    face->rrun++;
                return(0);
            }
            if (s > face->rseq && s - face->rseq < 255) {
                ndnd_msg(h, "seq_gap %u %ju to %ju",
                         face->faceid, face->rseq, s);
                face->rseq = s;
                face->rrun = 1;
                return(0);
            }
            if (s <= face->rseq) {
                if (face->rseq - s < face->rrun) {
                    ndnd_msg(h, "seq_dup %u %ju", face->faceid, s);
                    return(0);
                }
                if (face->rseq - s < 255) {
                    /* Received out of order */
                    ndnd_msg(h, "seq_ooo %u %ju", face->faceid, s);
                    if (s == face->rseq - face->rrun) {
                        face->rrun++;
                        return(0);
                    }
                }
            }
            face->rseq = s;
            face->rrun = 1;
            break;
        default:
            return(-1);
    }
    return(0);
}

/**
 * Checks for inactivity on datagram faces.
 * @returns number of faces that have gone away.
 */
static int
check_dgram_faces(struct ndnd_handle *h)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int count = 0;
    int checkflags = NDN_FACE_DGRAM;
    int wantflags = NDN_FACE_DGRAM;
    int adj_req = 0;
    
    hashtb_start(h->dgram_faces, e);
    while (e->data != NULL) {
        struct face *face = e->data;
        if (face->addr != NULL && (face->flags & checkflags) == wantflags) {
            face->flags &= ~NDN_FACE_LC; /* Rate limit link check interests */
            if (face->recvcount == 0) {
                if ((face->flags & (NDN_FACE_PERMANENT | NDN_FACE_ADJ)) == 0) {
                    count += 1;
                    hashtb_delete(e);
                    continue;
                }
            }
            else if (face->recvcount == 1) {
                face->recvcount = 0;
            }
            else {
                face->recvcount = 1; /* go around twice */
            }
        }
        hashtb_next(e);
    }
    hashtb_end(e);
    if (adj_req) {
        process_internal_client_buffer(h);
    }
    return(count);
}

/**
 * Destroys the face identified by faceid.
 * @returns 0 for success, -1 for failure.
 */
int
ndnd_destroy_face(struct ndnd_handle *h, unsigned faceid)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct face *face;
    int dgram_chk = NDN_FACE_DGRAM | NDN_FACE_MCAST;
    int dgram_want = NDN_FACE_DGRAM;
    
    face = face_from_faceid(h, faceid);
    if (face == NULL)
        return(-1);
    if ((face->flags & dgram_chk) == dgram_want) {
        hashtb_start(h->dgram_faces, e);
        hashtb_seek(e, face->addr, face->addrlen, 0);
        if (e->data == face)
            face = NULL;
        hashtb_delete(e);
        hashtb_end(e);
        if (face == NULL)
            return(0);
    }
    shutdown_client_fd(h, face->recv_fd);
    face = NULL;
    return(0);
}

/**
 * Remove expired faces from *ip
 */
static void
check_forward_to(struct ndnd_handle *h, struct ndn_indexbuf **ip)
{
    struct ndn_indexbuf *ft = *ip;
    int i;
    int j;
    if (ft == NULL)
        return;
    for (i = 0; i < ft->n; i++)
        if (face_from_faceid(h, ft->buf[i]) == NULL)
            break;
    for (j = i + 1; j < ft->n; j++)
        if (face_from_faceid(h, ft->buf[j]) != NULL)
            ft->buf[i++] = ft->buf[j];
    if (i == 0)
        ndn_indexbuf_destroy(ip);
    else if (i < ft->n)
        ft->n = i;
}

/**
 * Ages src info and retires unused nameprefix entries.
 * @returns number that have gone away.
 */
static int
check_nameprefix_entries(struct ndnd_handle *h)
{
    int count = 0;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ielinks *head;
    struct nameprefix_entry *npe;    
    
    hashtb_start(h->nameprefix_tab, e);
    for (npe = e->data; npe != NULL; npe = e->data) {
        if (  npe->src == NDN_NOFACEID &&
              npe->children == 0 &&
              npe->forwarding == NULL) {
            head = &npe->ie_head;
            if (head == head->next) {
                count += 1;
                if (npe->parent != NULL) {
                    npe->parent->children--;
                    npe->parent = NULL;
                }
                hashtb_delete(e);
                continue;
            }
        }
        check_forward_to(h, &npe->forward_to);
        check_forward_to(h, &npe->tap);
        npe->osrc = npe->src;
        npe->src = NDN_NOFACEID;
        hashtb_next(e);
    }
    hashtb_end(e);
    return(count);
}

static void
check_comm_file(struct ndnd_handle *h)
{
    if (!comm_file_ok()) {
        ndnd_msg(h, "stopping (%s gone)", unlink_this_at_exit);
        unlink_this_at_exit = NULL;
        h->running = 0;
    }
}

/**
 * Scheduled reap event for retiring expired structures.
 */
static int
reap(
    struct ndn_schedule *sched,
    void *clienth,
    struct ndn_scheduled_event *ev,
    int flags)
{
    struct ndnd_handle *h = clienth;
    (void)(sched);
    (void)(ev);
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        h->reaper = NULL;
        return(0);
    }
    check_dgram_faces(h);
    check_nameprefix_entries(h);
    check_comm_file(h);
    return(2 * NDN_INTEREST_LIFETIME_MICROSEC);
}

static void
reap_needed(struct ndnd_handle *h, int init_delay_usec)
{
    if (h->reaper == NULL)
        h->reaper = ndn_schedule_event(h->sched, init_delay_usec, reap, NULL, 0);
}

/**
 * Remove a content object from the store
 */
static int
remove_content(struct ndnd_handle *h, struct content_entry *content)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int res;
    if (content == NULL)
        return(-1);
    hashtb_start(h->content_tab, e);
    res = hashtb_seek(e, content->key,
                      content->key_size, content->size - content->key_size);
    if (res != HT_OLD_ENTRY)
        abort();
    if ((content->flags & NDN_CONTENT_ENTRY_STALE) != 0)
        h->n_stale--;
    if (h->debug & 4)
        ndnd_debug_ndnb(h, __LINE__, "remove", NULL,
                        content->key, content->size);
    hashtb_delete(e);
    hashtb_end(e);
    return(0);
}

/**
 * Periodic content cleaning
 */
static int
clean_daemon(struct ndn_schedule *sched,
             void *clienth,
             struct ndn_scheduled_event *ev,
             int flags)
{
    struct ndnd_handle *h = clienth;
    (void)(sched);
    (void)(ev);
    unsigned long n;
    ndn_accession_t limit;
    ndn_accession_t a;
    ndn_accession_t min_stale;
    int check_limit = 500;  /* Do not run for too long at once */
    struct content_entry *content = NULL;
    int res = 0;
    int ignore;
    int i;
    
    /*
     * If we ran into our processing limit (check_limit) last time,
     * ev->evint tells us where to restart.
     */
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        h->clean = NULL;
        return(0);
    }
    n = hashtb_n(h->content_tab);
    if (n <= h->capacity) {
        h->clean = NULL;
        return(0);
    }
    /* Toss unsolicited content first */
    for (i = 0; i < h->unsol->n; i++) {
        if (i == check_limit) {
            for (i = check_limit; i < h->unsol->n; i++)
                h->unsol->buf[i-check_limit] = h->unsol->buf[i];
            h->unsol->n -= check_limit;
            return(500);
        }
        a = h->unsol->buf[i];
        content = content_from_accession(h, a);
        if (content != NULL &&
            (content->flags & NDN_CONTENT_ENTRY_PRECIOUS) == 0)
            remove_content(h, content);
    }
    h->unsol->n = 0;
    n = hashtb_n(h->content_tab);
    if (h->min_stale <= h->max_stale) {
        /* clean out stale content next */
        limit = h->max_stale;
        if (limit > h->accession)
            limit = h->accession;
        min_stale = ~0;
        a = ev->evint;
        if (a <= h->min_stale || a > h->max_stale)
            a = h->min_stale;
        else
            min_stale = h->min_stale;
        for (; a <= limit && n > h->capacity; a++) {
            if (check_limit-- <= 0) {
                ev->evint = a;
                break;
            }
            content = content_from_accession(h, a);
            if (content != NULL &&
                  (content->flags & NDN_CONTENT_ENTRY_STALE) != 0) {
                res = remove_content(h, content);
                if (res < 0) {
                    if (a < min_stale)
                        min_stale = a;
                }
                else {
                    content = NULL;
                    n -= 1;
                }
            }
        }
        if (min_stale < a)
            h->min_stale = min_stale;
        else if (a > limit) {
            h->min_stale = ~0;
            h->max_stale = 0;
        }
        else
            h->min_stale = a;
        if (check_limit <= 0)
            return(5000);
    }
    else {
        /* Make oldish content stale, for cleanup on next round */
        limit = h->accession;
        ignore = NDN_CONTENT_ENTRY_STALE | NDN_CONTENT_ENTRY_PRECIOUS;
        for (a = h->accession_base; a <= limit && n > h->capacity; a++) {
            content = content_from_accession(h, a);
            if (content != NULL && (content->flags & ignore) == 0) {
                mark_stale(h, content);
                n--;
            }
        }
        ev->evint = 0;
        return(5000);
    }
    h->clean = NULL;
    return(0);
}

/**
 * Schedule clean_daemon, if it is not already scheduled.
 */
static void
clean_needed(struct ndnd_handle *h)
{
    if (h->clean == NULL)
        h->clean = ndn_schedule_event(h->sched, 5000, clean_daemon, NULL, 0);
}

/**
 * Age out the old forwarding table entries
 */
static int
age_forwarding(struct ndn_schedule *sched,
             void *clienth,
             struct ndn_scheduled_event *ev,
             int flags)
{
    struct ndnd_handle *h = clienth;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_forwarding *f;
    struct ndn_forwarding *next;
    struct ndn_forwarding **p;
    struct nameprefix_entry *npe;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        h->age_forwarding = NULL;
        return(0);
    }
    hashtb_start(h->nameprefix_tab, e);
    for (npe = e->data; npe != NULL; npe = e->data) {
        p = &npe->forwarding;
        for (f = npe->forwarding; f != NULL; f = next) {
            next = f->next;
            if ((f->flags & NDN_FORW_REFRESHED) == 0 ||
                  face_from_faceid(h, f->faceid) == NULL) {
                if (h->debug & 2) {
                    struct face *face = face_from_faceid(h, f->faceid);
                    if (face != NULL) {
                        struct ndn_charbuf *prefix = ndn_charbuf_create();
                        ndn_name_init(prefix);
                        ndn_name_append_components(prefix, e->key, 0, e->keysize);
                        ndnd_debug_ndnb(h, __LINE__, "prefix_expiry", face,
                                prefix->buf,
                                prefix->length);
                        ndn_charbuf_destroy(&prefix);
                    }
                }
                *p = next;
                free(f);
                f = NULL;
                continue;
            }
            f->expires -= NDN_FWU_SECS;
            if (f->expires <= 0)
                f->flags &= ~NDN_FORW_REFRESHED;
            p = &(f->next);
        }
        hashtb_next(e);
    }
    hashtb_end(e);
    h->forward_to_gen += 1;
    return(NDN_FWU_SECS*1000000);
}

/**
 * Make sure a call to age_forwarding is scheduled.
 */
static void
age_forwarding_needed(struct ndnd_handle *h)
{
    if (h->age_forwarding == NULL)
        h->age_forwarding = ndn_schedule_event(h->sched,
                                               NDN_FWU_SECS*1000000,
                                               age_forwarding,
                                               NULL, 0);
}

/**
 * Look up a forwarding entry, creating it if it is not there.
 */
static struct ndn_forwarding *
seek_forwarding(struct ndnd_handle *h,
                struct nameprefix_entry *npe, unsigned faceid)
{
    struct ndn_forwarding *f;
    
    for (f = npe->forwarding; f != NULL; f = f->next)
        if (f->faceid == faceid)
            return(f);
    f = calloc(1, sizeof(*f));
    if (f != NULL) {
        f->faceid = faceid;
        f->flags = (NDN_FORW_CHILD_INHERIT | NDN_FORW_ACTIVE);
        f->expires = 0x7FFFFFFF;
        f->next = npe->forwarding;
        npe->forwarding = f;
    }
    return(f);
}

/**
 * Register or update a prefix in the forwarding table (FIB).
 *
 * @param h is the ndnd handle.
 * @param msg is a ndnb-encoded message containing the name prefix somewhere.
 * @param comps contains the delimiting offsets for the name components in msg.
 * @param ncomps is the number of relevant components.
 * @param faceid indicates which face to forward to.
 * @param flags are the forwarding entry flags (NDN_FORW_...), -1 for defaults.
 * @param expires tells the remaining lifetime, in seconds.
 * @returns -1 for error, or new flags upon success; the private flag
 *        NDN_FORW_REFRESHED indicates a previously existing entry.
 */
static int
ndnd_reg_prefix(struct ndnd_handle *h,
                const unsigned char *msg,
                struct ndn_indexbuf *comps,
                int ncomps,
                unsigned faceid,
                int flags,
                int expires)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_forwarding *f = NULL;
    struct nameprefix_entry *npe = NULL;
    int res;
    struct face *face = NULL;
    
    if (flags >= 0 &&
        (flags & NDN_FORW_PUBMASK) != flags)
        return(-1);
    face = face_from_faceid(h, faceid);
    if (face == NULL)
        return(-1);
    /* This is a bit hacky, but it gives us a way to set NDN_FACE_DC */
    if (flags >= 0 && (flags & NDN_FORW_LAST) != 0)
        face->flags |= NDN_FACE_DC;
    hashtb_start(h->nameprefix_tab, e);
    res = nameprefix_seek(h, e, msg, comps, ncomps);
    if (res >= 0) {
        res = (res == HT_OLD_ENTRY) ? NDN_FORW_REFRESHED : 0;
        npe = e->data;
        f = seek_forwarding(h, npe, faceid);
        if (f != NULL) {
            h->forward_to_gen += 1; // XXX - too conservative, should check changes
            f->expires = expires;
            if (flags < 0)
                flags = f->flags & NDN_FORW_PUBMASK;
            f->flags = (NDN_FORW_REFRESHED | flags);
            res |= flags;
            if (h->debug & (2 | 4)) {
                struct ndn_charbuf *prefix = ndn_charbuf_create();
                struct ndn_charbuf *debugtag = ndn_charbuf_create();
                ndn_charbuf_putf(debugtag, "prefix,ff=%s%x",
                                 flags > 9 ? "0x" : "", flags);
                if (f->expires < (1 << 30))
                    ndn_charbuf_putf(debugtag, ",sec=%d", expires);
                ndn_name_init(prefix);
                ndn_name_append_components(prefix, msg,
                                           comps->buf[0], comps->buf[ncomps]);
                ndnd_debug_ndnb(h, __LINE__,
                                ndn_charbuf_as_string(debugtag),
                                face,
                                prefix->buf,
                                prefix->length);
                ndn_charbuf_destroy(&prefix);
                ndn_charbuf_destroy(&debugtag);
            }
        }
        else
            res = -1;
    }
    hashtb_end(e);
    if (res >= 0)
        update_npe_children(h, npe, faceid);
    return(res);
}

/**
 * Register a prefix, expressed in the form of a URI.
 * @returns negative value for error, or new face flags for success.
 */
int
ndnd_reg_uri(struct ndnd_handle *h,
             const char *uri,
             unsigned faceid,
             int flags,
             int expires)
{
    struct ndn_charbuf *name;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    struct ndn_indexbuf *comps;
    int res;
    
    name = ndn_charbuf_create();
    ndn_name_init(name);
    res = ndn_name_from_uri(name, uri);
    if (res < 0)
        goto Bail;
    comps = ndn_indexbuf_create();
    d = ndn_buf_decoder_start(&decoder, name->buf, name->length);
    res = ndn_parse_Name(d, comps);
    if (res < 0)
        goto Bail;
    res = ndnd_reg_prefix(h, name->buf, comps, comps->n - 1,
                          faceid, flags, expires);
Bail:
    ndn_charbuf_destroy(&name);
    ndn_indexbuf_destroy(&comps);
    return(res);
}

/**
 * Register prefixes, expressed in the form of a list of URIs.
 * The URIs in the charbuf are each terminated by nul.
 */
void
ndnd_reg_uri_list(struct ndnd_handle *h,
             struct ndn_charbuf *uris,
             unsigned faceid,
             int flags,
             int expires)
{
    size_t i;
    const char *s;
    s = ndn_charbuf_as_string(uris);
    for (i = 0; i + 1 < uris->length; i += strlen(s + i) + 1)
        ndnd_reg_uri(h, s + i, faceid, flags, expires);
}

/**
 * Called when a face is first created, and (perhaps) a second time in the case
 * that a face transitions from the undecided state.
 */
static void
register_new_face(struct ndnd_handle *h, struct face *face)
{
    if (face->faceid != 0 && (face->flags & (NDN_FACE_UNDECIDED | NDN_FACE_PASSIVE)) == 0) {
        ndnd_face_status_change(h, face->faceid);
        if (h->flood && h->autoreg != NULL && (face->flags & NDN_FACE_GG) == 0)
            ndnd_reg_uri_list(h, h->autoreg, face->faceid,
                              NDN_FORW_CAPTURE_OK | NDN_FORW_CHILD_INHERIT | NDN_FORW_ACTIVE,
                              0x7FFFFFFF);
        ndn_link_state_init(h, face);
    }
}

/**
 * Replaces contents of reply_body with a ndnb-encoded StatusResponse.
 *
 * @returns NDN_CONTENT_NACK, or -1 in case of error.
 */
static int
ndnd_nack(struct ndnd_handle *h, struct ndn_charbuf *reply_body,
          int errcode, const char *errtext)
{
    int res;
    reply_body->length = 0;
    res = ndn_encode_StatusResponse(reply_body, errcode, errtext);
    if (res == 0)
        res = NDN_CONTENT_NACK;
    return(res);
}

/**
 * Check that indicated ndndid matches ours.
 *
 * Fills reply_body with a StatusResponse in case of no match.
 *
 * @returns 0 if OK, or NDN_CONTENT_NACK if not.
 */
static int
check_ndndid(struct ndnd_handle *h,
             const void *p, size_t sz, struct ndn_charbuf *reply_body)
{
    if (sz != sizeof(h->ndnd_id) || memcmp(p, h->ndnd_id, sz) != 0)
        return(ndnd_nack(h, reply_body, 531, "missing or incorrect ndndid"));
    return(0);
}

/**
 * Check ndndid, given a face instance.
 */
static int
check_face_instance_ndndid(struct ndnd_handle *h,
    struct ndn_face_instance *f, struct ndn_charbuf *reply_body)
{
    return(check_ndndid(h, f->ndnd_id, f->ndnd_id_size, reply_body));
}

/**
 * Check ndndid, given a parsed ForwardingEntry.
 */
static int
check_forwarding_entry_ndndid(struct ndnd_handle *h,
    struct ndn_forwarding_entry *f, struct ndn_charbuf *reply_body)
{
    return(check_ndndid(h, f->ndnd_id, f->ndnd_id_size, reply_body));
}

/**
 * Process a newface request for the ndnd internal client.
 *
 * @param h is the ndnd handle
 * @param msg points to a ndnd-encoded ContentObject containing a
 *         FaceInstance in its Content.
 * @param size is its size in bytes
 * @param reply_body is a buffer to hold the Content of the reply, as a
 *         FaceInstance including faceid
 * @returns 0 for success, negative for no response, or NDN_CONTENT_NACK to
 *         set the response type to NACK.
 *
 * Is is permitted for the face to already exist.
 * A newly created face will have no registered prefixes, and so will not
 * receive any traffic.
 */
int
ndnd_req_newface(struct ndnd_handle *h,
                 const unsigned char *msg, size_t size,
                 struct ndn_charbuf *reply_body)
{
    struct ndn_parsed_ContentObject pco = {0};
    int res;
    const unsigned char *req;
    size_t req_size;
    struct ndn_face_instance *face_instance = NULL;
    struct addrinfo hints = {0};
    struct addrinfo *addrinfo = NULL;
    int mcast;
    struct face *face = NULL;
    struct face *reqface = NULL;
    struct face *newface = NULL;
    int save;
    int nackallowed = 0;

    save = h->flood;
    h->flood = 0; /* never auto-register for these */
    res = ndn_parse_ContentObject(msg, size, &pco, NULL);
    if (res < 0)
        goto Finish;
    res = ndn_content_get_value(msg, size, &pco, &req, &req_size);
    if (res < 0)
        goto Finish;
    res = -1;
    face_instance = ndn_face_instance_parse(req, req_size);
    if (face_instance == NULL || face_instance->action == NULL)
        goto Finish;
    if (strcmp(face_instance->action, "newface") != 0)
        goto Finish;
    /* consider the source ... */
    reqface = face_from_faceid(h, h->interest_faceid);
    if (reqface == NULL ||
        (reqface->flags & (NDN_FACE_LOOPBACK | NDN_FACE_LOCAL)) == 0)
        goto Finish;
    nackallowed = 1;
    res = check_face_instance_ndndid(h, face_instance, reply_body);
    if (res != 0)
        goto Finish;
    if (face_instance->descr.ipproto != IPPROTO_UDP &&
        face_instance->descr.ipproto != IPPROTO_TCP) {
        res = ndnd_nack(h, reply_body, 504, "parameter error");
        goto Finish;
    }
    if (face_instance->descr.address == NULL) {
        res = ndnd_nack(h, reply_body, 504, "parameter error");
        goto Finish;
    }
    if (face_instance->descr.port == NULL) {
        res = ndnd_nack(h, reply_body, 504, "parameter error");
        goto Finish;
    }
    if ((reqface->flags & NDN_FACE_GG) == 0) {
        res = ndnd_nack(h, reply_body, 430, "not authorized");
        goto Finish;
    }
    hints.ai_flags |= AI_NUMERICHOST;
    hints.ai_protocol = face_instance->descr.ipproto;
    hints.ai_socktype = (hints.ai_protocol == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    res = getaddrinfo(face_instance->descr.address,
                      face_instance->descr.port,
                      &hints,
                      &addrinfo);
    if (res != 0 || (h->debug & 128) != 0)
        ndnd_msg(h, "ndnd_req_newface from %u: getaddrinfo(%s, %s, ...) returned %d",
                 h->interest_faceid,
                 face_instance->descr.address,
                 face_instance->descr.port,
                 res);
    if (res != 0 || addrinfo == NULL) {
        res = ndnd_nack(h, reply_body, 501, "syntax error in address");
        goto Finish;
    }
    if (addrinfo->ai_next != NULL)
        ndnd_msg(h, "ndnd_req_newface: (addrinfo->ai_next != NULL) ? ?");
    if (face_instance->descr.ipproto == IPPROTO_UDP) {
        mcast = 0;
        if (addrinfo->ai_family == AF_INET) {
            face = face_from_faceid(h, h->ipv4_faceid);
            mcast = IN_MULTICAST(ntohl(((struct sockaddr_in *)(addrinfo->ai_addr))->sin_addr.s_addr));
        }
        else if (addrinfo->ai_family == AF_INET6) {
            face = face_from_faceid(h, h->ipv6_faceid);
            mcast = IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr);
        }
        if (mcast)
            face = setup_multicast(h, face_instance,
                                   addrinfo->ai_addr,
                                   addrinfo->ai_addrlen);
        if (face == NULL) {
            res = ndnd_nack(h, reply_body, 453, "could not setup multicast");
            goto Finish;
        }
        newface = get_dgram_source(h, face,
                                   addrinfo->ai_addr,
                                   addrinfo->ai_addrlen,
                                   0);
    }
    else if (addrinfo->ai_socktype == SOCK_STREAM) {
        newface = make_connection(h,
                                  addrinfo->ai_addr,
                                  addrinfo->ai_addrlen,
                                  0);
    }
    if (newface != NULL) {
        newface->flags |= NDN_FACE_PERMANENT;
        face_instance->action = NULL;
        face_instance->ndnd_id = h->ndnd_id;
        face_instance->ndnd_id_size = sizeof(h->ndnd_id);
        face_instance->faceid = newface->faceid;
        face_instance->lifetime = 0x7FFFFFFF;
        /*
         * A short lifetime is a clue to the client that
         * the connection has not been completed.
         */
        if ((newface->flags & NDN_FACE_CONNECTING) != 0)
            face_instance->lifetime = 1;
        res = ndnb_append_face_instance(reply_body, face_instance);
        if (res > 0)
            res = 0;
    }
    else
        res = ndnd_nack(h, reply_body, 450, "could not create face");
Finish:
    h->flood = save; /* restore saved flood flag */
    ndn_face_instance_destroy(&face_instance);
    if (addrinfo != NULL)
        freeaddrinfo(addrinfo);
    return((nackallowed || res <= 0) ? res : -1);
}

/**
 * @brief Process a destroyface request for the ndnd internal client.
 * @param h is the ndnd handle
 * @param msg points to a ndnd-encoded ContentObject containing a FaceInstance
            in its Content.
 * @param size is its size in bytes
 * @param reply_body is a buffer to hold the Content of the reply, as a
 *         FaceInstance including faceid
 * @returns 0 for success, negative for no response, or NDN_CONTENT_NACK to
 *         set the response type to NACK.
 *
 * Is is an error if the face does not exist.
 */
int
ndnd_req_destroyface(struct ndnd_handle *h,
                     const unsigned char *msg, size_t size,
                     struct ndn_charbuf *reply_body)
{
    struct ndn_parsed_ContentObject pco = {0};
    int res;
    int at = 0;
    const unsigned char *req;
    size_t req_size;
    struct ndn_face_instance *face_instance = NULL;
    struct face *reqface = NULL;
    int nackallowed = 0;

    res = ndn_parse_ContentObject(msg, size, &pco, NULL);
    if (res < 0) { at = __LINE__; goto Finish; }
    res = ndn_content_get_value(msg, size, &pco, &req, &req_size);
    if (res < 0) { at = __LINE__; goto Finish; }
    res = -1;
    face_instance = ndn_face_instance_parse(req, req_size);
    if (face_instance == NULL) { at = __LINE__; goto Finish; }
    if (face_instance->action == NULL) { at = __LINE__; goto Finish; }
    /* consider the source ... */
    reqface = face_from_faceid(h, h->interest_faceid);
    if (reqface == NULL) { at = __LINE__; goto Finish; }
    if ((reqface->flags & NDN_FACE_GG) == 0) { at = __LINE__; goto Finish; }
    nackallowed = 1;
    if (strcmp(face_instance->action, "destroyface") != 0)
        { at = __LINE__; goto Finish; }
    res = check_face_instance_ndndid(h, face_instance, reply_body);
    if (res != 0)
        { at = __LINE__; goto Finish; }
    if (face_instance->faceid == 0) { at = __LINE__; goto Finish; }
    res = ndnd_destroy_face(h, face_instance->faceid);
    if (res < 0) { at = __LINE__; goto Finish; }
    face_instance->action = NULL;
    face_instance->ndnd_id = h->ndnd_id;
    face_instance->ndnd_id_size = sizeof(h->ndnd_id);
    face_instance->lifetime = 0;
    res = ndnb_append_face_instance(reply_body, face_instance);
    if (res < 0) {
        at = __LINE__;
    }
Finish:
    if (at != 0) {
        ndnd_msg(h, "ndnd_req_destroyface failed (line %d, res %d)", at, res);
        if (reqface == NULL || (reqface->flags & NDN_FACE_GG) == 0)
            res = -1;
        else
            res = ndnd_nack(h, reply_body, 450, "could not destroy face");
    }
    ndn_face_instance_destroy(&face_instance);
    return((nackallowed || res <= 0) ? res : -1);
}

/**
 * Worker bee for two very similar public functions.
 */
static int
ndnd_req_prefix_or_self_reg(struct ndnd_handle *h,
                            const unsigned char *msg, size_t size, int selfreg,
                            struct ndn_charbuf *reply_body)
{
    struct ndn_parsed_ContentObject pco = {0};
    int res;
    const unsigned char *req;
    size_t req_size;
    struct ndn_forwarding_entry *forwarding_entry = NULL;
    struct face *face = NULL;
    struct face *reqface = NULL;
    struct ndn_indexbuf *comps = NULL;
    int nackallowed = 0;

    res = ndn_parse_ContentObject(msg, size, &pco, NULL);
    if (res < 0)
        goto Finish;
    res = ndn_content_get_value(msg, size, &pco, &req, &req_size);
    if (res < 0)
        goto Finish;
    res = -1;
    forwarding_entry = ndn_forwarding_entry_parse(req, req_size);
    if (forwarding_entry == NULL || forwarding_entry->action == NULL)
        goto Finish;
    /* consider the source ... */
    reqface = face_from_faceid(h, h->interest_faceid);
    if (reqface == NULL)
        goto Finish;
    if ((reqface->flags & (NDN_FACE_GG | NDN_FACE_REGOK)) == 0)
        goto Finish;
    nackallowed = 1;
    if (selfreg) {
        if (strcmp(forwarding_entry->action, "selfreg") != 0)
            goto Finish;
        if (forwarding_entry->faceid == NDN_NOFACEID)
            forwarding_entry->faceid = h->interest_faceid;
        else if (forwarding_entry->faceid != h->interest_faceid)
            goto Finish;
    }
    else {
        if (strcmp(forwarding_entry->action, "prefixreg") != 0)
        goto Finish;
    }
    if (forwarding_entry->name_prefix == NULL)
        goto Finish;
    if (forwarding_entry->ndnd_id_size == sizeof(h->ndnd_id)) {
        if (memcmp(forwarding_entry->ndnd_id,
                   h->ndnd_id, sizeof(h->ndnd_id)) != 0)
            goto Finish;
    }
    else if (forwarding_entry->ndnd_id_size != 0)
        goto Finish;
    face = face_from_faceid(h, forwarding_entry->faceid);
    if (face == NULL)
        goto Finish;
    if (forwarding_entry->lifetime < 0)
        forwarding_entry->lifetime = 2000000000;
    else if (forwarding_entry->lifetime > 3600 &&
             forwarding_entry->lifetime < (1 << 30))
        forwarding_entry->lifetime = 300;
    comps = ndn_indexbuf_create();
    res = ndn_name_split(forwarding_entry->name_prefix, comps);
    if (res < 0)
        goto Finish;
    res = ndnd_reg_prefix(h,
                          forwarding_entry->name_prefix->buf, comps, res,
                          face->faceid,
                          forwarding_entry->flags,
                          forwarding_entry->lifetime);
    if (res < 0)
        goto Finish;
    forwarding_entry->flags = res;
    forwarding_entry->action = NULL;
    forwarding_entry->ndnd_id = h->ndnd_id;
    forwarding_entry->ndnd_id_size = sizeof(h->ndnd_id);
    res = ndnb_append_forwarding_entry(reply_body, forwarding_entry);
    if (res > 0)
        res = 0;
Finish:
    ndn_forwarding_entry_destroy(&forwarding_entry);
    ndn_indexbuf_destroy(&comps);
    if (nackallowed && res < 0)
        res = ndnd_nack(h, reply_body, 450, "could not register prefix");
    return((nackallowed || res <= 0) ? res : -1);
}

/**
 * @brief Process a prefixreg request for the ndnd internal client.
 * @param h is the ndnd handle
 * @param msg points to a ndnd-encoded ContentObject containing a
 *          ForwardingEntry in its Content.
 * @param size is its size in bytes
 * @param reply_body is a buffer to hold the Content of the reply, as a
 *         FaceInstance including faceid
 * @returns 0 for success, negative for no response, or NDN_CONTENT_NACK to
 *         set the response type to NACK.
 *
 */
int
ndnd_req_prefixreg(struct ndnd_handle *h,
                   const unsigned char *msg, size_t size,
                   struct ndn_charbuf *reply_body)
{
    return(ndnd_req_prefix_or_self_reg(h, msg, size, 0, reply_body));
}

/**
 * @brief Process a selfreg request for the ndnd internal client.
 * @param h is the ndnd handle
 * @param msg points to a ndnd-encoded ContentObject containing a
 *          ForwardingEntry in its Content.
 * @param size is its size in bytes
 * @param reply_body is a buffer to hold the Content of the reply, as a
 *         ndnb-encoded ForwardingEntry
 * @returns 0 for success, negative for no response, or NDN_CONTENT_NACK to
 *         set the response type to NACK.
 *
 */
int
ndnd_req_selfreg(struct ndnd_handle *h,
                 const unsigned char *msg, size_t size,
                 struct ndn_charbuf *reply_body)
{
    return(ndnd_req_prefix_or_self_reg(h, msg, size, 1, reply_body));
}

/**
 * @brief Process an unreg request for the ndnd internal client.
 * @param h is the ndnd handle
 * @param msg points to a ndnd-encoded ContentObject containing a
 *          ForwardingEntry in its Content.
 * @param size is its size in bytes
 * @param reply_body is a buffer to hold the Content of the reply, as a
 *         ndnb-encoded ForwardingEntry
 * @returns 0 for success, negative for no response, or NDN_CONTENT_NACK to
 *         set the response type to NACK.
 *
 */
int
ndnd_req_unreg(struct ndnd_handle *h,
               const unsigned char *msg, size_t size,
               struct ndn_charbuf *reply_body)
{
    struct ndn_parsed_ContentObject pco = {0};
    int n_name_comp = 0;
    int res;
    const unsigned char *req;
    size_t req_size;
    size_t start;
    size_t stop;
    int found;
    struct ndn_forwarding_entry *forwarding_entry = NULL;
    struct face *face = NULL;
    struct face *reqface = NULL;
    struct ndn_indexbuf *comps = NULL;
    struct ndn_forwarding **p = NULL;
    struct ndn_forwarding *f = NULL;
    struct nameprefix_entry *npe = NULL;
    int nackallowed = 0;
    
    res = ndn_parse_ContentObject(msg, size, &pco, NULL);
    if (res < 0)
        goto Finish;        
    res = ndn_content_get_value(msg, size, &pco, &req, &req_size);
    if (res < 0)
        goto Finish;
    res = -1;
    forwarding_entry = ndn_forwarding_entry_parse(req, req_size);
    /* consider the source ... */
    reqface = face_from_faceid(h, h->interest_faceid);
    if (reqface == NULL || (reqface->flags & NDN_FACE_GG) == 0)
        goto Finish;
    nackallowed = 1;
    if (forwarding_entry == NULL || forwarding_entry->action == NULL)
        goto Finish;
    if (strcmp(forwarding_entry->action, "unreg") != 0)
        goto Finish;
    if (forwarding_entry->faceid == NDN_NOFACEID)
        goto Finish;
    if (forwarding_entry->name_prefix == NULL)
        goto Finish;
    res = check_forwarding_entry_ndndid(h, forwarding_entry, reply_body);
    if (res != 0)
        goto Finish;
    res = -1;
    face = face_from_faceid(h, forwarding_entry->faceid);
    if (face == NULL)
        goto Finish;
    comps = ndn_indexbuf_create();
    n_name_comp = ndn_name_split(forwarding_entry->name_prefix, comps);
    if (n_name_comp < 0)
        goto Finish;
    if (n_name_comp + 1 > comps->n)
        goto Finish;
    start = comps->buf[0];
    stop = comps->buf[n_name_comp];
    npe = hashtb_lookup(h->nameprefix_tab,
                        forwarding_entry->name_prefix->buf + start,
                        stop - start);
    if (npe == NULL)
        goto Finish;
    found = 0;
    p = &npe->forwarding;
    for (f = npe->forwarding; f != NULL; f = f->next) {
        if (f->faceid == forwarding_entry->faceid) {
            found = 1;
            if (h->debug & (2 | 4))
                ndnd_debug_ndnb(h, __LINE__, "prefix_unreg", face,
                                forwarding_entry->name_prefix->buf,
                                forwarding_entry->name_prefix->length);
            *p = f->next;
            free(f);
            f = NULL;
            h->forward_to_gen += 1;
            break;
        }
        p = &(f->next);
    }
    if (!found)
        goto Finish;    
    forwarding_entry->action = NULL;
    forwarding_entry->ndnd_id = h->ndnd_id;
    forwarding_entry->ndnd_id_size = sizeof(h->ndnd_id);
    res = ndnb_append_forwarding_entry(reply_body, forwarding_entry);
    if (res > 0)
        res = 0;
Finish:
    ndn_forwarding_entry_destroy(&forwarding_entry);
    ndn_indexbuf_destroy(&comps);
    if (nackallowed && res < 0)
        res = ndnd_nack(h, reply_body, 450, "could not unregister prefix");
    return((nackallowed || res <= 0) ? res : -1);
}

/**
 * Set up forward_to list for a name prefix entry.
 *
 * Recomputes the contents of npe->forward_to and npe->flags
 * from forwarding lists of npe and all of its ancestors.
 */
static void
update_forward_to(struct ndnd_handle *h, struct nameprefix_entry *npe)
{
    struct ndn_indexbuf *x = NULL;
    struct ndn_indexbuf *tap = NULL;
    struct ndn_forwarding *f = NULL;
    struct nameprefix_entry *p = NULL;
    unsigned tflags;
    unsigned wantflags;
    unsigned moreflags;
    unsigned lastfaceid;
    unsigned namespace_flags;

    x = npe->forward_to;
    if (x == NULL)
        npe->forward_to = x = ndn_indexbuf_create();
    else
        x->n = 0;
    wantflags = NDN_FORW_ACTIVE;
    lastfaceid = NDN_NOFACEID;
    namespace_flags = 0;
    for (p = npe; p != NULL; p = p->parent) {
        moreflags = NDN_FORW_CHILD_INHERIT;
        for (f = p->forwarding; f != NULL; f = f->next) {
            if (face_from_faceid(h, f->faceid) == NULL)
                continue;
            /* The sense of this flag needs to be inverted for this test */
            tflags = f->flags ^ NDN_FORW_CAPTURE_OK;
            if ((tflags & wantflags) == wantflags) {
                if (h->debug & 32)
                    ndnd_msg(h, "fwd.%d adding %u", __LINE__, f->faceid);
                ndn_indexbuf_set_insert(x, f->faceid);
                if ((f->flags & NDN_FORW_TAP) != 0) {
                    if (tap == NULL)
                        tap = ndn_indexbuf_create();
                    ndn_indexbuf_set_insert(tap, f->faceid);
                }
                if ((f->flags & NDN_FORW_LAST) != 0)
                    lastfaceid = f->faceid;
            }
            namespace_flags |= f->flags;
            if ((f->flags & NDN_FORW_CAPTURE) != 0)
                moreflags |= NDN_FORW_CAPTURE_OK;
        }
        wantflags |= moreflags;
    }
    if (lastfaceid != NDN_NOFACEID)
        ndn_indexbuf_move_to_end(x, lastfaceid);
    npe->flags = namespace_flags;
    npe->fgen = h->forward_to_gen;
    if (x->n == 0)
        ndn_indexbuf_destroy(&npe->forward_to);
    ndn_indexbuf_destroy(&npe->tap);
    npe->tap = tap;
}

/**
 * This is where we consult the interest forwarding table.
 * @param h is the ndnd handle
 * @param from is the handle for the originating face (may be NULL).
 * @param msg points to the ndnb-encoded interest message
 * @param pi must be the parse information for msg
 * @param npe should be the result of the prefix lookup
 * @result Newly allocated set of outgoing faceids (never NULL)
 */
static struct ndn_indexbuf *
get_outbound_faces(struct ndnd_handle *h,
    struct face *from,
    const unsigned char *msg,
    struct ndn_parsed_interest *pi,
    struct nameprefix_entry *npe)
{
    int checkmask = 0;
    int wantmask = 0;
    struct ndn_indexbuf *x;
    struct face *face;
    int i;
    int n;
    unsigned faceid;
    
    while (npe->parent != NULL && npe->forwarding == NULL)
        npe = npe->parent;
    if (npe->fgen != h->forward_to_gen)
        update_forward_to(h, npe);
    x = ndn_indexbuf_create();
    if (pi->scope == 0)
        return(x);
    if (from != NULL && (from->flags & NDN_FACE_GG) != 0) {
        i = ndn_fetch_tagged_nonNegativeInteger(NDN_DTAG_FaceID, msg,
              pi->offset[NDN_PI_B_OTHER], pi->offset[NDN_PI_E_OTHER]);
        if (i != -1) {
            faceid = i;
            ndn_indexbuf_append_element(x, faceid);
            if (h->debug & 32)
                ndnd_msg(h, "outbound.%d adding %u", __LINE__, faceid);
            return(x);
        }
    }
    if (npe->forward_to == NULL || npe->forward_to->n == 0)
        return(x);
    if ((npe->flags & NDN_FORW_LOCAL) != 0)
        checkmask = (from != NULL && (from->flags & NDN_FACE_GG) != 0) ? NDN_FACE_GG : (~0);
    else if (pi->scope == 1)
        checkmask = NDN_FACE_GG;
    else if (pi->scope == 2)
        checkmask = from ? (NDN_FACE_GG & ~(from->flags)) : ~0;
    wantmask = checkmask;
    if (wantmask == NDN_FACE_GG)
        checkmask |= NDN_FACE_DC;
    for (n = npe->forward_to->n, i = 0; i < n; i++) {
        faceid = npe->forward_to->buf[i];
        face = face_from_faceid(h, faceid);
        if (face != NULL && face != from &&
            ((face->flags & checkmask) == wantmask)) {
            if (h->debug & 32)
                ndnd_msg(h, "outbound.%d adding %u", __LINE__, face->faceid);
            ndn_indexbuf_append_element(x, face->faceid);
        }
    }
    return(x);
}

/**
 * Compute the delay until the next timed action on an interest.
 */
static int
ie_next_usec(struct ndnd_handle *h, struct interest_entry *ie,
             ndn_wrappedtime *expiry)
{
    struct pit_face_item *p;
    ndn_wrappedtime base;
    ndn_wrappedtime delta;
    ndn_wrappedtime mn;
    int ans;
    int debug = (h->debug & 32) != 0;
    const int horizon = 6 * WTHZ; /* complain if we get behind by too much */
    
    base = h->wtnow - horizon;
    mn = 600 * WTHZ + horizon;
    for (p = ie->pfl; p != NULL; p = p->next) {
        delta = p->expiry - base;
        if (delta >= 0x80000000 && (h->debug & 2) != 0)
            debug = 1;
        if (debug) {
            static const char fmt_ie_next_usec[] = 
              "ie_next_usec.%d now%+d i=%u f=%04x %u "
              " %02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X";
            ndnd_msg(h, fmt_ie_next_usec, __LINE__,
                     (int)delta - horizon, ie->serial, p->pfi_flags, p->faceid,
                     p->nonce[0], p->nonce[1], p->nonce[2], p->nonce[3],
                     p->nonce[4], p->nonce[5], p->nonce[6], p->nonce[7],
                     p->nonce[8], p->nonce[9], p->nonce[10], p->nonce[11]);
        }
        if (delta < mn)
            mn = delta;
    }
    if (mn < horizon)
        mn = 0;
    else
        mn -= horizon;
    ans = mn * (1000000 / WTHZ);
    if (expiry != NULL) {
        *expiry = h->wtnow + mn;
        if (debug)
            ndnd_msg(h, "ie_next_usec.%d expiry=%x", __LINE__,
                     (unsigned)*expiry);
    }
    if (debug)
        ndnd_msg(h, "ie_next_usec.%d %d usec", __LINE__, ans);
    return(ans);
}

/**
 *  Forward an interest message
 *
 *  x is downstream (the interest came x).
 *  p is upstream (the interest is to be forwarded to p).
 *  @returns p (or its reallocated replacement).
 */
static struct pit_face_item *
send_interest(struct ndnd_handle *h, struct interest_entry *ie,
              struct pit_face_item *x, struct pit_face_item *p)
{
    struct face *face = NULL;
    struct ndn_charbuf *c = h->send_interest_scratch;
    const intmax_t default_life = NDN_INTEREST_LIFETIME_SEC << 12;
    intmax_t lifetime = default_life;
    ndn_wrappedtime delta;
    size_t noncesize;
    
    face = face_from_faceid(h, p->faceid);
    if (face == NULL)
        return(p);
    h->interest_faceid = x->faceid; /* relevant if p is face 0 */
    p = pfi_copy_nonce(h, ie, p, x);
    delta = x->expiry - x->renewed;
    lifetime = (intmax_t)delta * 4096 / WTHZ;
    /* clip lifetime against various limits here */
    lifetime = (((lifetime + 511) >> 9) << 9); /* round up - 1/8 sec */
    p->renewed = h->wtnow;
    p->expiry = h->wtnow + (lifetime * WTHZ / 4096);
    ndn_charbuf_reset(c);
    if (lifetime != default_life)
        ndnb_append_tagged_binary_number(c, NDN_DTAG_InterestLifetime, lifetime);
    noncesize = p->pfi_flags & NDND_PFI_NONCESZ;
    if (noncesize != 0)
        ndnb_append_tagged_blob(c, NDN_DTAG_Nonce, p->nonce, noncesize);
    ndn_charbuf_append_closer(c);
    h->interests_sent += 1;
    p->pfi_flags |= NDND_PFI_UPENDING;
    p->pfi_flags &= ~(NDND_PFI_SENDUPST | NDND_PFI_UPHUNGRY);
    ndnd_meter_bump(h, face->meter[FM_INTO], 1);
    stuff_and_send(h, face, ie->interest_msg, ie->size - 1, c->buf, c->length, (h->debug & 2) ? "interest_to" : NULL, __LINE__);
    return(p);
}

/**
 * Find the entry for the longest name prefix that contains forwarding info
 */
struct nameprefix_entry *
get_fib_npe(struct ndnd_handle *h, struct interest_entry *ie)
{
    struct nameprefix_entry *npe;
    
    for (npe = ie->ll.npe; npe != NULL; npe = npe->parent)
        if (npe->forwarding != NULL)
            return(npe);
    return(NULL);
}

/** Implementation detail for strategy_settimer */
static int
strategy_timer(struct ndn_schedule *sched,
             void *clienth,
             struct ndn_scheduled_event *ev,
             int flags)
{
    struct ndnd_handle *h = clienth;
    struct interest_entry *ie = ev->evdata;
    struct ndn_strategy *s = &ie->strategy;

    if (s->ev == ev)
        s->ev = NULL;
    if (flags & NDN_SCHEDULE_CANCEL)
        return(0);
    strategy_callout(h, ie, (enum ndn_strategy_op)ev->evint);
    return(0);
}

/**
 * Schedule a strategy wakeup
 *
 * Any previously wakeup will be cancelled.
 */
static void
strategy_settimer(struct ndnd_handle *h, struct interest_entry *ie,
                  int usec, enum ndn_strategy_op op)
{
    struct ndn_strategy *s = &ie->strategy;
    
    if (s->ev != NULL)
        ndn_schedule_cancel(h->sched, s->ev);
    if (op == NDNST_NOP)
        return;
    s->ev = ndn_schedule_event(h->sched, usec, strategy_timer, ie, op);
}

/**
 * This implements the default strategy.
 *
 * Eventually there will be a way to have other strategies.
 */
static void
strategy_callout(struct ndnd_handle *h,
                 struct interest_entry *ie,
                 enum ndn_strategy_op op)
{
    struct pit_face_item *x = NULL;
    struct pit_face_item *p = NULL;
    struct nameprefix_entry *npe = NULL;
    struct ndn_indexbuf *tap = NULL;
    unsigned best = NDN_NOFACEID;
    unsigned randlow, randrange;
    unsigned nleft;
    unsigned amt;
    int usec;
    
    switch (op) {
        case NDNST_NOP:
            break;
        case NDNST_FIRST:
            
            npe = get_fib_npe(h, ie);
            if (npe != NULL)
                tap = npe->tap;
            npe = ie->ll.npe;
            best = npe->src;
            if (best == NDN_NOFACEID)
                best = npe->src = npe->osrc;
            /* Find our downstream; right now there should be just one. */
            for (x = ie->pfl; x != NULL; x = x->next)
                if ((x->pfi_flags & NDND_PFI_DNSTREAM) != 0)
                    break;
            if (x == NULL || (x->pfi_flags & NDND_PFI_PENDING) == 0) {
                ndnd_debug_ndnb(h, __LINE__, "canthappen", NULL,
                                ie->interest_msg, ie->size);
                break;
            }
            if (best == NDN_NOFACEID) {
                randlow = 4000;
                randrange = 75000;
            }
            else {
                randlow = npe->usec;
                if (randlow < 2000)
                    randlow = 100 + nrand48(h->seed) % 4096U;
                randrange = (randlow + 1) / 2;
            }
            nleft = 0;
            for (p = ie->pfl; p!= NULL; p = p->next) {
                if ((p->pfi_flags & NDND_PFI_UPSTREAM) != 0) {
                    if (p->faceid == best) {
                        p = send_interest(h, ie, x, p);
                        strategy_settimer(h, ie, npe->usec, NDNST_TIMER);
                    }
                    else if (ndn_indexbuf_member(tap, p->faceid) >= 0)
                        p = send_interest(h, ie, x, p);
                    else if (p->faceid == npe->osrc)
                        pfi_set_expiry_from_micros(h, ie, p, randlow);
                    else {
                        /* Want to preserve the order of the rest */
                        nleft++;
                        p->pfi_flags |= NDND_PFI_SENDUPST;
                    }
                }
            }
            if (nleft > 0) {
                /* Send remainder in order, with randomized timing */
                amt = (2 * randrange + nleft - 1) / nleft;
                if (amt == 0) amt = 1; /* paranoia - should never happen */
                usec = randlow;
                for (p = ie->pfl; p!= NULL; p = p->next) {
                    if ((p->pfi_flags & NDND_PFI_SENDUPST) != 0) {
                        pfi_set_expiry_from_micros(h, ie, p, usec);
                        usec += nrand48(h->seed) % amt;
                    }
                }
            }
            break;
        case NDNST_TIMER:
            /*
             * Our best choice has not responded in time.
             * Increase the predicted response.
             */
            adjust_predicted_response(h, ie, 1);
            break;
        case NDNST_SATISFIED:
            break;
        case NDNST_TIMEOUT:
            break;
    }
}

/**
 * Execute the next timed action on a propagating interest.
 */
static int
do_propagate(struct ndn_schedule *sched,
             void *clienth,
             struct ndn_scheduled_event *ev,
             int flags)
{
    struct ndnd_handle *h = clienth;
    struct interest_entry *ie = ev->evdata;
    struct face *face = NULL;
    struct pit_face_item *p = NULL;
    struct pit_face_item *next = NULL;
    struct pit_face_item *d[3] = { NULL, NULL, NULL };
    ndn_wrappedtime now;
    int next_delay;
    int i;
    int n;
    int pending;
    int upstreams;
    unsigned life;
    unsigned mn;
    unsigned rem;
    
    if (ie->ev == ev)
        ie->ev = NULL;
    else if (ie->ev != NULL) abort();
    if (flags & NDN_SCHEDULE_CANCEL)
        return(0);
    now = h->wtnow;  /* capture our reference */
    mn = 600 * WTHZ; /* keep track of when we should wake up again */
    pending = 0;
    n = 0;
    for (p = ie->pfl; p != NULL; p = next) {
        next = p->next;
        if ((p->pfi_flags & NDND_PFI_DNSTREAM) != 0) {
            if (wt_compare(p->expiry, now) <= 0) {
                if (h->debug & 2)
                    ndnd_debug_ndnb(h, __LINE__, "interest_expiry",
                                    face_from_faceid(h, p->faceid),
                                    ie->interest_msg, ie->size);
                pfi_destroy(h, ie, p);
                continue;
            }
            if ((p->pfi_flags & NDND_PFI_PENDING) == 0)
                continue;
            rem = p->expiry - now;
            if (rem < mn)
                mn = rem;
            pending++;
            /* If this downstream will expire soon, don't use it */
            life = p->expiry - p->renewed;
            if (rem * 8 <= life)
                continue;
            /* keep track of the 2 longest-lasting downstreams */
            for (i = n; i > 0 && wt_compare(d[i-1]->expiry, p->expiry) < 0; i--)
                d[i] = d[i-1];
            d[i] = p;
            if (n < 2)
                n++;
        }
    }
    /* Send the interests out */
    upstreams = 0; /* Count unexpired upstreams */
    for (p = ie->pfl; p != NULL; p = next) {
        next = p->next;
        if ((p->pfi_flags & NDND_PFI_UPSTREAM) == 0)
            continue;
        face = face_from_faceid(h, p->faceid);
        if (face == NULL || (face->flags & NDN_FACE_NOSEND) != 0) {
            pfi_destroy(h, ie, p);
            continue;
        }
        if ((face->flags & NDN_FACE_DC) != 0 &&
            (p->pfi_flags & NDND_PFI_DCFACE) == 0) {
            /* Add 60 ms extra delay before sending to a DC face */
            p->expiry += (60 * WTHZ + 999) / 1000;
            p->pfi_flags |= NDND_PFI_DCFACE;
        }
        if (wt_compare(now + 1, p->expiry) < 0) {
            /* Not expired yet */
            rem = p->expiry - now;
            if (rem < mn)
                mn = rem;
            upstreams++;
            continue;
        }
        for (i = 0; i < n; i++)
            if (d[i]->faceid != p->faceid)
                break;
        if (i < n) {
            p = send_interest(h, ie, d[i], p);
            if (ie->ev != NULL)
                ndn_schedule_cancel(h->sched, ie->ev);
            upstreams++;
            rem = p->expiry - now;
            if (rem < mn)
                mn = rem;
        }
        else {
            /* Upstream expired, but we have nothing to feed it. */
            p->pfi_flags |= NDND_PFI_UPHUNGRY;
        }
    }
    if (pending == 0 && upstreams == 0) {
        strategy_callout(h, ie, NDNST_TIMEOUT);
        consume_interest(h, ie);
        return(0);
    }
    /* Determine when we need to run again */
    if (mn == 0) abort();
    next_delay = mn * (1000000 / WTHZ);
    ev->evint = h->wtnow + mn;
    if (ie->ev != NULL) abort();
    ie->ev = ev;
    return(next_delay);
}

/**
 * Append an interest Nonce value that is useful for debugging.
 *
 * This does leak some information about the origin of interests, but it
 * also makes it easier to figure out what is happening.
 *
 * The debug nonce is 12 bytes long.  When converted to hexadecimal and
 * broken into fields (big-endian style), it looks like
 *
 *   IIIIII-PPPP-FFFF-SSss-XXXXXX
 *
 * where
 *   IIIIII - first 24 bits of the NDNDID.
 *   PPPP   - pid of the ndnd.
 *   FFFF   - 16 low-order bits of the faceid.
 *   SSss   - local time modulo 256 seconds, with 8 bits of fraction
 *   XXXXXX - 24 random bits.
 */
static int
ndnd_debug_nonce(struct ndnd_handle *h, struct face *face, unsigned char *s) {
    int i;
    
    for (i = 0; i < 3; i++)
        s[i] = h->ndnd_id[i];
    s[i++] = h->logpid >> 8;
    s[i++] = h->logpid;
    s[i++] = face->faceid >> 8;
    s[i++] = face->faceid;
    s[i++] = h->sec;
    s[i++] = h->usec * 256 / 1000000;
    for (; i < TYPICAL_NONCE_SIZE; i++)
        s[i] = nrand48(h->seed);
    return(i);
}

/**
 * Append a random interest Nonce value.
 *
 * For production use, although this uses a simple PRNG.
 */
static int
ndnd_plain_nonce(struct ndnd_handle *h, struct face *face, unsigned char *s) {
    int noncebytes = 6;
    int i;
    
    for (i = 0; i < noncebytes; i++)
        s[i] = nrand48(h->seed);
    return(i);
}

/**
 * Compare two wrapped time values
 *
 * @returns negative if a < b, 0 if a == b, positive if a > b
 */
static int
wt_compare(ndn_wrappedtime a, ndn_wrappedtime b)
{
    ndn_wrappedtime delta = a - b;
    if (delta >= 0x80000000)
        return(-1);
    return(delta > 0);
}

/** Used in just one place; could go away */
static struct pit_face_item *
pfi_create(struct ndnd_handle *h,
           unsigned faceid, unsigned flags,
           const unsigned char *nonce, size_t noncesize,
           struct pit_face_item **pp)
{
    struct pit_face_item *p;    
    size_t nsize = TYPICAL_NONCE_SIZE;
    
    if (noncesize > NDND_PFI_NONCESZ) return(NULL);
    if (noncesize > nsize)
        nsize = noncesize;
    p = calloc(1, sizeof(*p) + nsize - TYPICAL_NONCE_SIZE);
    if (p == NULL) return(NULL);
    p->faceid = faceid;
    p->renewed = h->wtnow;
    p->expiry = h->wtnow;
    p->pfi_flags = (flags & ~NDND_PFI_NONCESZ) + noncesize;
    memcpy(p->nonce, nonce, noncesize);
    if (pp != NULL) {
        p->next = *pp;
        *pp = p;
    }
    return(p);    
}

/** Remove the pit face item from the interest entry */
static void
pfi_destroy(struct ndnd_handle *h, struct interest_entry *ie,
            struct pit_face_item *p)
{
    struct face *face = NULL;
    struct pit_face_item **pp;
    
    for (pp = &ie->pfl; *pp != p; pp = &(*pp)->next) {
        if (*pp == NULL) abort();
    }
    if ((p->pfi_flags & NDND_PFI_PENDING) != 0) {
        face = face_from_faceid(h, p->faceid);
        if (face != NULL)
            face->pending_interests -= 1;
    }
    *pp = p->next;
    free(p);
}

/**
 * Find the pit face item with the given flag set,
 * or create it if not present.
 *
 * New items are appended to the end of the list
 */
static struct pit_face_item *
pfi_seek(struct ndnd_handle *h, struct interest_entry *ie,
         unsigned faceid, unsigned pfi_flag)
{
    struct pit_face_item *p;
    struct pit_face_item **pp;
    
    for (pp = &ie->pfl, p = ie->pfl; p != NULL; pp = &p->next, p = p->next) {
        if (p->faceid == faceid && (p->pfi_flags & pfi_flag) != 0)
            return(p);
    }
    p = calloc(1, sizeof(*p));
    if (p != NULL) {
        p->faceid = faceid;
        p->pfi_flags = pfi_flag;
        p->expiry = h->wtnow;
        *pp = p;
    }
    return(p);
}

/**
 * Set the expiry of the pit face item based upon an interest lifetime
 *
 * lifetime is in the units specified by the NDNx protocal - 1/4096 sec
 *
 * Also sets the renewed timestamp to now.
 */
static void
pfi_set_expiry_from_lifetime(struct ndnd_handle *h, struct interest_entry *ie,
                             struct pit_face_item *p, intmax_t lifetime)
{
    ndn_wrappedtime delta;
    ndn_wrappedtime odelta;
    int minlifetime = 4096 / 4;
    unsigned maxlifetime = 7 * 24 * 3600 * 4096U; /* one week */
    
    if (lifetime < minlifetime)
        lifetime = minlifetime;
    if (lifetime > maxlifetime)
        lifetime = maxlifetime;
    lifetime = (((lifetime + 511) >> 9) << 9); /* round up - 1/8 sec */
    delta = ((uintmax_t)lifetime * WTHZ + 4095U) / 4096U;
    odelta = p->expiry - h->wtnow;
    if (delta < odelta && odelta < 0x80000000)
        ndnd_msg(h, "pfi_set_expiry_from_lifetime.%d Oops", __LINE__);
    p->renewed = h->wtnow;
    p->expiry = h->wtnow + delta;
}

/**
 * Set the expiry of the pit face item using a time in microseconds from present
 *
 * Does not set the renewed timestamp.
 */
static void
pfi_set_expiry_from_micros(struct ndnd_handle *h, struct interest_entry *ie,
                           struct pit_face_item *p, unsigned micros)
{
    ndn_wrappedtime delta;
    
    delta = (micros + (1000000 / WTHZ - 1)) / (1000000 / WTHZ);
    p->expiry = h->wtnow + delta;
}

/**
 * Set the nonce in a pit face item
 *
 * @returns the replacement value, which is p unless the nonce will not fit.
 */
static struct pit_face_item *
pfi_set_nonce(struct ndnd_handle *h, struct interest_entry *ie,
             struct pit_face_item *p,
             const unsigned char *nonce, size_t noncesize)
{
    struct pit_face_item *q = NULL;    
    size_t nsize;
    
    nsize = (p->pfi_flags & NDND_PFI_NONCESZ);
    if (noncesize != nsize) {
        if (noncesize > TYPICAL_NONCE_SIZE) {
            /* Hard case, need to reallocate */
            q = pfi_create(h, p->faceid, p->pfi_flags,
                           nonce, noncesize, &p->next);
            if (q != NULL) {
                q->renewed = p->renewed;
                q->expiry = p->expiry;
                p->pfi_flags = 0; /* preserve pending interest accounting */
                pfi_destroy(h, ie, p);
            }
            return(q);
        }
        p->pfi_flags = (p->pfi_flags & ~NDND_PFI_NONCESZ) + noncesize;
    }
    memcpy(p->nonce, nonce, noncesize);
    return(p);
}

/**
 * Return true iff the nonce in p matches the given one.
 */
static int
pfi_nonce_matches(struct pit_face_item *p,
                  const unsigned char *nonce, size_t size)
{
    if (p == NULL)
        return(0);
    if (size != (p->pfi_flags & NDND_PFI_NONCESZ))
        return(0);
    if (memcmp(nonce, p->nonce, size) != 0)
        return(0);
    return(1);
}

/**
 * Copy a nonce from src into p
 *
 * @returns p (or its replacement)
 */
static struct pit_face_item *
pfi_copy_nonce(struct ndnd_handle *h, struct interest_entry *ie,
             struct pit_face_item *p, const struct pit_face_item *src)
{
    p = pfi_set_nonce(h, ie, p, src->nonce, src->pfi_flags & NDND_PFI_NONCESZ);
    return(p);
}

/**
 * True iff the nonce in p does not occur in any of the other items of the entry
 */
static int
pfi_unique_nonce(struct ndnd_handle *h, struct interest_entry *ie,
                 struct pit_face_item *p)
{
    struct pit_face_item *q = NULL;
    size_t nsize;
    
    if (p == NULL)
        return(1);
    nsize = (p->pfi_flags & NDND_PFI_NONCESZ);
    for (q = ie->pfl; q != NULL; q = q->next) {
        if (q != p && pfi_nonce_matches(q, p->nonce, nsize))
            return(0);
    }
    return(1);
}

/**
 * Schedules the propagation of an Interest message.
 */
static int
propagate_interest(struct ndnd_handle *h,
                   struct face *face,
                   unsigned char *msg,
                   struct ndn_parsed_interest *pi,
                   struct nameprefix_entry *npe)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct pit_face_item *p = NULL;
    struct interest_entry *ie = NULL;
    struct ndn_indexbuf *outbound = NULL;
    const unsigned char *nonce;
    intmax_t lifetime;
    ndn_wrappedtime expiry;
    unsigned char cb[TYPICAL_NONCE_SIZE];
    size_t noncesize;
    unsigned faceid;
    int i;
    int res;
    int usec;
    
    faceid = face->faceid;
    hashtb_start(h->interest_tab, e);
    res = hashtb_seek(e, msg, pi->offset[NDN_PI_B_InterestLifetime], 1);
    if (res < 0) goto Bail;
    ie = e->data;
    if (res == HT_NEW_ENTRY) {
        ie->serial = ++h->iserial;
        ie->strategy.birth = h->wtnow;
        ie->strategy.renewed = h->wtnow;
        ie->strategy.renewals = 0;
    }
    if (ie->interest_msg == NULL) {
        struct ndn_parsed_interest xpi = {0};
        int xres;
        link_interest_entry_to_nameprefix(h, ie, npe);
        ie->interest_msg = e->key;
        ie->size = pi->offset[NDN_PI_B_InterestLifetime] + 1;
        /* Ugly bit, this.  Clear the extension byte. */
        ((unsigned char *)(intptr_t)ie->interest_msg)[ie->size - 1] = 0;
        xres = ndn_parse_interest(ie->interest_msg, ie->size, &xpi, NULL);
        if (xres < 0) abort();
    }
    lifetime = ndn_interest_lifetime(msg, pi);
    outbound = get_outbound_faces(h, face, msg, pi, npe);
    if (outbound == NULL) goto Bail;
    nonce = msg + pi->offset[NDN_PI_B_Nonce];
    noncesize = pi->offset[NDN_PI_E_Nonce] - pi->offset[NDN_PI_B_Nonce];
    if (noncesize != 0)
        ndn_ref_tagged_BLOB(NDN_DTAG_Nonce, msg,
                            pi->offset[NDN_PI_B_Nonce],
                            pi->offset[NDN_PI_E_Nonce],
                            &nonce, &noncesize);
    else {
        /* This interest has no nonce; generate one before going on */
        noncesize = (h->noncegen)(h, face, cb);
        nonce = cb;
        nonce_ok(h, face, msg, pi, nonce, noncesize);
    }
    p = pfi_seek(h, ie, faceid, NDND_PFI_DNSTREAM);
    p = pfi_set_nonce(h, ie, p, nonce, noncesize);
    if (nonce == cb || pfi_unique_nonce(h, ie, p)) {
        ie->strategy.renewed = h->wtnow;
        ie->strategy.renewals += 1;
        if ((p->pfi_flags & NDND_PFI_PENDING) == 0) {
            p->pfi_flags |= NDND_PFI_PENDING;
            face->pending_interests += 1;
        }
    }
    else {
        /* Nonce has been seen before; do not forward. */
        p->pfi_flags |= NDND_PFI_SUPDATA;
    }
    pfi_set_expiry_from_lifetime(h, ie, p, lifetime);
    for (i = 0; i < outbound->n; i++) {
        p = pfi_seek(h, ie, outbound->buf[i], NDND_PFI_UPSTREAM);
        if (wt_compare(p->expiry, h->wtnow) < 0) {
            p->expiry = h->wtnow + 1; // ZZZZ - the +1 may be overkill here.
            p->pfi_flags &= ~NDND_PFI_UPHUNGRY;
        }
    }
    if (res == HT_NEW_ENTRY)
        strategy_callout(h, ie, NDNST_FIRST);
    usec = ie_next_usec(h, ie, &expiry);
    if (ie->ev != NULL && wt_compare(expiry + 2, ie->ev->evint) < 0)
        ndn_schedule_cancel(h->sched, ie->ev);
    if (ie->ev == NULL)
        ie->ev = ndn_schedule_event(h->sched, usec, do_propagate, ie, expiry);
Bail:
    hashtb_end(e);
    ndn_indexbuf_destroy(&outbound);
    return(res);
}

/**
 * We have a FIB change - accelerate forwarding of existing interests
 */
static void
update_npe_children(struct ndnd_handle *h, struct nameprefix_entry *npe, unsigned faceid)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct face *fface = NULL;
    struct ndn_parsed_interest pi;
    struct pit_face_item *p = NULL;
    struct interest_entry *ie = NULL;
    struct nameprefix_entry *x = NULL;
    struct ndn_indexbuf *ob = NULL;
    int i;
    unsigned usec = 6000; /*  a bit of time for prefix reg  */

    hashtb_start(h->interest_tab, e);
    for (ie = e->data; ie != NULL; ie = e->data) {
        for (x = ie->ll.npe; x != NULL; x = x->parent) {
            if (x == npe) {
                for (fface = NULL, p = ie->pfl; p != NULL; p = p->next) {
                    if (p->faceid == faceid) {
                        if ((p->pfi_flags & NDND_PFI_UPSTREAM) != 0) {
                            fface = NULL;
                            break;
                        }
                    }
                    else if ((p->pfi_flags & NDND_PFI_DNSTREAM) != 0) {
                        if (fface == NULL || (fface->flags & NDN_FACE_GG) == 0)
                            fface = face_from_faceid(h, p->faceid);
                    }
                }
                if (fface != NULL) {
                    ndn_parse_interest(ie->interest_msg, ie->size, &pi, NULL);
                    ob = get_outbound_faces(h, fface, ie->interest_msg,
                                            &pi, ie->ll.npe);
                    for (i = 0; i < ob->n; i++) {
                        if (ob->buf[i] == faceid) {
                            p = pfi_seek(h, ie, faceid, NDND_PFI_UPSTREAM);
                            if ((p->pfi_flags & NDND_PFI_UPENDING) == 0) {
                                p->expiry = h->wtnow + usec / (1000000 / WTHZ);
                                usec += 200;
                                if (ie->ev != NULL && wt_compare(p->expiry + 4, ie->ev->evint) < 0)
                                    ndn_schedule_cancel(h->sched, ie->ev);
                                if (ie->ev == NULL)
                                    ie->ev = ndn_schedule_event(h->sched, usec, do_propagate, ie, p->expiry);
                            }
                            break;
                        }
                    }
                    ndn_indexbuf_destroy(&ob);
                }
                break;
            }
        }
        hashtb_next(e);
    }
    hashtb_end(e);
}

/**
 * Creates a nameprefix entry if it does not already exist, together
 * with all of its parents.
 */
static int
nameprefix_seek(struct ndnd_handle *h, struct hashtb_enumerator *e,
                const unsigned char *msg, struct ndn_indexbuf *comps, int ncomps)
{
    int i;
    int base;
    int res = -1;
    struct nameprefix_entry *parent = NULL;
    struct nameprefix_entry *npe = NULL;
    struct ielinks *head = NULL;

    if (ncomps + 1 > comps->n)
        return(-1);
    base = comps->buf[0];
    for (i = 0; i <= ncomps; i++) {
        res = hashtb_seek(e, msg + base, comps->buf[i] - base, 0);
        if (res < 0)
            break;
        npe = e->data;
        if (res == HT_NEW_ENTRY) {
            head = &npe->ie_head;
            head->next = head;
            head->prev = head;
            head->npe = NULL;
            npe->parent = parent;
            npe->forwarding = NULL;
            npe->fgen = h->forward_to_gen - 1;
            npe->forward_to = NULL;
            if (parent != NULL) {
                parent->children++;
                npe->flags = parent->flags;
                npe->src = parent->src;
                npe->osrc = parent->osrc;
                npe->usec = parent->usec;
            }
            else {
                npe->src = npe->osrc = NDN_NOFACEID;
                npe->usec = (nrand48(h->seed) % 4096U) + 8192;
            }
        }
        parent = npe;
    }
    return(res);
}

// ZZZZ - not in the most obvious place - move closer to other content table stuff
// XXX - missing doxy
static struct content_entry *
next_child_at_level(struct ndnd_handle *h,
                    struct content_entry *content, int level)
{
    struct content_entry *next = NULL;
    struct ndn_charbuf *name;
    struct ndn_indexbuf *pred[NDN_SKIPLIST_MAX_DEPTH] = {NULL};
    int d;
    int res;
    
    if (content == NULL)
        return(NULL);
    if (content->ncomps <= level + 1)
        return(NULL);
    name = ndn_charbuf_create();
    ndn_name_init(name);
    res = ndn_name_append_components(name, content->key,
                                     content->comps[0],
                                     content->comps[level + 1]);
    if (res < 0) abort();
    res = ndn_name_next_sibling(name);
    if (res < 0) abort();
    if (h->debug & 8)
        ndnd_debug_ndnb(h, __LINE__, "child_successor", NULL,
                        name->buf, name->length);
    d = content_skiplist_findbefore(h, name->buf, name->length,
                                    NULL, pred);
    next = content_from_accession(h, pred[0]->buf[0]);
    if (next == content) {
        // XXX - I think this case should not occur, but just in case, avoid a loop.
        next = content_from_accession(h, content_skiplist_next(h, content));
        ndnd_debug_ndnb(h, __LINE__, "bump", NULL, next->key, next->size);
    }
    ndn_charbuf_destroy(&name);
    return(next);
}

/**
 * Check whether the interest should be dropped for local namespace reasons
 */
static int
drop_nonlocal_interest(struct ndnd_handle *h, struct nameprefix_entry *npe,
                       struct face *face,
                       unsigned char *msg, size_t size)
{
    if (npe->fgen != h->forward_to_gen)
        update_forward_to(h, npe);
    if ((npe->flags & NDN_FORW_LOCAL) != 0 &&
        (face->flags & NDN_FACE_GG) == 0) {
        ndnd_debug_ndnb(h, __LINE__, "interest_nonlocal", face, msg, size);
        h->interests_dropped += 1;
        return (1);
    }
    return(0);
}

/**
 * Process an incoming interest message.
 *
 * Parse the Interest and discard if it does not parse.
 * Check for correct scope (a scope 0 or scope 1 interest should never
 *  arrive on an external face).
 * Check for a duplicated Nonce, discard if it has been seen before.
 * Look up the name prefix.  Check for a local namespace and discard
 *  if an interest in a local namespace arrives from outside.
 * Consult the content store.  If a suitable matching ContentObject is found,
 *  prepare to send it, consuming this interest and any pending interests
 *  on that face that also match this object.
 * Otherwise, initiate propagation of the interest.
 */
static void
process_incoming_interest(struct ndnd_handle *h, struct face *face,
                          unsigned char *msg, size_t size)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_parsed_interest parsed_interest = {0};
    struct ndn_parsed_interest *pi = &parsed_interest;
    size_t namesize = 0;
    int k;
    int res;
    int try;
    int matched;
    int s_ok;
    struct interest_entry *ie = NULL;
    struct nameprefix_entry *npe = NULL;
    struct content_entry *content = NULL;
    struct content_entry *last_match = NULL;
    struct ndn_indexbuf *comps = indexbuf_obtain(h);
    if (size > 65535)
        res = -__LINE__;
    else
        res = ndn_parse_interest(msg, size, pi, comps);
    if (res < 0) {
        ndnd_msg(h, "error parsing Interest - code %d", res);
        ndn_indexbuf_destroy(&comps);
        return;
    }
    ndnd_meter_bump(h, face->meter[FM_INTI], 1);
    if (pi->scope >= 0 && pi->scope < 2 &&
             (face->flags & NDN_FACE_GG) == 0) {
        ndnd_debug_ndnb(h, __LINE__, "interest_outofscope", face, msg, size);
        h->interests_dropped += 1;
    }
    else {
        if (h->debug & (16 | 8 | 2))
            ndnd_debug_ndnb(h, __LINE__, "interest_from", face, msg, size);
        if (pi->magic < 20090701) {
            if (++(h->oldformatinterests) == h->oldformatinterestgrumble) {
                h->oldformatinterestgrumble *= 2;
                ndnd_msg(h, "downrev interests received: %d (%d)",
                         h->oldformatinterests,
                         pi->magic);
            }
        }
        namesize = comps->buf[pi->prefix_comps] - comps->buf[0];
        h->interests_accepted += 1;
        res = nonce_ok(h, face, msg, pi, NULL, 0);
        if (res == 0) {
            if (h->debug & 2)
                ndnd_debug_ndnb(h, __LINE__, "interest_dupnonce", face, msg, size);
            h->interests_dropped += 1;
            indexbuf_release(h, comps);
            return;
        }
        ie = hashtb_lookup(h->interest_tab, msg,
                           pi->offset[NDN_PI_B_InterestLifetime]);
        if (ie != NULL) {
            /* Since this is in the PIT, we do not need to check the CS. */
            indexbuf_release(h, comps);
            comps = NULL;
            npe = ie->ll.npe;
            if (drop_nonlocal_interest(h, npe, face, msg, size))
                return;
            propagate_interest(h, face, msg, pi, npe);
            return;
        }
        if (h->debug & 16) {
            /* Only print details that are not already presented */
            ndnd_msg(h,
                     "version: %d, "
                     "etc: %d bytes",
                     pi->magic,
                     pi->offset[NDN_PI_E_OTHER] - pi->offset[NDN_PI_B_OTHER]);
        }
        s_ok = (pi->answerfrom & NDN_AOK_STALE) != 0;
        matched = 0;
        hashtb_start(h->nameprefix_tab, e);
        res = nameprefix_seek(h, e, msg, comps, pi->prefix_comps);
        npe = e->data;
        if (npe == NULL || drop_nonlocal_interest(h, npe, face, msg, size))
            goto Bail;
        if ((pi->answerfrom & NDN_AOK_CS) != 0) {
            last_match = NULL;
            content = find_first_match_candidate(h, msg, pi);
            if (content != NULL && (h->debug & 8))
                ndnd_debug_ndnb(h, __LINE__, "first_candidate", NULL,
                                content->key,
                                content->size);
            if (content != NULL &&
                !content_matches_interest_prefix(h, content, msg, comps,
                                                 pi->prefix_comps)) {
                if (h->debug & 8)
                    ndnd_debug_ndnb(h, __LINE__, "prefix_mismatch", NULL,
                                    msg, size);
                content = NULL;
            }
            for (try = 0; content != NULL; try++) {
                if ((s_ok || (content->flags & NDN_CONTENT_ENTRY_STALE) == 0) &&
                    ndn_content_matches_interest(content->key,
                                       content->size,
                                       0, NULL, msg, size, pi)) {
                    if (h->debug & 8)
                        ndnd_debug_ndnb(h, __LINE__, "matches", NULL,
                                        content->key,
                                        content->size);
                    if ((pi->orderpref & 1) == 0) // XXX - should be symbolic
                        break;
                    last_match = content;
                    content = next_child_at_level(h, content, comps->n - 1);
                    goto check_next_prefix;
                }
                content = content_from_accession(h, content_skiplist_next(h, content));
            check_next_prefix:
                if (content != NULL &&
                    !content_matches_interest_prefix(h, content, msg,
                                                     comps, pi->prefix_comps)) {
                    if (h->debug & 8)
                        ndnd_debug_ndnb(h, __LINE__, "prefix_mismatch", NULL,
                                        content->key,
                                        content->size);
                    content = NULL;
                }
            }
            if (last_match != NULL)
                content = last_match;
            if (content != NULL) {
                /* Check to see if we are planning to send already */
                enum cq_delay_class c;
                for (c = 0, k = -1; c < NDN_CQ_N && k == -1; c++)
                    if (face->q[c] != NULL)
                        k = ndn_indexbuf_member(face->q[c]->send_queue, content->accession);
                if (k == -1) {
                    k = face_send_queue_insert(h, face, content);
                    if (k >= 0) {
                        if (h->debug & (32 | 8))
                            ndnd_debug_ndnb(h, __LINE__, "consume", face, msg, size);
                    }
                    /* Any other matched interests need to be consumed, too. */
                    match_interests(h, content, NULL, face, NULL);
                }
                if ((pi->answerfrom & NDN_AOK_EXPIRE) != 0)
                    mark_stale(h, content);
                matched = 1;
            }
        }
        if (!matched && npe != NULL && (pi->answerfrom & NDN_AOK_EXPIRE) == 0)
            propagate_interest(h, face, msg, pi, npe);
    Bail:
        hashtb_end(e);
    }
    indexbuf_release(h, comps);
}

/**
 * Mark content as stale
 */
static void
mark_stale(struct ndnd_handle *h, struct content_entry *content)
{
    ndn_accession_t accession = content->accession;
    if ((content->flags & NDN_CONTENT_ENTRY_STALE) != 0)
        return;
    if (h->debug & 4)
            ndnd_debug_ndnb(h, __LINE__, "stale", NULL,
                            content->key, content->size);
    content->flags |= NDN_CONTENT_ENTRY_STALE;
    h->n_stale++;
    if (accession < h->min_stale)
        h->min_stale = accession;
    if (accession > h->max_stale)
        h->max_stale = accession;
}

/**
 * Scheduled event that makes content stale when its FreshnessSeconds
 * has exported.
 *
 * May actually remove the content if we are over quota.
 */
static int
expire_content(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnd_handle *h = clienth;
    ndn_accession_t accession = ev->evint;
    struct content_entry *content = NULL;
    int res;
    unsigned n;
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    content = content_from_accession(h, accession);
    if (content != NULL) {
        n = hashtb_n(h->content_tab);
        /* The fancy test here lets existing stale content go away, too. */
        if ((n - (n >> 3)) > h->capacity ||
            (n > h->capacity && h->min_stale > h->max_stale)) {
            res = remove_content(h, content);
            if (res == 0)
                return(0);
        }
        mark_stale(h, content);
    }
    return(0);
}

/**
 * Schedules content expiration based on its FreshnessSeconds, and the
 * configured default and limit.
 */
static void
set_content_timer(struct ndnd_handle *h, struct content_entry *content,
                  struct ndn_parsed_ContentObject *pco)
{
    int seconds = 0;
    int microseconds = 0;
    size_t start = pco->offset[NDN_PCO_B_FreshnessSeconds];
    size_t stop  = pco->offset[NDN_PCO_E_FreshnessSeconds];
    if (h->force_zero_freshness) {
        /* Keep around for long enough to make it through the queues */
        microseconds = 8 * h->data_pause_microsec + 10000;
        goto Finish;
    }
    if (start == stop)
        seconds = h->tts_default;
    else
        seconds = ndn_fetch_tagged_nonNegativeInteger(
                NDN_DTAG_FreshnessSeconds,
                content->key,
                start, stop);
    if (seconds <= 0 || (h->tts_limit > 0 && seconds > h->tts_limit))
        seconds = h->tts_limit;
    if (seconds <= 0)
        return;
    if (seconds > ((1U<<31) / 1000000)) {
        ndnd_debug_ndnb(h, __LINE__, "FreshnessSeconds_too_large", NULL,
            content->key, pco->offset[NDN_PCO_E]);
        return;
    }
    microseconds = seconds * 1000000;
Finish:
    ndn_schedule_event(h->sched, microseconds,
                       &expire_content, NULL, content->accession);
}

/**
 * Process an arriving ContentObject.
 *
 * Parse the ContentObject and discard if it is not well-formed.
 *
 * Compute the digest.
 *
 * Look it up in the content store.  It it is already there, but is stale,
 * make it fresh again.  If it is not there, add it.
 *
 * Find the matching pending interests in the PIT and consume them,
 * queueing the ContentObject to be sent on the associated faces.
 * If no matches were found and the content object was new, discard remove it
 * from the store.
 *
 * XXX - the change to staleness should also not happen if there was no
 * matching PIT entry.
 */
static void
process_incoming_content(struct ndnd_handle *h, struct face *face,
                         unsigned char *wire_msg, size_t wire_size)
{
    unsigned char *msg;
    size_t size;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_parsed_ContentObject obj = {0};
    int res;
    size_t keysize = 0;
    size_t tailsize = 0;
    unsigned char *tail = NULL;
    struct content_entry *content = NULL;
    int i;
    struct ndn_indexbuf *comps = indexbuf_obtain(h);
    struct ndn_charbuf *cb = charbuf_obtain(h);
    
    msg = wire_msg;
    size = wire_size;
    
    res = ndn_parse_ContentObject(msg, size, &obj, comps);
    if (res < 0) {
        ndnd_msg(h, "error parsing ContentObject - code %d", res);
        goto Bail;
    }
    ndnd_meter_bump(h, face->meter[FM_DATI], 1);
    if (comps->n < 1 ||
        (keysize = comps->buf[comps->n - 1]) > 65535 - 36) {
        ndnd_msg(h, "ContentObject with keysize %lu discarded",
                 (unsigned long)keysize);
        ndnd_debug_ndnb(h, __LINE__, "oversize", face, msg, size);
        res = -__LINE__;
        goto Bail;
    }
    /* Make the ContentObject-digest name component explicit */
    ndn_digest_ContentObject(msg, &obj);
    if (obj.digest_bytes != 32) {
        ndnd_debug_ndnb(h, __LINE__, "indigestible", face, msg, size);
        goto Bail;
    }
    i = comps->buf[comps->n - 1];
    ndn_charbuf_append(cb, msg, i);
    ndn_charbuf_append_tt(cb, NDN_DTAG_Component, NDN_DTAG);
    ndn_charbuf_append_tt(cb, obj.digest_bytes, NDN_BLOB);
    ndn_charbuf_append(cb, obj.digest, obj.digest_bytes);
    ndn_charbuf_append_closer(cb);
    ndn_charbuf_append(cb, msg + i, size - i);
    msg = cb->buf;
    size = cb->length;
    res = ndn_parse_ContentObject(msg, size, &obj, comps);
    if (res < 0) abort(); /* must have just messed up */
    
    if (obj.magic != 20090415) {
        if (++(h->oldformatcontent) == h->oldformatcontentgrumble) {
            h->oldformatcontentgrumble *= 10;
            ndnd_msg(h, "downrev content items received: %d (%d)",
                     h->oldformatcontent,
                     obj.magic);
        }
    }
    if (h->debug & 4)
        ndnd_debug_ndnb(h, __LINE__, "content_from", face, msg, size);
    keysize = obj.offset[NDN_PCO_B_Content];
    tail = msg + keysize;
    tailsize = size - keysize;
    hashtb_start(h->content_tab, e);
    res = hashtb_seek(e, msg, keysize, tailsize);
    content = e->data;
    if (res == HT_OLD_ENTRY) {
        if (tailsize != e->extsize ||
              0 != memcmp(tail, ((unsigned char *)e->key) + keysize, tailsize)) {
            ndnd_msg(h, "ContentObject name collision!!!!!");
            ndnd_debug_ndnb(h, __LINE__, "new", face, msg, size);
            ndnd_debug_ndnb(h, __LINE__, "old", NULL, e->key, e->keysize + e->extsize);
            content = NULL;
            hashtb_delete(e); /* XXX - Mercilessly throw away both of them. */
            res = -__LINE__;
        }
        else if ((content->flags & NDN_CONTENT_ENTRY_STALE) != 0) {
            /* When old content arrives after it has gone stale, freshen it */
            // XXX - ought to do mischief checks before this
            content->flags &= ~NDN_CONTENT_ENTRY_STALE;
            h->n_stale--;
            set_content_timer(h, content, &obj);
            /* Record the new arrival face only if the old face is gone */
            // XXX - it is not clear that this is the most useful choice
            if (face_from_faceid(h, content->arrival_faceid) == NULL)
                content->arrival_faceid = face->faceid;
            // XXX - no counter for this case
        }
        else {
            h->content_dups_recvd++;
            ndnd_msg(h, "received duplicate ContentObject from %u (accession %llu)",
                     face->faceid, (unsigned long long)content->accession);
            ndnd_debug_ndnb(h, __LINE__, "dup", face, msg, size);
        }
    }
    else if (res == HT_NEW_ENTRY) {
        unsigned long n = hashtb_n(h->content_tab);
        if (n > h->capacity + (h->capacity >> 3))
            clean_needed(h);
        content->accession = ++(h->accession);
        content->arrival_faceid = face->faceid;
        enroll_content(h, content);
        if (content == content_from_accession(h, content->accession)) {
            content->ncomps = comps->n;
            content->comps = calloc(comps->n, sizeof(comps[0]));
            if (content->comps == NULL) {
                ndnd_msg(h, "could not enroll ContentObject (accession %llu)",
                         (unsigned long long)content->accession);
                content = NULL;
                hashtb_delete(e);
                res = -__LINE__;
                hashtb_end(e);
                goto Bail;
            }
        }
        content->key_size = e->keysize;
        content->size = e->keysize + e->extsize;
        content->key = e->key;
        for (i = 0; i < comps->n; i++)
            content->comps[i] = comps->buf[i];
        content_skiplist_insert(h, content);
        set_content_timer(h, content, &obj);
        /* Mark public keys supplied at startup as precious. */
        if (obj.type == NDN_CONTENT_KEY && content->accession <= (h->capacity + 7)/8)
            content->flags |= NDN_CONTENT_ENTRY_PRECIOUS;
    }
    hashtb_end(e);
Bail:
    indexbuf_release(h, comps);
    charbuf_release(h, cb);
    cb = NULL;
    if (res >= 0 && content != NULL) {
        int n_matches;
        enum cq_delay_class c;
        struct content_queue *q;
        n_matches = match_interests(h, content, &obj, NULL, face);
        if (res == HT_NEW_ENTRY) {
            if (n_matches < 0) {
                remove_content(h, content);
                return;
            }
            if (n_matches == 0 && (face->flags & NDN_FACE_GG) == 0) {
                content->flags |= NDN_CONTENT_ENTRY_SLOWSEND;
                ndn_indexbuf_append_element(h->unsol, content->accession);
            }
        }
        // ZZZZ - review whether the following is actually needed
        for (c = 0; c < NDN_CQ_N; c++) {
            q = face->q[c];
            if (q != NULL) {
                i = ndn_indexbuf_member(q->send_queue, content->accession);
                if (i >= 0) {
                    /*
                     * In the case this consumed any interests from this source,
                     * don't send the content back
                     */
                    if (h->debug & 8)
                        ndnd_debug_ndnb(h, __LINE__, "content_nosend", face, msg, size);
                    q->send_queue->buf[i] = 0;
                }
            }
        }
    }
}

/**
 * Process an incoming message.
 *
 * This is where we decide whether we have an Interest message,
 * a ContentObject, or something else.
 */
static void
process_input_message(struct ndnd_handle *h, struct face *face,
                      unsigned char *msg, size_t size, int pdu_ok)
{
    struct ndn_skeleton_decoder decoder = {0};
    struct ndn_skeleton_decoder *d = &decoder;
    ssize_t dres;
    enum ndn_dtag dtag;
    
    if ((face->flags & NDN_FACE_UNDECIDED) != 0) {
        face->flags &= ~NDN_FACE_UNDECIDED;
        if ((face->flags & NDN_FACE_LOOPBACK) != 0)
            face->flags |= NDN_FACE_GG;
        /* YYY This is the first place that we know that an inbound stream face is speaking NDNx protocol. */
        register_new_face(h, face);
    }
    d->state |= NDN_DSTATE_PAUSE;
    dres = ndn_skeleton_decode(d, msg, size);
    if (d->state < 0)
        abort(); /* cannot happen because of checks in caller */
    if (NDN_GET_TT_FROM_DSTATE(d->state) != NDN_DTAG) {
        ndnd_msg(h, "discarding unknown message; size = %lu", (unsigned long)size);
        // XXX - keep a count?
        return;
    }
    dtag = d->numval;
    switch (dtag) {
        case NDN_DTAG_NDNProtocolDataUnit:
            if (!pdu_ok)
                break;
            size -= d->index;
            if (size > 0)
                size--;
            msg += d->index;
            if ((face->flags & (NDN_FACE_LINK | NDN_FACE_GG)) != NDN_FACE_LINK) {
                face->flags |= NDN_FACE_LINK;
                face->flags &= ~NDN_FACE_GG;
                register_new_face(h, face);
            }
            memset(d, 0, sizeof(*d));
            while (d->index < size) {
                dres = ndn_skeleton_decode(d, msg + d->index, size - d->index);
                if (d->state != 0)
                    abort(); /* cannot happen because of checks in caller */
                /* The pdu_ok parameter limits the recursion depth */
                process_input_message(h, face, msg + d->index - dres, dres, 0);
            }
            return;
        case NDN_DTAG_Interest:
            process_incoming_interest(h, face, msg, size);
            return;
        case NDN_DTAG_ContentObject:
            process_incoming_content(h, face, msg, size);
            return;
        case NDN_DTAG_SequenceNumber:
            process_incoming_link_message(h, face, dtag, msg, size);
            return;
        default:
            break;
    }
    ndnd_msg(h, "discarding unknown message; dtag=%u, size = %lu",
             (unsigned)dtag,
             (unsigned long)size);
}

/**
 * Log a notification that a new datagram face has been created.
 */
static void
ndnd_new_face_msg(struct ndnd_handle *h, struct face *face)
{
    const struct sockaddr *addr = face->addr;
    int port = 0;
    const unsigned char *rawaddr = NULL;
    char printable[80];
    const char *peer = NULL;
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        rawaddr = (const unsigned char *)&addr6->sin6_addr;
        port = htons(addr6->sin6_port);
    }
    else if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        rawaddr = (const unsigned char *)&addr4->sin_addr.s_addr;
        port = htons(addr4->sin_port);
    }
    if (rawaddr != NULL)
        peer = inet_ntop(addr->sa_family, rawaddr, printable, sizeof(printable));
    if (peer == NULL)
        peer = "(unknown)";
    ndnd_msg(h,
             "accepted datagram client id=%d (flags=0x%x) %s port %d",
             face->faceid, face->flags, peer, port);
}

/**
 * Since struct sockaddr_in6 may contain fields that should not participate
 * in comparison / hash, ensure the undesired fields are zero.
 *
 * Per RFC 3493, sin6_flowinfo is zeroed.
 *
 * @param addr is the sockaddr (any family)
 * @param addrlen is its length
 * @param space points to a buffer that may be used for the result.
 * @returns either the original addr or a pointer to a scrubbed copy.
 *
 */
static struct sockaddr *
scrub_sockaddr(struct sockaddr *addr, socklen_t addrlen,
               struct sockaddr_in6 *space)
{
    struct sockaddr_in6 *src;
    struct sockaddr_in6 *dst;
    if (addr->sa_family != AF_INET6 || addrlen != sizeof(*space))
        return(addr);
    dst = space;
    src = (void *)addr;
    memset(dst, 0, addrlen);
    /* Copy first byte case sin6_len is used. */
    ((uint8_t *)dst)[0] = ((uint8_t *)src)[0];
    dst->sin6_family   = src->sin6_family;
    dst->sin6_port     = src->sin6_port;
    dst->sin6_addr     = src->sin6_addr;
    dst->sin6_scope_id = src->sin6_scope_id;
    return((struct sockaddr *)dst);
}

/**
 * Get (or create) the face associated with a given sockaddr.
 */
static struct face *
get_dgram_source(struct ndnd_handle *h, struct face *face,
                 struct sockaddr *addr, socklen_t addrlen, int why)
{
    struct face *source = NULL;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct sockaddr_in6 space;
    int res;
    if ((face->flags & NDN_FACE_DGRAM) == 0)
        return(face);
    if ((face->flags & NDN_FACE_MCAST) != 0)
        return(face);
    hashtb_start(h->dgram_faces, e);
    res = hashtb_seek(e, scrub_sockaddr(addr, addrlen, &space), addrlen, 0);
    if (res >= 0) {
        source = e->data;
        source->recvcount++;
        if (source->addr == NULL) {
            source->addr = e->key;
            source->addrlen = e->keysize;
            source->recv_fd = face->recv_fd;
            source->sendface = face->faceid;
            init_face_flags(h, source, NDN_FACE_DGRAM);
            if (why == 1 && (source->flags & NDN_FACE_LOOPBACK) != 0)
                source->flags |= NDN_FACE_GG;
            res = enroll_face(h, source);
            if (res == -1) {
                hashtb_delete(e);
                source = NULL;
            }
            else
                ndnd_new_face_msg(h, source);
        }
    }
    hashtb_end(e);
    return(source);
}

/**
 * Break up data in a face's input buffer buffer into individual messages,
 * and call process_input_message on each one.
 *
 * This is used to handle things originating from the internal client -
 * its output is input for face 0.
 */
static void
process_input_buffer(struct ndnd_handle *h, struct face *face)
{
    unsigned char *msg;
    size_t size;
    ssize_t dres;
    struct ndn_skeleton_decoder *d;

    if (face == NULL || face->inbuf == NULL)
        return;
    d = &face->decoder;
    msg = face->inbuf->buf;
    size = face->inbuf->length;
    while (d->index < size) {
        dres = ndn_skeleton_decode(d, msg + d->index, size - d->index);
        if (d->state != 0)
            break;
        process_input_message(h, face, msg + d->index - dres, dres, 0);
    }
    if (d->index != size) {
        ndnd_msg(h, "protocol error on face %u (state %d), discarding %d bytes",
                     face->faceid, d->state, (int)(size - d->index));
        // XXX - perhaps this should be a fatal error.
    }
    face->inbuf->length = 0;
    memset(d, 0, sizeof(*d));
}

/**
 * Process the input from a socket.
 *
 * The socket has been found ready for input by the poll call.
 * Decide what face it corresponds to, and after checking for exceptional
 * cases, receive data, parse it into ndnb-encoded messages, and call
 * process_input_message for each one.
 */
static void
process_input(struct ndnd_handle *h, int fd)
{
    struct face *face = NULL;
    struct face *source = NULL;
    ssize_t res;
    ssize_t dres;
    ssize_t msgstart;
    unsigned char *buf;
    struct ndn_skeleton_decoder *d;
    struct sockaddr_storage sstor;
    socklen_t addrlen = sizeof(sstor);
    struct sockaddr *addr = (struct sockaddr *)&sstor;
    int err = 0;
    socklen_t err_sz;
    
    face = hashtb_lookup(h->faces_by_fd, &fd, sizeof(fd));
    if (face == NULL)
        return;
    if ((face->flags & (NDN_FACE_DGRAM | NDN_FACE_PASSIVE)) == NDN_FACE_PASSIVE) {
        accept_connection(h, fd);
        check_comm_file(h);
        return;
    }
    err_sz = sizeof(err);
    res = getsockopt(face->recv_fd, SOL_SOCKET, SO_ERROR, &err, &err_sz);
    if (res >= 0 && err != 0) {
        ndnd_msg(h, "error on face %u: %s (%d)", face->faceid, strerror(err), err);
        if (err == ETIMEDOUT && (face->flags & NDN_FACE_CONNECTING) != 0) {
            shutdown_client_fd(h, fd);
            return;
        }
    }
    d = &face->decoder;
    if (face->inbuf == NULL)
        face->inbuf = ndn_charbuf_create();
    if (face->inbuf->length == 0)
        memset(d, 0, sizeof(*d));
    buf = ndn_charbuf_reserve(face->inbuf, 8800);
    memset(&sstor, 0, sizeof(sstor));
    res = recvfrom(face->recv_fd, buf, face->inbuf->limit - face->inbuf->length,
            /* flags */ 0, addr, &addrlen);
    if (res == -1)
        ndnd_msg(h, "recvfrom face %u :%s (errno = %d)",
                    face->faceid, strerror(errno), errno);
    else if (res == 0 && (face->flags & NDN_FACE_DGRAM) == 0)
        shutdown_client_fd(h, fd);
    else {
        source = get_dgram_source(h, face, addr, addrlen, (res == 1) ? 1 : 2);
        ndnd_meter_bump(h, source->meter[FM_BYTI], res);
        source->recvcount++;
        source->surplus = 0; // XXX - we don't actually use this, except for some obscure messages.
        if (res <= 1 && (source->flags & NDN_FACE_DGRAM) != 0) {
            // XXX - If the initial heartbeat gets missed, we don't realize the locality of the face.
            if (h->debug & 128)
                ndnd_msg(h, "%d-byte heartbeat on %d", (int)res, source->faceid);
            return;
        }
        face->inbuf->length += res;
        msgstart = 0;
        if (((face->flags & NDN_FACE_UNDECIDED) != 0 &&
             face->inbuf->length >= 6 &&
             0 == memcmp(face->inbuf->buf, "GET ", 4))) {
            ndnd_stats_handle_http_connection(h, face);
            return;
        }
        dres = ndn_skeleton_decode(d, buf, res);
        while (d->state == 0) {
            process_input_message(h, source,
                                  face->inbuf->buf + msgstart,
                                  d->index - msgstart,
                                  (face->flags & NDN_FACE_LOCAL) != 0);
            msgstart = d->index;
            if (msgstart == face->inbuf->length) {
                face->inbuf->length = 0;
                return;
            }
            dres = ndn_skeleton_decode(d,
                    face->inbuf->buf + d->index, // XXX - msgstart and d->index are the same here - use msgstart
                    res = face->inbuf->length - d->index);  // XXX - why is res set here?
        }
        if ((face->flags & NDN_FACE_DGRAM) != 0) {
            ndnd_msg(h, "protocol error on face %u, discarding %u bytes",
                source->faceid,
                (unsigned)(face->inbuf->length));  // XXX - Should be face->inbuf->length - d->index (or msgstart)
            face->inbuf->length = 0;
            /* XXX - should probably ignore this source for a while */
            return;
        }
        else if (d->state < 0) {
            ndnd_msg(h, "protocol error on face %u", source->faceid);
            shutdown_client_fd(h, fd);
            return;
        }
        if (msgstart < face->inbuf->length && msgstart > 0) {
            /* move partial message to start of buffer */
            memmove(face->inbuf->buf, face->inbuf->buf + msgstart,
                face->inbuf->length - msgstart);
            face->inbuf->length -= msgstart;
            d->index -= msgstart;
        }
    }
}

/**
 * Process messages from our internal client.
 *
 * The internal client's output is input to us.
 */
static void
process_internal_client_buffer(struct ndnd_handle *h)
{
    struct face *face = h->face0;
    if (face == NULL)
        return;
    face->inbuf = ndn_grab_buffered_output(h->internal_client);
    if (face->inbuf == NULL)
        return;
    ndnd_meter_bump(h, face->meter[FM_BYTI], face->inbuf->length);
    process_input_buffer(h, face);
    ndn_charbuf_destroy(&(face->inbuf));
}

/**
 * Scheduled event for deferred processing of internal client
 */
static int
process_icb_action(
    struct ndn_schedule *sched,
    void *clienth,
    struct ndn_scheduled_event *ev,
    int flags)
{
    struct ndnd_handle *h = clienth;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    process_internal_client_buffer(h);
    return(0);
}

/**
 * Schedule the processing of internal client results
 *
 * This little dance keeps us from destroying an interest
 * entry while we are in the middle of processing it.
 */
void
ndnd_internal_client_has_somthing_to_say(struct ndnd_handle *h)
{
    ndn_schedule_event(h->sched, 0, process_icb_action, NULL, 0);
}

/**
 * Handle errors after send() or sendto().
 * @returns -1 if error has been dealt with, or 0 to defer sending.
 */
static int
handle_send_error(struct ndnd_handle *h, int errnum, struct face *face,
                  const void *data, size_t size)
{
    int res = -1;
    if (errnum == EAGAIN) {
        res = 0;
    }
    else if (errnum == EPIPE) {
        face->flags |= NDN_FACE_NOSEND;
        face->outbufindex = 0;
        ndn_charbuf_destroy(&face->outbuf);
    }
    else {
        ndnd_msg(h, "send to face %u failed: %s (errno = %d)",
                 face->faceid, strerror(errnum), errnum);
        if (errnum == EISCONN)
            res = 0;
    }
    return(res);
}

/**
 * Determine what socket to use to send on a face.
 *
 * For streams, this just returns the associated fd.
 *
 * For datagrams, one fd may be in use for many faces, so we need to find the
 * right one to use.
 *
 * This is not as smart as it should be for situations where
 * NDND_LISTEN_ON has been specified.
 */
static int
sending_fd(struct ndnd_handle *h, struct face *face)
{
    struct face *out = NULL;
    if (face->sendface == face->faceid)
        return(face->recv_fd);
    out = face_from_faceid(h, face->sendface);
    if (out != NULL)
        return(out->recv_fd);
    face->sendface = NDN_NOFACEID;
    if (face->addr != NULL) {
        switch (face->addr->sa_family) {
            case AF_INET:
                face->sendface = h->ipv4_faceid;
                break;
            case AF_INET6:
                face->sendface = h->ipv6_faceid;
                break;
            default:
                break;
        }
    }
    out = face_from_faceid(h, face->sendface);
    if (out != NULL)
        return(out->recv_fd);
    return(-1);
}

/**
 * Send data to the face.
 *
 * No direct error result is provided; the face state is updated as needed.
 */
void
ndnd_send(struct ndnd_handle *h,
          struct face *face,
          const void *data, size_t size)
{
    ssize_t res;
    int fd;
    int bcast = 0;
    
    if ((face->flags & NDN_FACE_NOSEND) != 0)
        return;
    face->surplus++;
    if (face->outbuf != NULL) {
        ndn_charbuf_append(face->outbuf, data, size);
        return;
    }
    if (face == h->face0) {
        ndnd_meter_bump(h, face->meter[FM_BYTO], size);
        ndn_dispatch_message(h->internal_client, (void *)data, size);
        ndnd_internal_client_has_somthing_to_say(h);
        return;
    }
    if ((face->flags & NDN_FACE_DGRAM) == 0)
        res = send(face->recv_fd, data, size, 0);
    else {
        fd = sending_fd(h, face);
        if ((face->flags & NDN_FACE_BC) != 0) {
            bcast = 1;
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
        }
        res = sendto(fd, data, size, 0, face->addr, face->addrlen);
        if (res == -1 && errno == EACCES &&
            (face->flags & (NDN_FACE_BC | NDN_FACE_NBC)) == 0) {
            bcast = 1;
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
            res = sendto(fd, data, size, 0, face->addr, face->addrlen);
            if (res == -1)
                face->flags |= NDN_FACE_NBC; /* did not work, do not try */
            else
                face->flags |= NDN_FACE_BC; /* remember for next time */
        }
        if (bcast != 0) {
            bcast = 0;
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
        }
    }
    if (res > 0)
        ndnd_meter_bump(h, face->meter[FM_BYTO], res);
    if (res == size)
        return;
    if (res == -1) {
        res = handle_send_error(h, errno, face, data, size);
        if (res == -1)
            return;
    }
    if ((face->flags & NDN_FACE_DGRAM) != 0) {
        ndnd_msg(h, "sendto short");
        return;
    }
    face->outbufindex = 0;
    face->outbuf = ndn_charbuf_create();
    if (face->outbuf == NULL) {
        ndnd_msg(h, "do_write: %s", strerror(errno));
        return;
    }
    ndn_charbuf_append(face->outbuf,
                       ((const unsigned char *)data) + res, size - res);
}

/**
 * Do deferred sends.
 *
 * These can only happen on streams, after there has been a partial write.
 */
static void
do_deferred_write(struct ndnd_handle *h, int fd)
{
    /* This only happens on connected sockets */
    ssize_t res;
    struct face *face = hashtb_lookup(h->faces_by_fd, &fd, sizeof(fd));
    if (face == NULL)
        return;
    if (face->outbuf != NULL) {
        ssize_t sendlen = face->outbuf->length - face->outbufindex;
        if (sendlen > 0) {
            res = send(fd, face->outbuf->buf + face->outbufindex, sendlen, 0);
            if (res == -1) {
                if (errno == EPIPE) {
                    face->flags |= NDN_FACE_NOSEND;
                    face->outbufindex = 0;
                    ndn_charbuf_destroy(&face->outbuf);
                    return;
                }
                ndnd_msg(h, "send: %s (errno = %d)", strerror(errno), errno);
                shutdown_client_fd(h, fd);
                return;
            }
            if (res == sendlen) {
                face->outbufindex = 0;
                ndn_charbuf_destroy(&face->outbuf);
                if ((face->flags & NDN_FACE_CLOSING) != 0)
                    shutdown_client_fd(h, fd);
                return;
            }
            face->outbufindex += res;
            return;
        }
        face->outbufindex = 0;
        ndn_charbuf_destroy(&face->outbuf);
    }
    if ((face->flags & NDN_FACE_CLOSING) != 0)
        shutdown_client_fd(h, fd);
    else if ((face->flags & NDN_FACE_CONNECTING) != 0) {
        face->flags &= ~NDN_FACE_CONNECTING;
        ndnd_face_status_change(h, face->faceid);
    }
    else
        ndnd_msg(h, "ndnd:do_deferred_write: something fishy on %d", fd);
}

/**
 * Set up the array of fd descriptors for the poll(2) call.
 *
 * Arrange the array so that multicast receivers are early, so that
 * if the same packet arrives on both a multicast socket and a
 * normal socket, we will count is as multicast.
 */
static void
prepare_poll_fds(struct ndnd_handle *h)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    int i, j, k;
    if (hashtb_n(h->faces_by_fd) != h->nfds) {
        h->nfds = hashtb_n(h->faces_by_fd);
        h->fds = realloc(h->fds, h->nfds * sizeof(h->fds[0]));
        memset(h->fds, 0, h->nfds * sizeof(h->fds[0]));
    }
    for (i = 0, k = h->nfds, hashtb_start(h->faces_by_fd, e);
         i < k && e->data != NULL; hashtb_next(e)) {
        struct face *face = e->data;
        if (face->flags & NDN_FACE_MCAST)
            j = i++;
        else
            j = --k;
        h->fds[j].fd = face->recv_fd;
        h->fds[j].events = ((face->flags & NDN_FACE_NORECV) == 0) ? POLLIN : 0;
        if ((face->outbuf != NULL || (face->flags & NDN_FACE_CLOSING) != 0))
            h->fds[j].events |= POLLOUT;
    }
    hashtb_end(e);
    if (i < k)
        abort();
}

/**
 * Run the main loop of the ndnd
 */
void
ndnd_run(struct ndnd_handle *h)
{
    int i;
    int res;
    int timeout_ms = -1;
    int prev_timeout_ms = -1;
    int usec;
    for (h->running = 1; h->running;) {
        process_internal_client_buffer(h);
        usec = ndn_schedule_run(h->sched);
        timeout_ms = (usec < 0) ? -1 : ((usec + 960) / 1000);
        if (timeout_ms == 0 && prev_timeout_ms == 0)
            timeout_ms = 1;
        process_internal_client_buffer(h);
        prepare_poll_fds(h);
        if (0) ndnd_msg(h, "at ndnd.c:%d poll(h->fds, %d, %d)", __LINE__, h->nfds, timeout_ms);
        res = poll(h->fds, h->nfds, timeout_ms);
        prev_timeout_ms = ((res == 0) ? timeout_ms : 1);
        if (-1 == res) {
            ndnd_msg(h, "poll: %s (errno = %d)", strerror(errno), errno);
            sleep(1);
            continue;
        }
        if (res > 0) {
            /* we need a fresh current time for setting interest expiries */
            struct ndn_timeval dummy;
            h->ticktock.gettime(&h->ticktock, &dummy);
        }
        for (i = 0; res > 0 && i < h->nfds; i++) {
            if (h->fds[i].revents != 0) {
                res--;
                if (h->fds[i].revents & (POLLERR | POLLNVAL | POLLHUP)) {
                    if (h->fds[i].revents & (POLLIN))
                        process_input(h, h->fds[i].fd);
                    else
                        shutdown_client_fd(h, h->fds[i].fd);
                    continue;
                }
                if (h->fds[i].revents & (POLLOUT))
                    do_deferred_write(h, h->fds[i].fd);
                else if (h->fds[i].revents & (POLLIN))
                    process_input(h, h->fds[i].fd);
            }
        }
    }
}

/**
 * Reseed our pseudo-random number generator.
 */
static void
ndnd_reseed(struct ndnd_handle *h)
{
    int fd;
    ssize_t res;
    
    res = -1;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        res = read(fd, h->seed, sizeof(h->seed));
        close(fd);
    }
    if (res != sizeof(h->seed)) {
        h->seed[1] = (unsigned short)getpid(); /* better than no entropy */
        h->seed[2] = (unsigned short)time(NULL);
    }
    /*
     * The call to seed48 is needed by cygwin, and should be harmless
     * on other platforms.
     */
    seed48(h->seed);
}

/**
 * Get the name of our unix-domain socket listener.
 *
 * Uses the library to generate the name, using the environment.
 * @returns a newly-allocated nul-terminated string.
 */
static char *
ndnd_get_local_sockname(void)
{
    struct sockaddr_un sa;
    ndn_setup_sockaddr_un(NULL, &sa);
    return(strdup(sa.sun_path));
}

/**
 * Get the time.
 *
 * This is used to supply the clock for our scheduled events.
 */
static void
ndnd_gettime(const struct ndn_gettime *self, struct ndn_timeval *result)
{
    struct ndnd_handle *h = self->data;
    struct timeval now = {0};
    long int sdelta;
    int udelta;
    ndn_wrappedtime delta;
    
    gettimeofday(&now, 0);
    result->s = now.tv_sec;
    result->micros = now.tv_usec;
    sdelta = now.tv_sec - h->sec;
    udelta = now.tv_usec + h->sliver - h->usec;
    h->sec = now.tv_sec;
    h->usec = now.tv_usec;
    while (udelta < 0) {
        udelta += 1000000;
        sdelta -= 1;
    }
    /* avoid letting time run backwards or taking huge steps */
    if (sdelta < 0)
        delta = 1;
    else if (sdelta >= (1U << 30) / WTHZ)
        delta = (1U << 30) / WTHZ;
    else {
        delta = (unsigned)udelta / (1000000U / WTHZ);
        h->sliver = udelta - delta * (1000000U / WTHZ);
        delta += (unsigned)sdelta * WTHZ;
    }
    h->wtnow += delta;
}

/**
 * Set IPV6_V6ONLY on a socket.
 *
 * The handle is used for error reporting.
 */
void
ndnd_setsockopt_v6only(struct ndnd_handle *h, int fd)
{
    int yes = 1;
    int res = 0;
#ifdef IPV6_V6ONLY
    res = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
#endif
    if (res == -1)
        ndnd_msg(h, "warning - could not set IPV6_V6ONLY on fd %d: %s",
                 fd, strerror(errno));
}

/**
 * Translate an address family constant to a string.
 */
static const char *
af_name(int family)
{
    switch (family) {
        case AF_INET:
            return("ipv4");
        case AF_INET6:
            return("ipv6");
        default:
            return("");
    }
}

/**
 * Create the standard ipv4 and ipv6 bound ports.
 */
static int
ndnd_listen_on_wildcards(struct ndnd_handle *h)
{
    int fd;
    int res;
    int whichpf;
    struct addrinfo hints = {0};
    struct addrinfo *addrinfo = NULL;
    struct addrinfo *a;
    
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    for (whichpf = 0; whichpf < 2; whichpf++) {
        hints.ai_family = whichpf ? PF_INET6 : PF_INET;
        res = getaddrinfo(NULL, h->portstr, &hints, &addrinfo);
        if (res == 0) {
            for (a = addrinfo; a != NULL; a = a->ai_next) {
                fd = socket(a->ai_family, SOCK_DGRAM, 0);
                if (fd != -1) {
                    struct face *face = NULL;
                    int yes = 1;
                    int rcvbuf = 0;
                    socklen_t rcvbuf_sz;
                    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
                    rcvbuf_sz = sizeof(rcvbuf);
                    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbuf_sz);
                    if (a->ai_family == AF_INET6)
                        ndnd_setsockopt_v6only(h, fd);
                    res = bind(fd, a->ai_addr, a->ai_addrlen);
                    if (res != 0) {
                        close(fd);
                        continue;
                    }
                    face = record_connection(h, fd,
                                             a->ai_addr, a->ai_addrlen,
                                             NDN_FACE_DGRAM | NDN_FACE_PASSIVE);
                    if (face == NULL) {
                        close(fd);
                        continue;
                    }
                    if (a->ai_family == AF_INET)
                        h->ipv4_faceid = face->faceid;
                    else
                        h->ipv6_faceid = face->faceid;
                    ndnd_msg(h, "accepting %s datagrams on fd %d rcvbuf %d",
                             af_name(a->ai_family), fd, rcvbuf);
                }
            }
            for (a = addrinfo; a != NULL; a = a->ai_next) {
                fd = socket(a->ai_family, SOCK_STREAM, 0);
                if (fd != -1) {
                    int yes = 1;
                    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
                    if (a->ai_family == AF_INET6)
                        ndnd_setsockopt_v6only(h, fd);
                    res = bind(fd, a->ai_addr, a->ai_addrlen);
                    if (res != 0) {
                        close(fd);
                        continue;
                    }
                    res = listen(fd, 30);
                    if (res == -1) {
                        close(fd);
                        continue;
                    }
                    record_connection(h, fd,
                                      a->ai_addr, a->ai_addrlen,
                                      NDN_FACE_PASSIVE);
                    ndnd_msg(h, "accepting %s connections on fd %d",
                             af_name(a->ai_family), fd);
                }
            }
            freeaddrinfo(addrinfo);
        }
    }
    return(0);
}

/**
 * Create a tcp listener and a bound udp socket on the given address
 */
static int
ndnd_listen_on_address(struct ndnd_handle *h, const char *addr)
{
    int fd;
    int res;
    struct addrinfo hints = {0};
    struct addrinfo *addrinfo = NULL;
    struct addrinfo *a;
    int ok = 0;
    
    ndnd_msg(h, "listen_on %s", addr);
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    res = getaddrinfo(addr, h->portstr, &hints, &addrinfo);
    if (res == 0) {
        for (a = addrinfo; a != NULL; a = a->ai_next) {
            fd = socket(a->ai_family, SOCK_DGRAM, 0);
            if (fd != -1) {
                struct face *face = NULL;
                int yes = 1;
                int rcvbuf = 0;
                socklen_t rcvbuf_sz;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
                rcvbuf_sz = sizeof(rcvbuf);
                getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbuf_sz);
                if (a->ai_family == AF_INET6)
                    ndnd_setsockopt_v6only(h, fd);
                res = bind(fd, a->ai_addr, a->ai_addrlen);
                if (res != 0) {
                    close(fd);
                    continue;
                }
                face = record_connection(h, fd,
                                         a->ai_addr, a->ai_addrlen,
                                         NDN_FACE_DGRAM | NDN_FACE_PASSIVE);
                if (face == NULL) {
                    close(fd);
                    continue;
                }
                if (a->ai_family == AF_INET)
                    h->ipv4_faceid = face->faceid;
                else
                    h->ipv6_faceid = face->faceid;
                ndnd_msg(h, "accepting %s datagrams on fd %d rcvbuf %d",
                             af_name(a->ai_family), fd, rcvbuf);
                ok++;
            }
        }
        for (a = addrinfo; a != NULL; a = a->ai_next) {
            fd = socket(a->ai_family, SOCK_STREAM, 0);
            if (fd != -1) {
                int yes = 1;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
                if (a->ai_family == AF_INET6)
                    ndnd_setsockopt_v6only(h, fd);
                res = bind(fd, a->ai_addr, a->ai_addrlen);
                if (res != 0) {
                    close(fd);
                    continue;
                }
                res = listen(fd, 30);
                if (res == -1) {
                    close(fd);
                    continue;
                }
                record_connection(h, fd,
                                  a->ai_addr, a->ai_addrlen,
                                  NDN_FACE_PASSIVE);
                ndnd_msg(h, "accepting %s connections on fd %d",
                         af_name(a->ai_family), fd);
                ok++;
            }
        }
        freeaddrinfo(addrinfo);
    }
    return(ok > 0 ? 0 : -1);
}

/**
 * Create listeners or bound udp ports using the given addresses
 *
 * The addresses may be separated by whitespace, commas, or semicolons.
 */
static int
ndnd_listen_on(struct ndnd_handle *h, const char *addrs)
{
    unsigned char ch;
    unsigned char dlm;
    int res = 0;
    int i;
    struct ndn_charbuf *addr = NULL;
    
    if (addrs == NULL || !*addrs || 0 == strcmp(addrs, "*"))
        return(ndnd_listen_on_wildcards(h));
    addr = ndn_charbuf_create();
    for (i = 0, ch = addrs[i]; addrs[i] != 0;) {
        addr->length = 0;
        dlm = 0;
        if (ch == '[') {
            dlm = ']';
            ch = addrs[++i];
        }
        for (; ch > ' ' && ch != ',' && ch != ';' && ch != dlm; ch = addrs[++i])
            ndn_charbuf_append_value(addr, ch, 1);
        if (ch && ch == dlm)
            ch = addrs[++i];
        if (addr->length > 0) {
            res |= ndnd_listen_on_address(h, ndn_charbuf_as_string(addr));
        }
        while ((0 < ch && ch <= ' ') || ch == ',' || ch == ';')
            ch = addrs[++i];
    }
    ndn_charbuf_destroy(&addr);
    return(res);
}

/**
 * Parse a list of ndnx URIs
 *
 * The URIs may be separated by whitespace, commas, or semicolons.
 *
 * Errors are logged.
 *
 * @returns a newly-allocated charbuf containing nul-terminated URIs; or
 *          NULL if no valid URIs are found.
 */
static struct ndn_charbuf *
ndnd_parse_uri_list(struct ndnd_handle *h, const char *what, const char *uris)
{
    struct ndn_charbuf *ans;
    struct ndn_charbuf *name;
    int i;
    size_t j;
    int res;
    unsigned char ch;
    const char *uri;

    if (uris == NULL)
        return(NULL);
    ans = ndn_charbuf_create();
    name = ndn_charbuf_create();
    for (i = 0, ch = uris[0]; ch != 0;) {
        while ((0 < ch && ch <= ' ') || ch == ',' || ch == ';')
            ch = uris[++i];
        j = ans->length;
        while (ch > ' ' && ch != ',' && ch != ';') {
            ndn_charbuf_append_value(ans, ch, 1);
            ch = uris[++i];
        }
        if (j < ans->length) {
            ndn_charbuf_append_value(ans, 0, 1);
            uri = (const char *)ans->buf + j;
            name->length = 0;
            res = ndn_name_from_uri(name, uri);
            if (res < 0) {
                ndnd_msg(h, "%s: invalid ndnx URI: %s", what, uri);
                ans->length = j;
            }
        }
    }
    ndn_charbuf_destroy(&name);
    if (ans->length == 0)
        ndn_charbuf_destroy(&ans);
    return(ans);
}

/**
 * Start a new ndnd instance
 * @param progname - name of program binary, used for locating helpers
 * @param logger - logger function
 * @param loggerdata - data to pass to logger function
 */
struct ndnd_handle *
ndnd_create(const char *progname, ndnd_logger logger, void *loggerdata)
{
    char *sockname;
    const char *portstr;
    const char *debugstr;
    const char *entrylimit;
    const char *mtu;
    const char *data_pause;
    const char *tts_default;
    const char *tts_limit;
    const char *predicted_response_limit;
    const char *autoreg;
    const char *listen_on;
    int fd;
    struct ndnd_handle *h;
    struct hashtb_param param = {0};
    
    sockname = ndnd_get_local_sockname();
    h = calloc(1, sizeof(*h));
    if (h == NULL)
        return(h);
    h->logger = logger;
    h->loggerdata = loggerdata;
    h->noncegen = &ndnd_plain_nonce;
    h->logpid = (int)getpid();
    h->progname = progname;
    h->debug = -1;
    h->skiplinks = ndn_indexbuf_create();
    param.finalize_data = h;
    h->face_limit = 1024; /* soft limit */
    h->faces_by_faceid = calloc(h->face_limit, sizeof(h->faces_by_faceid[0]));
    param.finalize = &finalize_face;
    h->faces_by_fd = hashtb_create(sizeof(struct face), &param);
    h->dgram_faces = hashtb_create(sizeof(struct face), &param);
    param.finalize = &finalize_nonce;
    h->nonce_tab = hashtb_create(sizeof(struct nonce_entry), &param);
    h->ncehead.next = h->ncehead.prev = &h->ncehead;
    param.finalize = 0;
    h->faceid_by_guid = hashtb_create(sizeof(unsigned), &param);
    param.finalize = &finalize_content;
    h->content_tab = hashtb_create(sizeof(struct content_entry), &param);
    param.finalize = &finalize_nameprefix;
    h->nameprefix_tab = hashtb_create(sizeof(struct nameprefix_entry), &param);
    param.finalize = &finalize_interest;
    h->interest_tab = hashtb_create(sizeof(struct interest_entry), &param);
    param.finalize = &finalize_guest;
    h->guest_tab = hashtb_create(sizeof(struct guest_entry), &param);
    param.finalize = 0;
    h->sparse_straggler_tab = hashtb_create(sizeof(struct sparse_straggler_entry), NULL);
    h->min_stale = ~0;
    h->max_stale = 0;
    h->send_interest_scratch = ndn_charbuf_create();
    h->unsol = ndn_indexbuf_create();
    h->ticktock.descr[0] = 'C';
    h->ticktock.micros_per_base = 1000000;
    h->ticktock.gettime = &ndnd_gettime;
    h->ticktock.data = h;
    h->sched = ndn_schedule_create(h, &h->ticktock);
    h->starttime = h->sec;
    h->starttime_usec = h->usec;
    h->wtnow = 0xFFFF0000; /* provoke a rollover early on */
    h->oldformatcontentgrumble = 1;
    h->oldformatinterestgrumble = 1;
    debugstr = getenv("NDND_DEBUG");
    if (debugstr != NULL && debugstr[0] != 0) {
        h->debug = atoi(debugstr);
        if (h->debug == 0 && debugstr[0] != '0')
            h->debug = 1;
    }
    else
        h->debug = 1;
    portstr = getenv(NDN_LOCAL_PORT_ENVNAME);
    if (portstr == NULL || portstr[0] == 0 || strlen(portstr) > 10)
        portstr = NDN_DEFAULT_UNICAST_PORT;
    h->portstr = portstr;
    entrylimit = getenv("NDND_CAP");
    h->capacity = ~0;
    if (entrylimit != NULL && entrylimit[0] != 0) {
        h->capacity = atol(entrylimit);
        if (h->capacity == 0)
            h->force_zero_freshness = 1;
        if (h->capacity <= 0)
            h->capacity = 10;
    }
    ndnd_msg(h, "NDND_DEBUG=%d NDND_CAP=%lu", h->debug, h->capacity);
    h->mtu = 0;
    mtu = getenv("NDND_MTU");
    if (mtu != NULL && mtu[0] != 0) {
        h->mtu = atol(mtu);
        if (h->mtu < 0)
            h->mtu = 0;
        if (h->mtu > 8800)
            h->mtu = 8800;
    }
    h->data_pause_microsec = 10000;
    data_pause = getenv("NDND_DATA_PAUSE_MICROSEC");
    if (data_pause != NULL && data_pause[0] != 0) {
        h->data_pause_microsec = atol(data_pause);
        if (h->data_pause_microsec == 0)
            h->data_pause_microsec = 1;
        if (h->data_pause_microsec > 1000000)
            h->data_pause_microsec = 1000000;
    }
    h->tts_default = -1;
    tts_default = getenv("NDND_DEFAULT_TIME_TO_STALE");
    if (tts_default != NULL && tts_default[0] != 0) {
        h->tts_default = atoi(tts_default);
        if (h->tts_default <= 0)
            h->tts_default = -1;
        ndnd_msg(h, "NDND_DEFAULT_TIME_TO_STALE=%d", h->tts_default);
    }
    h->tts_limit = ~0U;
    tts_limit = getenv("NDND_MAX_TIME_TO_STALE");
    if (tts_limit != NULL && tts_limit[0] != 0) {
        h->tts_limit = atoi(tts_limit);
        if (h->tts_limit <= 0)
            h->tts_limit = -1;
        else if (h->tts_limit > ((1U<<31) / 1000000))
            h->tts_limit = (1U<<31) / 1000000;
        ndnd_msg(h, "NDND_MAX_TIME_TO_STALE=%d", h->tts_limit);
    }
    h->predicted_response_limit = 160000;
    predicted_response_limit = getenv("NDND_MAX_RTE_MICROSEC");
    if (predicted_response_limit != NULL && predicted_response_limit[0] != 0) {
        h->predicted_response_limit = atoi(predicted_response_limit);
        if (h->predicted_response_limit <= 2000)
            h->predicted_response_limit = 2000;
        else if (h->predicted_response_limit > 60000000)
            h->predicted_response_limit = 60000000;
        ndnd_msg(h, "NDND_MAX_RTE_MICROSEC=%d", h->predicted_response_limit);
    }
    listen_on = getenv("NDND_LISTEN_ON");
    autoreg = getenv("NDND_AUTOREG");
    
    if (autoreg != NULL && autoreg[0] != 0) {
        h->autoreg = ndnd_parse_uri_list(h, "NDND_AUTOREG", autoreg);
        if (h->autoreg != NULL)
            ndnd_msg(h, "NDND_AUTOREG=%s", autoreg);
    }
    if (listen_on != NULL && listen_on[0] != 0)
        ndnd_msg(h, "NDND_LISTEN_ON=%s", listen_on);
    // if (h->debug & 256)
        h->noncegen = &ndnd_debug_nonce;
    /* Do keystore setup early, it takes a while the first time */
    ndnd_init_internal_keystore(h);
    ndnd_reseed(h);
    if (h->face0 == NULL) {
        struct face *face;
        face = calloc(1, sizeof(*face));
        face->recv_fd = -1;
        face->sendface = 0;
        face->flags = (NDN_FACE_GG | NDN_FACE_LOCAL);
        h->face0 = face;
    }
    enroll_face(h, h->face0);
    fd = create_local_listener(h, sockname, 42);
    if (fd == -1)
        ndnd_msg(h, "%s: %s", sockname, strerror(errno));
    else
        ndnd_msg(h, "listening on %s", sockname);
    h->flood = (h->autoreg != NULL);
    h->ipv4_faceid = h->ipv6_faceid = NDN_NOFACEID;
    ndnd_listen_on(h, listen_on);
    reap_needed(h, 55000);
    age_forwarding_needed(h);
    ndnd_internal_client_start(h);
    free(sockname);
    sockname = NULL;
    return(h);
}

/**
 * Shutdown listeners and bound datagram sockets, leaving connected streams.
 */
static void
ndnd_shutdown_listeners(struct ndnd_handle *h)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    for (hashtb_start(h->faces_by_fd, e); e->data != NULL;) {
        struct face *face = e->data;
        if ((face->flags & (NDN_FACE_MCAST | NDN_FACE_PASSIVE)) != 0)
            hashtb_delete(e);
        else
            hashtb_next(e);
    }
    hashtb_end(e);
}

/**
 * Destroy the ndnd instance, releasing all associated resources.
 */
void
ndnd_destroy(struct ndnd_handle **pndnd)
{
    struct ndnd_handle *h = *pndnd;
    if (h == NULL)
        return;
    ndnd_shutdown_listeners(h);
    ndnd_internal_client_stop(h);
    ndn_schedule_destroy(&h->sched);
    hashtb_destroy(&h->nonce_tab);
    hashtb_destroy(&h->dgram_faces);
    hashtb_destroy(&h->faces_by_fd);
    hashtb_destroy(&h->faceid_by_guid);
    hashtb_destroy(&h->content_tab);
    hashtb_destroy(&h->interest_tab);
    hashtb_destroy(&h->nameprefix_tab);
    hashtb_destroy(&h->sparse_straggler_tab);
    hashtb_destroy(&h->guest_tab);
    if (h->fds != NULL) {
        free(h->fds);
        h->fds = NULL;
        h->nfds = 0;
    }
    if (h->faces_by_faceid != NULL) {
        free(h->faces_by_faceid);
        h->faces_by_faceid = NULL;
        h->face_limit = h->face_gen = 0;
    }
    if (h->content_by_accession != NULL) {
        free(h->content_by_accession);
        h->content_by_accession = NULL;
        h->content_by_accession_window = 0;
    }
    ndn_charbuf_destroy(&h->send_interest_scratch);
    ndn_charbuf_destroy(&h->scratch_charbuf);
    ndn_charbuf_destroy(&h->autoreg);
    ndn_indexbuf_destroy(&h->skiplinks);
    ndn_indexbuf_destroy(&h->scratch_indexbuf);
    ndn_indexbuf_destroy(&h->unsol);
    if (h->face0 != NULL) {
        int i;
        ndn_charbuf_destroy(&h->face0->inbuf);
        ndn_charbuf_destroy(&h->face0->outbuf);
        for (i = 0; i < NDN_CQ_N; i++)
            content_queue_destroy(h, &(h->face0->q[i]));
        for (i = 0; i < NDND_FACE_METER_N; i++)
            ndnd_meter_destroy(&h->face0->meter[i]);
        free(h->face0);
        h->face0 = NULL;
    }
    free(h);
    *pndnd = NULL;
}
