/**
 * @file ndnd_private.h
 *
 * Private definitions for ndnd - the NDNx daemon.
 * Data structures are described here so that logging and status
 * routines can be compiled separately.
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
 
#ifndef NDND_PRIVATE_DEFINED
#define NDND_PRIVATE_DEFINED

#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ndn/ndn_private.h>
#include <ndn/coding.h>
#include <ndn/reg_mgmt.h>
#include <ndn/schedule.h>
#include <ndn/seqwriter.h>

/*
 * These are defined in other ndn headers, but the incomplete types suffice
 * for the purposes of this header.
 */
struct ndn_charbuf;
struct ndn_indexbuf;
struct hashtb;
struct ndnd_meter;

/*
 * These are defined in this header.
 */
struct ndnd_handle;
struct face;
struct content_entry;
struct nameprefix_entry;
struct interest_entry;
struct guest_entry;
struct pit_face_item;
struct content_tree_node;
struct ndn_forwarding;
struct ndn_strategy;

//typedef uint_least64_t ndn_accession_t;
typedef unsigned ndn_accession_t;

/**
 * Used for keeping track of interest expiry.
 *
 * Modulo 2**32, time units and origin are abitrary and private.
 */
typedef uint32_t ndn_wrappedtime;

typedef int (*ndnd_logger)(void *loggerdata, const char *format, va_list ap);

/* see nonce_entry */
struct ncelinks {
    struct ncelinks *next;           /**< next in list */
    struct ncelinks *prev;           /**< previous in list */
};

/**
 * We pass this handle almost everywhere within ndnd
 */
struct ndnd_handle {
    unsigned char ndnd_id[32];      /**< sha256 digest of our public key */
    struct hashtb *nonce_tab;       /**< keyed by interest Nonce */
    struct hashtb *faces_by_fd;     /**< keyed by fd */
    struct hashtb *dgram_faces;     /**< keyed by sockaddr */
    struct hashtb *faceid_by_guid;  /**< keyed by guid */
    struct hashtb *content_tab;     /**< keyed by portion of ContentObject */
    struct hashtb *nameprefix_tab;  /**< keyed by name prefix components */
    struct hashtb *interest_tab;    /**< keyed by interest msg sans Nonce */
    struct hashtb *guest_tab;       /**< keyed by faceid */
    struct ndn_indexbuf *skiplinks; /**< skiplist for content-ordered ops */
    unsigned forward_to_gen;        /**< for forward_to updates */
    unsigned face_gen;              /**< faceid generation number */
    unsigned face_rover;            /**< for faceid allocation */
    unsigned face_limit;            /**< current number of face slots */
    struct face **faces_by_faceid;  /**< array with face_limit elements */
    struct ncelinks ncehead;        /**< list head for expiry-sorted nonces */
    struct ndn_scheduled_event *reaper;
    struct ndn_scheduled_event *age;
    struct ndn_scheduled_event *clean;
    struct ndn_scheduled_event *age_forwarding;
    const char *portstr;            /**< "main" port number */
    unsigned ipv4_faceid;           /**< wildcard IPv4, bound to port */
    unsigned ipv6_faceid;           /**< wildcard IPv6, bound to port */
    nfds_t nfds;                    /**< number of entries in fds array */
    struct pollfd *fds;             /**< used for poll system call */
    struct ndn_gettime ticktock;    /**< our time generator */
    long sec;                       /**< cached gettime seconds */
    unsigned usec;                  /**< cached gettime microseconds */
    ndn_wrappedtime wtnow;          /**< corresponding wrapped time */
    int sliver;                     /**< extra microseconds beyond wtnow */
    long starttime;                 /**< ndnd start time, in seconds */
    unsigned starttime_usec;        /**< ndnd start time fractional part */
    unsigned iserial;               /**< interest serial number (for logs) */
    struct ndn_schedule *sched;     /**< our schedule */
    struct ndn_charbuf *send_interest_scratch; /**< for use by send_interest */
    struct ndn_charbuf *scratch_charbuf; /**< one-slot scratch cache */
    struct ndn_indexbuf *scratch_indexbuf; /**< one-slot scratch cache */
    /** Next three fields are used for direct accession-to-content table */
    ndn_accession_t accession_base;
    unsigned content_by_accession_window;
    struct content_entry **content_by_accession;
    /** The following holds stragglers that would otherwise bloat the above */
    struct hashtb *sparse_straggler_tab; /* keyed by accession */
    ndn_accession_t accession;      /**< newest used accession number */
    ndn_accession_t min_stale;      /**< smallest accession of stale content */
    ndn_accession_t max_stale;      /**< largest accession of stale content */
    unsigned long capacity;         /**< may toss content if there more than
                                     this many content objects in the store */
    unsigned long n_stale;          /**< Number of stale content objects */
    struct ndn_indexbuf *unsol;     /**< unsolicited content */
    unsigned long oldformatcontent;
    unsigned long oldformatcontentgrumble;
    unsigned long oldformatinterests;
    unsigned long oldformatinterestgrumble;
    unsigned long content_dups_recvd;
    unsigned long content_items_sent;
    unsigned long interests_accepted;
    unsigned long interests_dropped;
    unsigned long interests_sent;
    unsigned long interests_stuffed;
    unsigned short seed[3];         /**< for PRNG */
    int running;                    /**< true while should be running */
    int debug;                      /**< For controlling debug output */
    ndnd_logger logger;             /**< For debug output */
    void *loggerdata;               /**< Passed to logger */
    int logbreak;                   /**< see ndn_msg() */
    unsigned long logtime;          /**< see ndn_msg() */
    int logpid;                     /**< see ndn_msg() */
    int mtu;                        /**< Target size for stuffing interests */
    int flood;                      /**< Internal control for auto-reg */
    struct ndn_charbuf *autoreg;    /**< URIs to auto-register */
    int force_zero_freshness;       /**< Simulate freshness=0 on all content */
    unsigned interest_faceid;       /**< for self_reg internal client */
    const char *progname;           /**< our name, for locating helpers */
    struct ndn *internal_client;    /**< internal client */
    struct face *face0;             /**< special face for internal client */
    struct ndn_charbuf *service_ndnb; /**< for local service discovery */
    struct ndn_charbuf *neighbor_ndnb; /**< for neighbor service discovery */
    struct ndn_seqwriter *notice;   /**< for notices of status changes */
    struct ndn_indexbuf *chface;    /**< faceids w/ recent status changes */
    struct ndn_scheduled_event *internal_client_refresh;
    struct ndn_scheduled_event *notice_push;
    unsigned data_pause_microsec;   /**< tunable, see choose_face_delay() */
    int (*noncegen)(struct ndnd_handle *, struct face *, unsigned char *);
                                    /**< pluggable nonce generation */
    int tts_default;                /**< NDND_DEFAULT_TIME_TO_STALE (seconds) */
    int tts_limit;                  /**< NDND_MAX_TIME_TO_STALE (seconds) */
    int predicted_response_limit;   /**< NDND_MAX_RTE_MICROSEC */
};

/**
 * Each face is referenced by a number, the faceid.  The low-order
 * bits (under the MAXFACES) constitute a slot number that is
 * unique (for this ndnd) among the faces that are alive at a given time.
 * The rest of the bits form a generation number that make the
 * entire faceid unique over time, even for faces that are defunct.
 */
#define FACESLOTBITS 18
#define MAXFACES ((1U << FACESLOTBITS) - 1)

struct content_queue {
    unsigned burst_nsec;             /**< nsec per KByte, limits burst rate */
    unsigned min_usec;               /**< minimum delay for this queue */
    unsigned rand_usec;              /**< randomization range */
    unsigned ready;                  /**< # that have waited enough */
    unsigned nrun;                   /**< # sent since last randomized delay */
    struct ndn_indexbuf *send_queue; /**< accession numbers of pending content */
    struct ndn_scheduled_event *sender;
};

enum cq_delay_class {
    NDN_CQ_ASAP,
    NDN_CQ_NORMAL,
    NDN_CQ_SLOW,
    NDN_CQ_N
};

/**
 * Face meter index
 */
enum ndnd_face_meter_index {
    FM_BYTI,
    FM_BYTO,
    FM_DATI,
    FM_INTO,
    FM_DATO,
    FM_INTI,
    NDND_FACE_METER_N
};

/**
 * One of our active faces
 */
struct face {
    int recv_fd;                /**< socket for receiving */
    unsigned sendface;          /**< faceid for sending (maybe == faceid) */
    int flags;                  /**< NDN_FACE_* face flags */
    int surplus;                /**< sends since last successful recv */
    unsigned faceid;            /**< internal face id */
    unsigned recvcount;         /**< for activity level monitoring */
    const unsigned char *guid;  /**< guid name for channel, shared w/ peers */
    struct ndn_charbuf *guid_cob; /**< content object publishing face guid */
    struct content_queue *q[NDN_CQ_N]; /**< outgoing content, per delay class */
    struct ndn_charbuf *inbuf;
    struct ndn_skeleton_decoder decoder;
    size_t outbufindex;
    struct ndn_charbuf *outbuf;
    const struct sockaddr *addr;
    socklen_t addrlen;
    int pending_interests;
    unsigned rrun;
    uintmax_t rseq;
    struct ndnd_meter *meter[NDND_FACE_METER_N];
    unsigned short pktseq;      /**< sequence number for sent packets */
    unsigned short adjstate;    /**< state of adjacency negotiotiation */
};

/** face flags */
#define NDN_FACE_LINK   (1 << 0) /**< Elements wrapped by NDNProtocolDataUnit */
#define NDN_FACE_DGRAM  (1 << 1) /**< Datagram interface, respect packets */
#define NDN_FACE_GG     (1 << 2) /**< Considered friendly */
#define NDN_FACE_LOCAL  (1 << 3) /**< PF_UNIX socket */
#define NDN_FACE_INET   (1 << 4) /**< IPv4 */
#define NDN_FACE_MCAST  (1 << 5) /**< a party line (e.g. multicast) */
#define NDN_FACE_INET6  (1 << 6) /**< IPv6 */
#define NDN_FACE_DC     (1 << 7) /**< Direct control face */
#define NDN_FACE_NOSEND (1 << 8) /**< Don't send anymore */
#define NDN_FACE_UNDECIDED (1 << 9) /**< Might not be talking ndn */
#define NDN_FACE_PERMANENT (1 << 10) /**< No timeout for inactivity */
#define NDN_FACE_CONNECTING (1 << 11) /**< Connect in progress */
#define NDN_FACE_LOOPBACK (1 << 12) /**< v4 or v6 loopback address */
#define NDN_FACE_CLOSING (1 << 13) /**< close stream when output is done */
#define NDN_FACE_PASSIVE (1 << 14) /**< a listener or a bound dgram socket */
#define NDN_FACE_NORECV (1 << 15) /**< use for sending only */
#define NDN_FACE_REGOK (1 << 16) /**< Allowed to do prefix registration */
#define NDN_FACE_SEQOK (1 << 17) /** OK to send SequenceNumber link messages */
#define NDN_FACE_SEQPROBE (1 << 18) /** SequenceNumber probe */
#define NDN_FACE_LC    (1 << 19) /** A link check has been issued recently */
#define NDN_FACE_BC    (1 << 20) /** Needs SO_BROADCAST to send */
#define NDN_FACE_NBC   (1 << 21) /** Don't use SO_BROADCAST to send */
#define NDN_FACE_ADJ   (1 << 22) /** Adjacency guid has been negotiatied */
#define NDN_NOFACEID    (~0U)    /** denotes no face */

/**
 *  The content hash table is keyed by the initial portion of the ContentObject
 *  that contains all the parts of the complete name.  The extdata of the hash
 *  table holds the rest of the object, so that the whole ContentObject is
 *  stored contiguously.  The internal form differs from the on-wire form in
 *  that the final content-digest name component is represented explicitly,
 *  which simplifies the matching logic.
 *  The original ContentObject may be reconstructed simply by excising this
 *  last name component, which is easily located via the comps array.
 */
struct content_entry {
    ndn_accession_t accession;  /**< assigned in arrival order */
    unsigned arrival_faceid;    /**< the faceid of first arrival */
    unsigned short *comps;      /**< Name Component byte boundary offsets */
    int ncomps;                 /**< Number of name components plus one */
    int flags;                  /**< see below */
    const unsigned char *key;   /**< ndnb-encoded ContentObject */
    int key_size;               /**< Size of fragment prior to Content */
    int size;                   /**< Size of ContentObject */
    struct ndn_indexbuf *skiplinks; /**< skiplist for name-ordered ops */
};

/**
 * content_entry flags
 */
#define NDN_CONTENT_ENTRY_SLOWSEND  1
#define NDN_CONTENT_ENTRY_STALE     2
#define NDN_CONTENT_ENTRY_PRECIOUS  4

/**
 * The sparse_straggler hash table, keyed by accession, holds scattered
 * entries that would otherwise bloat the direct content_by_accession table.
 */
struct sparse_straggler_entry {
    struct content_entry *content;
};

/**
 * State for the strategy engine
 *
 * This is still quite embryonic.
 */
struct ndn_strategy {
    struct ndn_scheduled_event *ev; /**< for time-based strategy event */
    int state;
    ndn_wrappedtime birth;          /**< when interest entry was created */
    ndn_wrappedtime renewed;        /**< when interest entry was renewed */
    unsigned renewals;              /**< number of times renewed */
};

struct ielinks;
struct ielinks {
    struct ielinks *next;           /**< next in list */
    struct ielinks *prev;           /**< previous in list */
    struct nameprefix_entry *npe;   /**< owning npe, or NULL for head */
};

/**
 * The interest hash table is keyed by the interest message
 *
 * The interest message has fields that do not participate in the
 * similarity test stripped out - in particular the nonce.
 *
 */
struct interest_entry {
    struct ielinks ll;
    struct ndn_strategy strategy;   /**< state of strategy engine */
    struct pit_face_item *pfl;      /**< upstream and downstream faces */
    struct ndn_scheduled_event *ev; /**< next interest timeout */
    const unsigned char *interest_msg; /**< pending interest message */
    unsigned size;                  /**< size of interest message */
    unsigned serial;                /**< used for logging */
};

/**
 * The nonce hash table is keyed by the interest nonce
 */
struct nonce_entry {
    struct ncelinks ll;             /** doubly-linked */
    const unsigned char *key;       /** owned by hashtb */
    unsigned size;                  /** size of key */
    unsigned faceid;                /** originating face */
    ndn_wrappedtime expiry;         /** when this should expire */
};

/**
 * The guest hash table is keyed by the faceid of the requestor
 *
 * The cob is an answer for the request.
 *
 */
struct guest_entry {
    struct ndn_charbuf *cob;
};

#define TYPICAL_NONCE_SIZE 12       /**< actual allocated size may differ */
/**
 * Per-face PIT information
 *
 * This is used to track the pending interest info that is specific to
 * a face.  The list may contain up to two entries for a given face - one
 * to track the most recent arrival on that face (the downstream), and
 * one to track the most recently sent (the upstream).
 */
struct pit_face_item {
    struct pit_face_item *next;     /**< next in list */
    unsigned faceid;                /**< face id */
    ndn_wrappedtime renewed;        /**< when entry was last refreshed */
    ndn_wrappedtime expiry;         /**< when entry expires */
    unsigned pfi_flags;             /**< NDND_PFI_x */
    unsigned char nonce[TYPICAL_NONCE_SIZE]; /**< nonce bytes */
};
#define NDND_PFI_NONCESZ  0x00FF    /**< Mask for actual nonce size */
#define NDND_PFI_UPSTREAM 0x0100    /**< Tracks upstream (sent interest) */
#define NDND_PFI_UPENDING 0x0200    /**< Has been sent upstream */
#define NDND_PFI_SENDUPST 0x0400    /**< Should be sent upstream */
#define NDND_PFI_UPHUNGRY 0x0800    /**< Upstream hungry, cupboard bare */
#define NDND_PFI_DNSTREAM 0x1000    /**< Tracks downstream (recvd interest) */
#define NDND_PFI_PENDING  0x2000    /**< Pending for immediate data */
#define NDND_PFI_SUPDATA  0x4000    /**< Suppressed data reply */
#define NDND_PFI_DCFACE  0x10000    /**< This upstream is a DC face */

/**
 * The nameprefix hash table is keyed by the Component elements of
 * the Name prefix.
 */
struct nameprefix_entry {
    struct ielinks ie_head;      /**< list head for interest entries */
    struct ndn_indexbuf *forward_to; /**< faceids to forward to */
    struct ndn_indexbuf *tap;    /**< faceids to forward to as tap */
    struct ndn_forwarding *forwarding; /**< detailed forwarding info */
    struct nameprefix_entry *parent; /**< link to next-shorter prefix */
    int children;                /**< number of children */
    unsigned flags;              /**< NDN_FORW_* flags about namespace */
    int fgen;                    /**< used to decide when forward_to is stale */
    unsigned src;                /**< faceid of recent content source */
    unsigned osrc;               /**< and of older matching content */
    unsigned usec;               /**< response-time prediction */
};

/**
 * Keeps track of the faces that interests matching a given name prefix may be
 * forwarded to.
 */
struct ndn_forwarding {
    unsigned faceid;             /**< locally unique number identifying face */
    unsigned flags;              /**< NDN_FORW_* - c.f. <ndn/reg_mgnt.h> */
    int expires;                 /**< time remaining, in seconds */
    struct ndn_forwarding *next;
};

/* create and destroy procs for separately allocated meters */
struct ndnd_meter *ndnd_meter_create(struct ndnd_handle *h, const char *what);
void ndnd_meter_destroy(struct ndnd_meter **);

/* for meters kept within other structures */
void ndnd_meter_init(struct ndnd_handle *h, struct ndnd_meter *m, const char *what);

/* count something (messages, packets, bytes), getting time info from h */
void ndnd_meter_bump(struct ndnd_handle *h, struct ndnd_meter *m, unsigned amt);

unsigned ndnd_meter_rate(struct ndnd_handle *h, struct ndnd_meter *m);
uintmax_t ndnd_meter_total(struct ndnd_meter *m);


/**
 * Refer to doc/technical/Registration.txt for the meaning of these flags.
 *
 *  NDN_FORW_ACTIVE         1
 *  NDN_FORW_CHILD_INHERIT  2
 *  NDN_FORW_ADVERTISE      4
 *  NDN_FORW_LAST           8
 *  NDN_FORW_CAPTURE       16
 *  NDN_FORW_LOCAL         32
 *  NDN_FORW_TAP           64
 *  NDN_FORW_CAPTURE_OK   128
 */
#define NDN_FORW_PFXO (NDN_FORW_ADVERTISE | NDN_FORW_CAPTURE | NDN_FORW_LOCAL)
#define NDN_FORW_REFRESHED      (1 << 16) /**< private to ndnd */

 
/**
 * Determines how frequently we age our forwarding entries
 */
#define NDN_FWU_SECS 5

/*
 * Internal client
 * The internal client is for communication between the ndnd and other
 * components, using (of course) ndn protocols.
 */
int ndnd_init_internal_keystore(struct ndnd_handle *);
int ndnd_internal_client_start(struct ndnd_handle *);
void ndnd_internal_client_stop(struct ndnd_handle *);

/*
 * The internal client calls this with the argument portion ARG of
 * a face-creation request (/ndnx/NDNDID/newface/ARG)
 */
int ndnd_req_newface(struct ndnd_handle *h,
                     const unsigned char *msg, size_t size,
                     struct ndn_charbuf *reply_body);

/*
 * The internal client calls this with the argument portion ARG of
 * a face-destroy request (/ndnx/NDNDID/destroyface/ARG)
 */
int ndnd_req_destroyface(struct ndnd_handle *h,
                         const unsigned char *msg, size_t size,
                         struct ndn_charbuf *reply_body);

/*
 * The internal client calls this with the argument portion ARG of
 * a prefix-registration request (/ndnx/NDNDID/prefixreg/ARG)
 */
int ndnd_req_prefixreg(struct ndnd_handle *h,
                       const unsigned char *msg, size_t size,
                       struct ndn_charbuf *reply_body);

/*
 * The internal client calls this with the argument portion ARG of
 * a prefix-registration request for self (/ndnx/NDNDID/selfreg/ARG)
 */
int ndnd_req_selfreg(struct ndnd_handle *h,
                     const unsigned char *msg, size_t size,
                     struct ndn_charbuf *reply_body);

/**
 * URIs for prefixes served by the internal client
 */
#define NDNDID_LOCAL_URI "ndn:/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY"
#define NDNDID_NEIGHBOR_URI "ndn:/%C1.M.S.neighborhood/%C1.M.SRV/ndnd/KEY"

/*
 * The internal client calls this with the argument portion ARG of
 * a prefix-unregistration request (/ndnx/NDNDID/unreg/ARG)
 */
int ndnd_req_unreg(struct ndnd_handle *h,
                   const unsigned char *msg, size_t size,
                   struct ndn_charbuf *reply_body);

int ndnd_reg_uri(struct ndnd_handle *h,
                 const char *uri,
                 unsigned faceid,
                 int flags,
                 int expires);

void ndnd_generate_face_guid(struct ndnd_handle *h, struct face *face, int size,
                             const unsigned char *lo, const unsigned char *hi);
int ndnd_set_face_guid(struct ndnd_handle *h, struct face *face,
                       const unsigned char *guid, size_t size);
void ndnd_forget_face_guid(struct ndnd_handle *h, struct face *face);
int ndnd_append_face_guid(struct ndnd_handle *h, struct ndn_charbuf *cb,
                          struct face *face);
unsigned ndnd_faceid_from_guid(struct ndnd_handle *h,
                               const unsigned char *guid, size_t size);
void ndnd_adjacency_offer_or_commit_req(struct ndnd_handle *ndnd,
                                        struct face *face);

void ndnd_internal_client_has_somthing_to_say(struct ndnd_handle *h);

struct face *ndnd_face_from_faceid(struct ndnd_handle *, unsigned);
void ndnd_face_status_change(struct ndnd_handle *, unsigned);
int ndnd_destroy_face(struct ndnd_handle *h, unsigned faceid);
void ndnd_send(struct ndnd_handle *h, struct face *face,
               const void *data, size_t size);

/* Consider a separate header for these */
int ndnd_stats_handle_http_connection(struct ndnd_handle *, struct face *);
void ndnd_msg(struct ndnd_handle *, const char *, ...);
void ndnd_debug_ndnb(struct ndnd_handle *h,
                     int lineno,
                     const char *msg,
                     struct face *face,
                     const unsigned char *ndnb,
                     size_t ndnb_size);

struct ndnd_handle *ndnd_create(const char *, ndnd_logger, void *);
void ndnd_run(struct ndnd_handle *h);
void ndnd_destroy(struct ndnd_handle **);
extern const char *ndnd_usage_message;

#endif
