/**
 * @file ndn/ndn.h
 *
 * This is the low-level interface for NDNx clients.
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

#ifndef NDN_NDN_DEFINED
#define NDN_NDN_DEFINED

#include <stdint.h>
#include <ndn/coding.h>
#include <ndn/charbuf.h>
#include <ndn/indexbuf.h>

/**
 * A macro that clients may use to cope with an evolving API.
 *
 * The decimal digits of this use the pattern MMVVXXX, where MM is the
 * major release number and VV is the minor version level.
 * XXX will be bumped when an API change is made, but it will not be
 * directly tied to the patch level in a release number.
 * Thus NDN_API_VERSION=1000 would have corresponded to the first public
 * release (0.1.0), but that version did not have this macro defined.
 */
#define NDN_API_VERSION 7002

/**
 * Interest lifetime default.
 *
 * If the interest lifetime is not explicit, this is the default value.
 */
#define NDN_INTEREST_LIFETIME_SEC 4
#define NDN_INTEREST_LIFETIME_MICROSEC (NDN_INTEREST_LIFETIME_SEC * 1000000)

/* opaque declarations */
struct ndn;
struct ndn_pkey;

/* forward declarations */
struct ndn_closure;
struct ndn_upcall_info;
struct ndn_parsed_interest;
struct ndn_parsed_ContentObject;
struct ndn_parsed_Link;

/*
 * Types for implementing upcalls
 * To receive notifications of incoming interests and content, the
 * client creates closures (using client-managed memory).
 */

/**
 * This tells what kind of event the upcall is handling.
 *
 * The KEYMISSING and RAW codes are used only if deferred verification has been
 * requested.
 */
enum ndn_upcall_kind {
    NDN_UPCALL_FINAL,             /**< handler is about to be deregistered */
    NDN_UPCALL_INTEREST,          /**< incoming interest */
    NDN_UPCALL_CONSUMED_INTEREST, /**< incoming interest, someone has answered */
    NDN_UPCALL_CONTENT,           /**< incoming verified content */
    NDN_UPCALL_INTEREST_TIMED_OUT,/**< interest timed out */
    NDN_UPCALL_CONTENT_UNVERIFIED,/**< content that has not been verified */
    NDN_UPCALL_CONTENT_BAD,       /**< verification failed */
    NDN_UPCALL_CONTENT_KEYMISSING,/**< key has not been fetched */
    NDN_UPCALL_CONTENT_RAW        /**< verification has not been attempted */
};

/**
 * Upcalls return one of these values.
 */
enum ndn_upcall_res {
    NDN_UPCALL_RESULT_ERR = -1, /**< upcall detected an error */
    NDN_UPCALL_RESULT_OK = 0,   /**< normal upcall return */
    NDN_UPCALL_RESULT_REEXPRESS = 1, /**< reexpress the same interest again */
    NDN_UPCALL_RESULT_INTEREST_CONSUMED = 2,/**< upcall claims to consume interest */
    NDN_UPCALL_RESULT_VERIFY = 3, /**< force an unverified result to be verified */
    NDN_UPCALL_RESULT_FETCHKEY = 4 /**< request fetching of an unfetched key */
};

/**
 * @typedef ndn_handler
 * This is the procedure type for the closure's implementation.
 */
typedef enum ndn_upcall_res (*ndn_handler)(
    struct ndn_closure *selfp,
    enum ndn_upcall_kind kind,
    struct ndn_upcall_info *info  /**< details about the event */
);

/**
 * Handle for upcalls that allow clients receive notifications of
 * incoming interests and content.
 *
 * The client is responsible for managing this piece of memory and the
 * data therein. The refcount should be initially zero, and is used by the
 * library to keep to track of multiple registrations of the same closure.
 * When the count drops back to 0, the closure will be called with
 * kind = NDN_UPCALL_FINAL so that it has an opportunity to clean up.
 */
struct ndn_closure {
    ndn_handler p;      /**< client-supplied handler */
    void *data;         /**< for client use */
    intptr_t intdata;   /**< for client use */
    int refcount;       /**< client should not update this directly */
};

/**
 * Additional information provided in the upcall.
 *
 * The client is responsible for managing this piece of memory and the
 * data therein. The refcount should be initially zero, and is used by the
 * library to keep to track of multiple registrations of the same closure.
 * When the count drops back to 0, the closure will be called with
 * kind = NDN_UPCALL_FINAL so that it has an opportunity to clean up.
 */
struct ndn_upcall_info {
    struct ndn *h;              /**< The ndn library handle */
    /* Interest (incoming or matched) */
    const unsigned char *interest_ndnb;
    struct ndn_parsed_interest *pi;
    struct ndn_indexbuf *interest_comps;
    int matched_comps;
    /* Incoming content for NDN_UPCALL_CONTENT* - otherwise NULL */
    const unsigned char *content_ndnb;
    struct ndn_parsed_ContentObject *pco;
    struct ndn_indexbuf *content_comps;
};

/*
 * ndn_create: create a client handle
 * Creates and initializes a client handle, not yet connected.
 * On error, returns NULL and sets errno.
 * Errors: ENOMEM
 */ 
struct ndn *ndn_create(void);

/*
 * ndn_connect: connect to local ndnd
 * Use NULL for name to get the default.
 * Normal return value is the fd for the connection.
 * On error, returns -1.
 */ 
int ndn_connect(struct ndn *h, const char *name);

/*
 * ndn_get_connection_fd: get connection socket fd
 * This is in case the client needs to know the associated
 * file descriptor, e.g. for use in select/poll.
 * The client should not use this fd for actual I/O.
 * Normal return value is the fd for the connection.
 * Returns -1 if the handle is not connected.
 */ 
int ndn_get_connection_fd(struct ndn *h);

/*
 * ndn_disconnect: disconnect from local ndnd
 * This breaks the connection and discards buffered I/O,
 * but leaves other state intact.  Interests that are pending at disconnect
 * will be reported as timed out, and interest filters active at disconnect
 * will be re-registered if a subsequent ndn_connect on the handle succeeds.
 */ 
int ndn_disconnect(struct ndn *h);

/*
 * ndn_destroy: destroy handle
 * Releases all resources associated with *hp and sets it to NULL.
 */ 
void ndn_destroy(struct ndn **hp);

/* Control where verification happens */
int ndn_defer_verification(struct ndn *h, int defer);

/***********************************
 * Writing Names
 * Names for interests are constructed in charbufs using 
 * the following routines.
 */

/*
 * ndn_name_init: reset charbuf to represent an empty Name in binary format
 * Return value is 0, or -1 for error.
 */
int ndn_name_init(struct ndn_charbuf *c);

/*
 * ndn_name_append: add a Component to a Name
 * The component is an arbitrary string of n octets, no escaping required.
 * Return value is 0, or -1 for error.
 */
int ndn_name_append(struct ndn_charbuf *c, const void *component, size_t n);

/*
 * ndn_name_append_str: add a Component that is a \0 terminated string.
 * The component added is the bytes of the string without the \0.
 * This function is convenient for those applications that construct 
 * component names from simple strings.
 * Return value is 0, or -1 for error
 */
int ndn_name_append_str(struct ndn_charbuf *c, const char *s);

/*
 * ndn_name_append_components: add sequence of ndnb-encoded Components
 *    to a ndnb-encoded Name
 * start and stop are offsets from ndnb
 * Return value is 0, or -1 for obvious error
 */
int ndn_name_append_components(struct ndn_charbuf *c,
                               const unsigned char *ndnb,
                               size_t start, size_t stop);

enum ndn_marker {
    NDN_MARKER_NONE = -1,
    NDN_MARKER_SEQNUM  = 0x00, /**< consecutive block sequence numbers */
    NDN_MARKER_CONTROL = 0xC1, /**< commands, etc. */ 
    NDN_MARKER_OSEQNUM = 0xF8, /**< deprecated */
    NDN_MARKER_BLKID   = 0xFB, /**< nonconsecutive block ids */
    NDN_MARKER_VERSION = 0xFD  /**< timestamp-based versioning */
};

/*
 * ndn_name_append_numeric: add binary Component to ndnb-encoded Name
 * These are special components used for marking versions, fragments, etc.
 * Return value is 0, or -1 for error
 * see doc/technical/NameConventions.html
 */
int ndn_name_append_numeric(struct ndn_charbuf *c,
                            enum ndn_marker tag, uintmax_t value);

/*
 * ndn_name_append_nonce: add nonce Component to ndnb-encoded Name
 * Uses %C1.N.n marker.
 * see doc/technical/NameConventions.html
 */
int ndn_name_append_nonce(struct ndn_charbuf *c);

/*
 * ndn_name_split: find Component boundaries in a ndnb-encoded Name
 * Thin veneer over ndn_parse_Name().
 * returns -1 for error, otherwise the number of Components
 * components arg may be NULL to just do a validity check
 */
int ndn_name_split(const struct ndn_charbuf *c,
                   struct ndn_indexbuf* components);

/*
 * ndn_name_chop: Chop the name down to n components.
 * returns -1 for error, otherwise the new number of Components
 * components arg may be NULL; if provided it must be consistent with
 * some prefix of the name, and is updated accordingly.
 * n may be negative to say how many components to remove instead of how
 * many to leave, e.g. -1 will remove just the last component.
 */
int ndn_name_chop(struct ndn_charbuf *c,
                  struct ndn_indexbuf* components, int n);


/***********************************
 * Authenticators and signatures for content are constructed in charbufs
 * using the following routines.
 */

enum ndn_content_type {
    NDN_CONTENT_DATA = 0x0C04C0,
    NDN_CONTENT_ENCR = 0x10D091,
    NDN_CONTENT_GONE = 0x18E344,
    NDN_CONTENT_KEY  = 0x28463F,
    NDN_CONTENT_LINK = 0x2C834A,
    NDN_CONTENT_NACK = 0x34008A
};

/***********************************
 * ndn_express_interest: 
 * Use the above routines to set up namebuf.
 * Matching occurs only on the first prefix_comps components of
 * the name, or on all components if prefix_comps is -1.
 * Any remaining components serve to establish the starting point for
 * the search for matching content.
 * The namebuf may be reused or destroyed after the call.
 * If action is not NULL, it is invoked when matching data comes back.
 * If interest_template is supplied, it should contain a ndnb formatted
 * interest message to provide the other portions of the interest.
 * It may also be reused or destroyed after the call.
 * When an interest times out, the upcall may return
 * NDN_UPCALL_RESULT_REEXPRESS to simply re-express the interest.
 * The default is to unregister the handler.  The common use will be for
 * the upcall to register again with an interest modified to prevent matching
 * the same interest again.
 */
int ndn_express_interest(struct ndn *h,
                         struct ndn_charbuf *namebuf,
                         struct ndn_closure *action,
                         struct ndn_charbuf *interest_template);

/*
 * Register to receive interests on a prefix
 */
int ndn_set_interest_filter(struct ndn *h, struct ndn_charbuf *namebuf,
                            struct ndn_closure *action);

/*
 * Variation allows non-default forwarding flags
 */
int ndn_set_interest_filter_with_flags(struct ndn *h,
                                       struct ndn_charbuf *namebuf,
                                       struct ndn_closure *action,
                                       int forw_flags);

/*
 * ndn_put: send ndn binary
 * This checks for a single well-formed ndn binary object and 
 * sends it out (or queues it to be sent).  For normal clients,
 * this should be a ContentObject sent in response to an Interest,
 * but ndn_put does not check for that.
 * Returns -1 for error, 0 if sent completely, 1 if queued.
 */
int ndn_put(struct ndn *h, const void *p, size_t length);

/*
 * ndn_output_is_pending:
 * This is for client-managed select or poll.
 * Returns 1 if there is data waiting to be sent, else 0.
 */
int ndn_output_is_pending(struct ndn *h);

/*
 * ndn_run: process incoming
 * This may serve as the main event loop for simple apps by passing 
 * a timeout value of -1.
 * The timeout is in milliseconds.
 */
int ndn_run(struct ndn *h, int timeout);

/*
 * ndn_set_run_timeout: modify ndn_run timeout
 * This may be called from an upcall to change the timeout value.
 * The timeout is in milliseconds.  Returns old value.
 */
int ndn_set_run_timeout(struct ndn *h, int timeout);

/*
 * ndn_get: Get a single matching ContentObject
 * This is a convenience for getting a single matching ContentObject.
 * Blocks until a matching ContentObject arrives or there is a timeout.
 * If h is NULL or ndn_get is called from inside an upcall, a new connection
 * will be used and upcalls from other requests will not be processed while
 * ndn_get is active.
 * The pcobuf and compsbuf arguments may be supplied to save the work of
 * re-parsing the ContentObject.  Either or both may be NULL if this
 * information is not actually needed.
 * flags are not currently used, should be 0.
 * Returns 0 for success, -1 for an error.
 */
int ndn_get(struct ndn *h,
            struct ndn_charbuf *name,
            struct ndn_charbuf *interest_template,
            int timeout_ms,
            struct ndn_charbuf *resultbuf,
            struct ndn_parsed_ContentObject *pcobuf,
            struct ndn_indexbuf *compsbuf,
            int flags);

#define NDN_GET_NOKEYWAIT 1

/* Handy if the content object didn't arrive in the usual way. */
int ndn_verify_content(struct ndn *h,
                       const unsigned char *msg,
                       struct ndn_parsed_ContentObject *pco);

/***********************************
 * Binary decoding
 * These routines require that the whole binary object be buffered.
 */

struct ndn_buf_decoder {
    struct ndn_skeleton_decoder decoder;
    const unsigned char *buf;
    size_t size;
};

struct ndn_buf_decoder *ndn_buf_decoder_start(struct ndn_buf_decoder *d,
    const unsigned char *buf, size_t size);

void ndn_buf_advance(struct ndn_buf_decoder *d);
int ndn_buf_advance_past_element(struct ndn_buf_decoder *d);

/* The match routines return a boolean - true for match */
/* XXX - note, ndn_buf_match_blob doesn't match - it extracts the blob! */
int ndn_buf_match_dtag(struct ndn_buf_decoder *d, enum ndn_dtag dtag);

int ndn_buf_match_some_dtag(struct ndn_buf_decoder *d);

int ndn_buf_match_some_blob(struct ndn_buf_decoder *d);
int ndn_buf_match_blob(struct ndn_buf_decoder *d,
                       const unsigned char **bufp, size_t *sizep);

int ndn_buf_match_udata(struct ndn_buf_decoder *d, const char *s);

int ndn_buf_match_attr(struct ndn_buf_decoder *d, const char *s);

/* On error, the parse routines enter an error state and return a negative value. */
int ndn_parse_required_tagged_BLOB(struct ndn_buf_decoder *d,
                                   enum ndn_dtag dtag,
                                   int minlen, int maxlen);
int ndn_parse_optional_tagged_BLOB(struct ndn_buf_decoder *d,
                                   enum ndn_dtag dtag,
                                   int minlen, int maxlen);
int ndn_parse_nonNegativeInteger(struct ndn_buf_decoder *d);
int ndn_parse_optional_tagged_nonNegativeInteger(struct ndn_buf_decoder *d,
                                                 enum ndn_dtag dtag);
int ndn_parse_uintmax(struct ndn_buf_decoder *d, uintmax_t *result);
int ndn_parse_tagged_string(struct ndn_buf_decoder *d,
                            enum ndn_dtag dtag, struct ndn_charbuf *store);
/* check the decoder error state for these two - result can't be negative */
uintmax_t ndn_parse_required_tagged_binary_number(struct ndn_buf_decoder *d,
                                                  enum ndn_dtag dtag,
                                                  int minlen, int maxlen);
uintmax_t ndn_parse_optional_tagged_binary_number(struct ndn_buf_decoder *d,
                                                  enum ndn_dtag dtag,
                                                  int minlen, int maxlen,
                                                  uintmax_t default_value);
/**
 * Enter an error state if element closer not found.
 */
void ndn_buf_check_close(struct ndn_buf_decoder *d);

/*
 * ndn_ref_tagged_BLOB: Get address & size associated with blob-valued element
 * Returns 0 for success, negative value for error.
 */
int ndn_ref_tagged_BLOB(enum ndn_dtag tt,
                        const unsigned char *buf,
                        size_t start, size_t stop,
                        const unsigned char **presult, size_t *psize);

/*
 * ndn_ref_tagged_string: Get address & size associated with
 * string(UDATA)-valued element.   Note that since the element closer
 * is a 0 byte, the string result will be correctly interpreted as a C string.
 * Returns 0 for success, negative value for error.
 */
int ndn_ref_tagged_string(enum ndn_dtag tt,
                        const unsigned char *buf,
                        size_t start, size_t stop,
                        const unsigned char **presult, size_t *psize);

int ndn_fetch_tagged_nonNegativeInteger(enum ndn_dtag tt,
            const unsigned char *buf, size_t start, size_t stop);

/*********** Interest parsing ***********/

/*
 * The parse of an interest results in an array of offsets into the 
 * wire representation, with the start and end of each major element and
 * a few of the inportant sub-elements.  The following enum allows those
 * array items to be referred to symbolically.  The *_B_* indices correspond
 * to beginning offsets and the *_E_* indices correspond to ending offsets.
 * An omitted element has its beginning and ending offset equal to each other.
 * Normally these offsets will end up in non-decreasing order.
 * Some aliasing tricks may be played here, e.g. since
 * offset[NDN_PI_E_ComponentLast] is always equal to
 * offset[NDN_PI_E_LastPrefixComponent],
 * we may define NDN_PI_E_ComponentLast = NDN_PI_E_LastPrefixComponent.
 * However, code should not rely on that,
 * since it may change from time to time as the
 * interest schema evolves.
 */
enum ndn_parsed_interest_offsetid {
    NDN_PI_B_Name,
    NDN_PI_B_Component0,
    NDN_PI_B_LastPrefixComponent,
    NDN_PI_E_LastPrefixComponent,
    NDN_PI_E_ComponentLast = NDN_PI_E_LastPrefixComponent,
    NDN_PI_E_Name,
    NDN_PI_B_MinSuffixComponents,
    NDN_PI_E_MinSuffixComponents,
    NDN_PI_B_MaxSuffixComponents,
    NDN_PI_E_MaxSuffixComponents,
    NDN_PI_B_PublisherID, // XXX - rename
    NDN_PI_B_PublisherIDKeyDigest,
    NDN_PI_E_PublisherIDKeyDigest,
    NDN_PI_E_PublisherID,
    NDN_PI_B_Exclude,
    NDN_PI_E_Exclude,
    NDN_PI_B_ChildSelector,
    NDN_PI_E_ChildSelector,
    NDN_PI_B_AnswerOriginKind,
    NDN_PI_E_AnswerOriginKind,
    NDN_PI_B_Scope,
    NDN_PI_E_Scope,
    NDN_PI_B_InterestLifetime,
    NDN_PI_E_InterestLifetime,
    NDN_PI_B_Nonce,
    NDN_PI_E_Nonce,
    NDN_PI_B_OTHER,
    NDN_PI_E_OTHER,
    NDN_PI_E
};

struct ndn_parsed_interest {
    int magic;
    int prefix_comps;
    int min_suffix_comps;
    int max_suffix_comps;
    int orderpref;
    int answerfrom;
    int scope;
    unsigned short offset[NDN_PI_E+1];
};

enum ndn_parsed_Link_offsetid {
    NDN_PL_B_Name,
    NDN_PL_B_Component0,
    NDN_PL_E_ComponentLast,
    NDN_PL_E_Name,
    NDN_PL_B_Label,
    NDN_PL_E_Label,
    NDN_PL_B_LinkAuthenticator,
    NDN_PL_B_PublisherID,
    NDN_PL_B_PublisherDigest,
    NDN_PL_E_PublisherDigest,
    NDN_PL_E_PublisherID,
    NDN_PL_B_NameComponentCount,
    NDN_PL_E_NameComponentCount,
    NDN_PL_B_Timestamp,
    NDN_PL_E_Timestamp,
    NDN_PL_B_Type,
    NDN_PL_E_Type,
    NDN_PL_B_ContentDigest,
    NDN_PL_E_ContentDigest,
    NDN_PL_E_LinkAuthenticator,
    NDN_PL_E
};

struct ndn_parsed_Link {
    int name_ncomps;
    int name_component_count;
    int publisher_digest_type;
    int type;
    unsigned short offset[NDN_PL_E+1];
};

/*
 * ndn_parse_Link:
 * Returns number of name components, or a negative value for an error.
 * Fills in *link.
 * If components is not NULL, it is filled with byte indexes of
 * the start of each Component of the Name of the Link,
 * plus one additional value for the index of the end of the last component.
 */
int
ndn_parse_Link(struct ndn_buf_decoder *d,
                   struct ndn_parsed_Link *link,
                   struct ndn_indexbuf *components);

/*
 * ndn_append_Link: TODO: fill in documentation
 */
int
ndnb_append_Link(struct ndn_charbuf *buf,
                 const struct ndn_charbuf *name,
                 const char *label,
                 const struct ndn_charbuf *linkAuthenticator
                 );

/*
 * ndn_parse_LinkAuthenticator:
 */
int
ndn_parse_LinkAuthenticator(struct ndn_buf_decoder *d,
               struct ndn_parsed_Link *link);

/*
 * ndn_parse_Collection_start: TODO: fill in documentation
 */

int
ndn_parse_Collection_start(struct ndn_buf_decoder *d);

/*
 * ndn_parse_Collection_next: TODO: fill in documentation
 */

int
ndn_parse_Collection_next(struct ndn_buf_decoder *d,
                          struct ndn_parsed_Link *link,
                          struct ndn_indexbuf *components);

/*
 * Bitmasks for AnswerOriginKind
 */
#define NDN_AOK_CS      0x1     /* Answer from content store */
#define NDN_AOK_NEW     0x2     /* OK to produce new content */
#define NDN_AOK_DEFAULT (NDN_AOK_CS | NDN_AOK_NEW)
#define NDN_AOK_STALE   0x4     /* OK to answer with stale data */
#define NDN_AOK_EXPIRE  0x10    /* Mark as stale (must have Scope 0) */

/*
 * ndn_parse_interest:
 * Returns number of name components, or a negative value for an error.
 * Fills in *interest.
 * If components is not NULL, it is filled with byte indexes of
 * the start of each Component of the Name of the Interest,
 * plus one additional value for the index of the end of the last component.
 */
int
ndn_parse_interest(const unsigned char *msg, size_t size,
                   struct ndn_parsed_interest *interest,
                   struct ndn_indexbuf *components);

/*
 * Returns the lifetime of the interest in units of 2**(-12) seconds
 * (the same units as timestamps).
 */
intmax_t ndn_interest_lifetime(const unsigned char *msg,
                               const struct ndn_parsed_interest *pi);
/*
 * As above, but result is in seconds.  Any fractional part is truncated, so
 * this is not useful for short-lived interests.
 */
int ndn_interest_lifetime_seconds(const unsigned char *msg,
                                  const struct ndn_parsed_interest *pi);

/*********** ContentObject parsing ***********/
/* Analogous to enum ndn_parsed_interest_offsetid, but for content */
enum ndn_parsed_content_object_offsetid {
    NDN_PCO_B_Signature,
    NDN_PCO_B_DigestAlgorithm,
    NDN_PCO_E_DigestAlgorithm,
    NDN_PCO_B_Witness,
    NDN_PCO_E_Witness,
    NDN_PCO_B_SignatureBits,
    NDN_PCO_E_SignatureBits,
    NDN_PCO_E_Signature,
    NDN_PCO_B_Name,
    NDN_PCO_B_Component0,
    NDN_PCO_E_ComponentN,
    NDN_PCO_E_ComponentLast = NDN_PCO_E_ComponentN,
    NDN_PCO_E_Name,
    NDN_PCO_B_SignedInfo,
    NDN_PCO_B_PublisherPublicKeyDigest,
    NDN_PCO_E_PublisherPublicKeyDigest,
    NDN_PCO_B_Timestamp,
    NDN_PCO_E_Timestamp,
    NDN_PCO_B_Type,
    NDN_PCO_E_Type,
    NDN_PCO_B_FreshnessSeconds,
    NDN_PCO_E_FreshnessSeconds,
    NDN_PCO_B_FinalBlockID,
    NDN_PCO_E_FinalBlockID,
    NDN_PCO_B_KeyLocator,
    /* Exactly one of Key, Certificate, or KeyName will be present */
    NDN_PCO_B_Key_Certificate_KeyName,
    NDN_PCO_B_KeyName_Name,
    NDN_PCO_E_KeyName_Name,
    NDN_PCO_B_KeyName_Pub,
    NDN_PCO_E_KeyName_Pub,
    NDN_PCO_E_Key_Certificate_KeyName,
    NDN_PCO_E_KeyLocator,
    NDN_PCO_B_ExtOpt,
    NDN_PCO_E_ExtOpt,
    NDN_PCO_E_SignedInfo,
    NDN_PCO_B_Content,
    NDN_PCO_E_Content,
    NDN_PCO_E
};

struct ndn_parsed_ContentObject {
    int magic;
    enum ndn_content_type type;
    int name_ncomps;
    unsigned short offset[NDN_PCO_E+1];
    unsigned char digest[32];	/* Computed only when needed */
    int digest_bytes;
};

/*
 * ndn_parse_ContentObject:
 * Returns 0, or a negative value for an error.
 * Fills in *x with offsets of constituent elements.
 * If components is not NULL, it is filled with byte indexes
 * of the start of each Component of the Name of the ContentObject,
 * plus one additional value for the index of the end of the last component.
 * Sets x->digest_bytes to 0; the digest is computed lazily by calling
 * ndn_digest_ContentObject.
 */
int ndn_parse_ContentObject(const unsigned char *msg, size_t size,
                            struct ndn_parsed_ContentObject *x,
                            struct ndn_indexbuf *components);

void ndn_digest_ContentObject(const unsigned char *msg,
                              struct ndn_parsed_ContentObject *pc);

/*
 * ndn_parse_Name: Parses a ndnb-encoded name
 * components may be NULL, otherwise is filled in with Component boundary offsets
 * Returns the number of Components in the Name, or -1 if there is an error.
 */
int ndn_parse_Name(struct ndn_buf_decoder *d, struct ndn_indexbuf *components);

/*
 * ndn_compare_names:
 * Returns a value that is negative, zero, or positive depending upon whether
 * the Name element of a is less, equal, or greater than the Name element of b.
 * a and b may point to the start of ndnb-encoded elements of type Name,
 * Interest, or ContentObject.  The size values should be large enough to
 * encompass the entire Name element.
 * The ordering used is the canonical ordering of the ndn name hierarchy.
 */
int ndn_compare_names(const unsigned char *a, size_t asize,
                      const unsigned char *b, size_t bsize);

/***********************************
 * Reading Names:
 * Names may be (minimally) read using the following routines,
 * based on the component boundary markers generated from a parse.
 */

/*
 * ndn_indexbuf_comp_strcmp: perform strcmp of given val against 
 * name component at given index i (counting from 0).
 * Uses conventional string ordering, not the canonical NDNx ordering.
 * Returns negative, 0, or positive if val is less than, equal to,
 * or greater than the component.
 * Safe even on binary components, though the result may not be useful.
 * NOTE - this ordering is different from the canonical ordering
 * used by ndn_compare_names();
 */
int ndn_name_comp_strcmp(const unsigned char *data,
                         const struct ndn_indexbuf *indexbuf,
                         unsigned int i,
                         const char *val);

/*
 * ndn_name_comp_get: return a pointer to and size of component at
 * given index i.  The first component is index 0.
 */
int ndn_name_comp_get(const unsigned char *data,
                      const struct ndn_indexbuf *indexbuf,
                      unsigned int i,
                      const unsigned char **comp, size_t *size);

int ndn_name_next_sibling(struct ndn_charbuf *c);

/***********************************
 * Reading content objects
 */

int ndn_content_get_value(const unsigned char *data, size_t data_size,
                          const struct ndn_parsed_ContentObject *content,
                          const unsigned char **value, size_t *size);

/* checking for final block given upcall info */
int ndn_is_final_block(struct ndn_upcall_info *info);

/* checking for final block given parsed content object */
int ndn_is_final_pco(const unsigned char *ndnb,
                     struct ndn_parsed_ContentObject *pco,
                     struct ndn_indexbuf *comps);

/* content-object signing */

/**
 * Parameters for creating signed content objects.
 *
 * A pointer to one of these may be passed to ndn_sign_content() for
 * cases where the default signing behavior does not suffice.
 * For the default (sign with the user's default key pair), pass NULL
 * for the pointer.
 *
 * The recommended way to us this is to create a local variable:
 *
 *   struct ndn_signing_params myparams = NDN_SIGNING_PARAMS_INIT;
 *
 * and then fill in the desired fields.  This way if additional parameters
 * are added, it won't be necessary to go back and modify exiting clients.
 * 
 * The template_ndnb may contain a ndnb-encoded SignedInfo to supply
 * selected fields from under the direction of sp_flags.
 * It is permitted to omit unneeded fields from the template, even if the
 * schema says they are manditory.
 *
 * If the pubid is all zero, the user's default key pair is used for
 * signing.  Otherwise the corresponding private key must have already
 * been supplied to the handle using ndn_load_private_key() or equivalent.
 *
 * The default signing key is obtained from ~/.ndnx/.ndnx_keystore unless
 * the NDNX_DIR is used to override the directory location.
 */
 
struct ndn_signing_params {
    int api_version;
    int sp_flags;
    struct ndn_charbuf *template_ndnb;
    unsigned char pubid[32];
    enum ndn_content_type type;
    int freshness;
    // XXX where should digest_algorithm fit in?
};

#define NDN_SIGNING_PARAMS_INIT \
  { NDN_API_VERSION, 0, NULL, {0}, NDN_CONTENT_DATA, -1 }

#define NDN_SP_TEMPL_TIMESTAMP      0x0001
#define NDN_SP_TEMPL_FINAL_BLOCK_ID 0x0002
#define NDN_SP_TEMPL_FRESHNESS      0x0004
#define NDN_SP_TEMPL_KEY_LOCATOR    0x0008
#define NDN_SP_FINAL_BLOCK          0x0010
#define NDN_SP_OMIT_KEY_LOCATOR     0x0020
#define NDN_SP_TEMPL_EXT_OPT        0x0040

int ndn_sign_content(struct ndn *h,
                     struct ndn_charbuf *resultbuf,
                     const struct ndn_charbuf *name_prefix,
                     const struct ndn_signing_params *params,
                     const void *data, size_t size);

int ndn_load_private_key(struct ndn *h,
                         const char *keystore_path,
                         const char *keystore_passphrase,
                         struct ndn_charbuf *pubid_out);

int ndn_load_default_key(struct ndn *h,
                         const char *keystore_path,
                         const char *keystore_passphrase);

int ndn_get_public_key(struct ndn *h,
                       const struct ndn_signing_params *params,
                       struct ndn_charbuf *digest_result,
                       struct ndn_charbuf *result);

/**
 * @brief Get public key and public key name associated with signing params
 *
 * Same as ndn_get_public_key, but also attempts to load public key name, if possible.
 * If public key name is unknown, pubkey_name will not be modified
 *
 * Place the public key associated with the params into result
 * buffer, and its digest into digest_result.
 *
 * This is for one of our signing keys, not just any key.
 * Result buffers may be NULL if the corresponding result is not wanted.
 *
 * @returns 0 for success, negative for error
 */
int
ndn_get_public_key_and_name(struct ndn *h,
                            const struct ndn_signing_params *params,
                            struct ndn_charbuf *digest_result,
                            struct ndn_charbuf *pubkey_data,
                            struct ndn_charbuf *pubkey_name);

int ndn_chk_signing_params(struct ndn *h,
                           const struct ndn_signing_params *params,
                           struct ndn_signing_params *result,
                           struct ndn_charbuf **ptimestamp,
                           struct ndn_charbuf **pfinalblockid,
                           struct ndn_charbuf **pkeylocator,
                           struct ndn_charbuf **pextopt);

/* low-level content-object signing */

#define NDN_SIGNING_DEFAULT_DIGEST_ALGORITHM "SHA256"

int ndn_signed_info_create(
    struct ndn_charbuf *c,              /* filled with result */
    const void *publisher_key_id,	/* input, (sha256) hash */
    size_t publisher_key_id_size, 	/* input, 32 for sha256 hashes */
    const struct ndn_charbuf *timestamp,/* input ndnb blob, NULL for "now" */
    enum ndn_content_type type,         /* input */
    int freshness,			/* input, -1 means omit */
    const struct ndn_charbuf *finalblockid, /* input, NULL means omit */
    const struct ndn_charbuf *key_locator); /* input, optional, ndnb encoded */

int ndn_encode_ContentObject(struct ndn_charbuf *buf,
                             const struct ndn_charbuf *Name,
                             const struct ndn_charbuf *SignedInfo,
                             const void *data,
                             size_t size,
                             const char *digest_algorithm,
                             const struct ndn_pkey *private_key);

/***********************************
 * Matching
 */


/*
 * ndn_content_matches_interest: Test for a match
 * Return 1 if the ndnb-encoded content_object matches the 
 * ndnb-encoded interest_msg, otherwise 0.
 * The implicit_content_digest boolean says whether or not the
 * final name component is implicit (as in the on-wire format)
 * or explicit (as within ndnd's content store).
 * Valid parse information (pc and pi) may be provided to speed things
 * up; if NULL they will be reconstructed internally.
 */
int ndn_content_matches_interest(const unsigned char *content_object,
                                 size_t content_object_size,
                                 int implicit_content_digest,
                                 struct ndn_parsed_ContentObject *pc,
                                 const unsigned char *interest_msg,
                                 size_t interest_msg_size,
                                 const struct ndn_parsed_interest *pi);

/*
 * Test whether the given raw name is int the Exclude set.
 */
int ndn_excluded(const unsigned char *excl,
                 size_t excl_size,
                 const unsigned char *nextcomp,
                 size_t nextcomp_size);

/***********************************
 * StatusResponse
 */
int ndn_encode_StatusResponse(struct ndn_charbuf *buf,
                              int errcode, const char *errtext);

/***********************************
 * Debugging
 */

/*
 * ndn_perror: produce message on standard error output describing the last
 * error encountered during a call using the given handle.
 * ndn_seterror records error info, ndn_geterror gets it.
 */
void ndn_perror(struct ndn *h, const char *s);
int ndn_seterror(struct ndn *h, int error_code);
int ndn_geterror(struct ndn *h);

/***********************************
 * Low-level binary formatting
 */

/*
 * Append a ndnb start marker
 *
 * This forms the basic building block of ndnb-encoded data.
 * c is the buffer to append to.
 * Return value is 0, or -1 for error.
 */
int ndn_charbuf_append_tt(struct ndn_charbuf *c, size_t val, enum ndn_tt tt);

/**
 * Append a NDN_CLOSE
 *
 * Use this to close off an element in ndnb-encoded data.
 * @param c is the buffer to append to.
 * @returns 0 for success or -1 for error.
 */
int ndn_charbuf_append_closer(struct ndn_charbuf *c);

/***********************************
 * Slightly higher level binary formatting
 */

/*
 * Append a non-negative integer as a UDATA.
 */
int ndnb_append_number(struct ndn_charbuf *c, int nni);

/*
 * Append a binary timestamp
 * as a BLOB using the ndn binary Timestamp representation (12-bit fraction).
 */
int ndnb_append_timestamp_blob(struct ndn_charbuf *c,
                               enum ndn_marker marker,
                               intmax_t secs, int nsecs);

/*
 * Append a binary timestamp, using the current time.
 */
int ndnb_append_now_blob(struct ndn_charbuf *c, enum ndn_marker marker);

/*
 * Append a start-of-element marker.
 */
int ndnb_element_begin(struct ndn_charbuf *c, enum ndn_dtag dtag);

/*
 * Append an end-of-element marker.
 * This is the same as ndn_charbuf_append_closer()
 */
int ndnb_element_end(struct ndn_charbuf *c);

/*
 * Append a tagged BLOB
 */
int ndnb_append_tagged_blob(struct ndn_charbuf *c, enum ndn_dtag dtag,
                            const void *data, size_t size);

/*
 * Append a tagged binary number
 */
int ndnb_append_tagged_binary_number(struct ndn_charbuf *cb, enum ndn_dtag dtag,
                                      uintmax_t val);

/*
 * Append a tagged UDATA string, with printf-style formatting
 */
int ndnb_tagged_putf(struct ndn_charbuf *c, enum ndn_dtag dtag,
                     const char *fmt, ...);

/**
 * Versioning
 */

/* Not all of these flags make sense with all of the operations */
#define NDN_V_REPLACE  1 /**< if last component is version, replace it */
#define NDN_V_LOW      2 /**< look for early version */
#define NDN_V_HIGH     4 /**< look for newer version */
#define NDN_V_EST      8 /**< look for extreme */
#define NDN_V_LOWEST   (2|8)
#define NDN_V_HIGHEST  (4|8)
#define NDN_V_NEXT     (4|1)
#define NDN_V_PREV     (2|1)
#define NDN_V_NOW      16 /**< use current time */
#define NDN_V_NESTOK   32 /**< version within version is ok */
#define NDN_V_SCOPE0   64 /**< use scope 0 */
#define NDN_V_SCOPE1   128 /**< use scope 1 */
#define NDN_V_SCOPE2   256 /**< use scope 2 */

int ndn_resolve_version(struct ndn *h,
                        struct ndn_charbuf *name, /* ndnb encoded */
                        int versioning_flags,
                        int timeout_ms);

int ndn_create_version(struct ndn *h,
                       struct ndn_charbuf *name,
                       int versioning_flags,
                       intmax_t secs, int nsecs);

int ndn_guest_prefix(struct ndn *h, struct ndn_charbuf *result, int ms);

#endif
