/**
 * @file ndn/coding.h
 * 
 * Details of the ndn binary wire encoding.
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008-2012 Palo Alto Research Center, Inc.
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

#ifndef NDN_CODING_DEFINED
#define NDN_CODING_DEFINED

#include <sys/types.h>
#include <stddef.h>

#define NDN_TT_BITS 3
#define NDN_TT_MASK ((1 << NDN_TT_BITS) - 1)
#define NDN_MAX_TINY ((1 << (7-NDN_TT_BITS)) - 1)
#define NDN_TT_HBIT ((unsigned char)(1 << 7))

/**
 * Type tag for a ndnb start marker.
 */
enum ndn_tt {
    NDN_EXT,        /**< starts composite extension - numval is subtype */
    NDN_TAG,        /**< starts composite - numval is tagnamelen-1 */ 
    NDN_DTAG,       /**< starts composite - numval is tagdict index (enum ndn_dtag) */
    NDN_ATTR,       /**< attribute - numval is attrnamelen-1, value follows */
    NDN_DATTR,      /**< attribute numval is attrdict index */
    NDN_BLOB,       /**< opaque binary data - numval is byte count */
    NDN_UDATA,      /**< UTF-8 encoded character data - numval is byte count */
    NDN_NO_TOKEN    /**< should not occur in encoding */
};

/** NDN_CLOSE terminates composites */
#define NDN_CLOSE ((unsigned char)(0))

enum ndn_ext_subtype {
    /* skip smallest values for now */
    NDN_PROCESSING_INSTRUCTIONS = 16 /* <?name:U value:U?> */
};

/**
 * DTAG identifies ndnb-encoded elements.
 * c.f. tagname.csvdict
 * See the gen_enum_dtag script for help updating these.
 */
enum ndn_dtag {
    NDN_DTAG_Any = 13,
    NDN_DTAG_Name = 14,
    NDN_DTAG_Component = 15,
    NDN_DTAG_Certificate = 16,
    NDN_DTAG_Collection = 17,
    NDN_DTAG_CompleteName = 18,
    NDN_DTAG_Content = 19,
    NDN_DTAG_SignedInfo = 20,
    NDN_DTAG_ContentDigest = 21,
    NDN_DTAG_ContentHash = 22,
    NDN_DTAG_Count = 24,
    NDN_DTAG_Header = 25,
    NDN_DTAG_Interest = 26,	/* 20090915 */
    NDN_DTAG_Key = 27,
    NDN_DTAG_KeyLocator = 28,
    NDN_DTAG_KeyName = 29,
    NDN_DTAG_Length = 30,
    NDN_DTAG_Link = 31,
    NDN_DTAG_LinkAuthenticator = 32,
    NDN_DTAG_NameComponentCount = 33,	/* DeprecatedInInterest */
    NDN_DTAG_ExtOpt = 34,
    NDN_DTAG_RootDigest = 36,
    NDN_DTAG_Signature = 37,
    NDN_DTAG_Start = 38,
    NDN_DTAG_Timestamp = 39,
    NDN_DTAG_Type = 40,
    NDN_DTAG_Nonce = 41,
    NDN_DTAG_Scope = 42,
    NDN_DTAG_Exclude = 43,
    NDN_DTAG_Bloom = 44,
    NDN_DTAG_BloomSeed = 45,
    NDN_DTAG_AnswerOriginKind = 47,
    NDN_DTAG_InterestLifetime = 48,
    NDN_DTAG_Witness = 53,
    NDN_DTAG_SignatureBits = 54,
    NDN_DTAG_DigestAlgorithm = 55,
    NDN_DTAG_BlockSize = 56,
    NDN_DTAG_FreshnessSeconds = 58,
    NDN_DTAG_FinalBlockID = 59,
    NDN_DTAG_PublisherPublicKeyDigest = 60,
    NDN_DTAG_PublisherCertificateDigest = 61,
    NDN_DTAG_PublisherIssuerKeyDigest = 62,
    NDN_DTAG_PublisherIssuerCertificateDigest = 63,
    NDN_DTAG_ContentObject = 64,	/* 20090915 */
    NDN_DTAG_WrappedKey = 65,
    NDN_DTAG_WrappingKeyIdentifier = 66,
    NDN_DTAG_WrapAlgorithm = 67,
    NDN_DTAG_KeyAlgorithm = 68,
    NDN_DTAG_Label = 69,
    NDN_DTAG_EncryptedKey = 70,
    NDN_DTAG_EncryptedNonceKey = 71,
    NDN_DTAG_WrappingKeyName = 72,
    NDN_DTAG_Action = 73,
    NDN_DTAG_FaceID = 74,
    NDN_DTAG_IPProto = 75,
    NDN_DTAG_Host = 76,
    NDN_DTAG_Port = 77,
    NDN_DTAG_MulticastInterface = 78,
    NDN_DTAG_ForwardingFlags = 79,
    NDN_DTAG_FaceInstance = 80,
    NDN_DTAG_ForwardingEntry = 81,
    NDN_DTAG_MulticastTTL = 82,
    NDN_DTAG_MinSuffixComponents = 83,
    NDN_DTAG_MaxSuffixComponents = 84,
    NDN_DTAG_ChildSelector = 85,
    NDN_DTAG_RepositoryInfo = 86,
    NDN_DTAG_Version = 87,
    NDN_DTAG_RepositoryVersion = 88,
    NDN_DTAG_GlobalPrefix = 89,
    NDN_DTAG_LocalName = 90,
    NDN_DTAG_Policy = 91,
    NDN_DTAG_Namespace = 92,
    NDN_DTAG_GlobalPrefixName = 93,
    NDN_DTAG_PolicyVersion = 94,
    NDN_DTAG_KeyValueSet = 95,
    NDN_DTAG_KeyValuePair = 96,
    NDN_DTAG_IntegerValue = 97,
    NDN_DTAG_DecimalValue = 98,
    NDN_DTAG_StringValue = 99,
    NDN_DTAG_BinaryValue = 100,
    NDN_DTAG_NameValue = 101,
    NDN_DTAG_Entry = 102,
    NDN_DTAG_ACL = 103,
    NDN_DTAG_ParameterizedName = 104,
    NDN_DTAG_Prefix = 105,
    NDN_DTAG_Suffix = 106,
    NDN_DTAG_Root = 107,
    NDN_DTAG_ProfileName = 108,
    NDN_DTAG_Parameters = 109,
    NDN_DTAG_InfoString = 110,
    NDN_DTAG_StatusResponse = 112,
    NDN_DTAG_StatusCode = 113,
    NDN_DTAG_StatusText = 114,
    NDN_DTAG_SyncNode = 115,
    NDN_DTAG_SyncNodeKind = 116,
    NDN_DTAG_SyncNodeElement = 117,
    NDN_DTAG_SyncVersion = 118,
    NDN_DTAG_SyncNodeElements = 119,
    NDN_DTAG_SyncContentHash = 120,
    NDN_DTAG_SyncLeafCount = 121,
    NDN_DTAG_SyncTreeDepth = 122,
    NDN_DTAG_SyncByteCount = 123,
    NDN_DTAG_SyncConfigSlice = 124,
    NDN_DTAG_SyncConfigSliceList = 125,
    NDN_DTAG_SyncConfigSliceOp = 126,
    NDN_DTAG_SyncNodeDeltas = 127,
    NDN_DTAG_SequenceNumber = 256,
    NDN_DTAG_NDNProtocolDataUnit = 20587744 // the encoded empty element, viewed as a string is "NDN\202\000"
};

struct ndn_dict_entry {
    int index;              /**< matches enum ndn_dtag above */
    const char *name;       /**< textual name of dtag */
};

struct ndn_dict {
    int count;              /**< Count of elements in the table */
    const struct ndn_dict_entry *dict; /**< the table entries */
};

/**
 * Table for translating from DTAGs to names and vice versa.
 */
extern const struct ndn_dict ndn_dtag_dict; /* matches enum ndn_dtag above */

struct ndn_skeleton_decoder { /* initialize to all 0 */
    ssize_t index;          /**< Number of bytes processed */
    int state;              /**< Decoder state */
    int nest;               /**< Element nesting */
    size_t numval;          /**< Current numval, meaning depends on state */
    size_t token_index;     /**< Starting index of most-recent token */
    size_t element_index;   /**< Starting index of most-recent element */
};

/**
 * The decoder state is one of these, possibly with some
 * additional bits set for internal use.  A complete parse
 * ends up in state 0 or an error state.  Not all possible
 * error states are listed here.
 */
enum ndn_decoder_state {
    NDN_DSTATE_INITIAL = 0,
    NDN_DSTATE_NEWTOKEN,
    NDN_DSTATE_NUMVAL,
    NDN_DSTATE_UDATA,
    NDN_DSTATE_TAGNAME,
    NDN_DSTATE_ATTRNAME,
    NDN_DSTATE_BLOB,
    /* All error states are negative */
    NDN_DSTATE_ERR_OVERFLOW = -1,
    NDN_DSTATE_ERR_ATTR     = -2,       
    NDN_DSTATE_ERR_CODING   = -3,
    NDN_DSTATE_ERR_NEST     = -4, 
    NDN_DSTATE_ERR_BUG      = -5
};

/**
 * If the NDN_DSTATE_PAUSE bit is set in the decoder state,
 * the decoder will return just after recognizing each token.
 * In this instance, use NDN_GET_TT_FROM_DSTATE() to extract
 * the token type from the decoder state;
 * NDN_CLOSE will be reported as NDN_NO_TOKEN.
 * The pause bit persists, so the end test should take that into account
 * by using the NDN_FINAL_DSTATE macro instead of testing for state 0.
 */
#define NDN_DSTATE_PAUSE (1 << 15)
#define NDN_GET_TT_FROM_DSTATE(state) (NDN_TT_MASK & ((state) >> 16))
#define NDN_FINAL_DSTATE(state) (((state) & (NDN_DSTATE_PAUSE-1)) == 0)

ssize_t ndn_skeleton_decode(struct ndn_skeleton_decoder *d,
                            const unsigned char *p,
                            size_t n);

#endif
