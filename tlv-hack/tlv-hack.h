/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef TLV_HACK_H
#define TLV_HACK_H

#ifdef __cplusplus
extern "C" {
#endif

struct ndn_charbuf;
  
/**
 * @brief Convert TLV-encoded NDN packet into CCNb encoding
 *
 * This function supports only Interest and Data packet conversion
 *
 * @param [in] h     ndnd handle (for logging purposes)
 * @param [in] buf   Input buffer with TLV-encoded message
 * @param [in] res   Maximum size of the input buffer
 * @param [out] ndnb Buffer to write CCNb encoded message to. MUST NOT be NULL.
 *
 * @returns the number of consumed bytes from the wire, -1 if not
 *          sufficient buffer length to fully parse TLV format
 */
ssize_t
tlv_to_ndnb(const unsigned char *buf, size_t length, struct ndn_charbuf *ndnb);

ssize_t
ndnb_to_tlv(const unsigned char *buf, size_t length, unsigned char *tlvbuf, size_t maxlength);

ssize_t
tlv_encode_StatusResponse(struct ndn_charbuf *ndnb, int errcode, const char *errtext);
  
#ifdef __cplusplus
}
#endif

#endif // TLV_HACK_H
