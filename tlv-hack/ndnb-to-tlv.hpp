/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_NDNB_TO_TLV_HPP
#define NDN_NDNB_TO_TLV_HPP

#include "block.hpp"

extern "C" {
  struct ndn_charbuf;
  struct ndn_parsed_interest;
  struct ndn_indexbuf;
}

namespace ndn {

Block
interest_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi, ndn_indexbuf &comps);

Block
data_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co, ndn_indexbuf &comps);

// void
// name_ndnb_to_tlv(tlv::Element &tlv, unsigned char *tlv, size_t maxsize);

// void
// selectors_ndnb_to_tlv(tlv::Element &tlv, unsigned char *tlv, size_t maxsize);

// void
// exclude_ndnb_to_tlv(tlv::Element &tlv, unsigned char *tlv, size_t maxsize);

// void
// signature_info_and_value_ndnb_to_tlv(tlv::Element &info, tlv::Element &value, struct ndn_charbuf *ndnb);

// void
// meta_and_signature_info_ndnb_to_tlv(tlv::Element &meta, tlv::Element &signature, struct ndn_charbuf *ndnb);

}

#endif // NDN_NDNB_TO_TLV_HPP
