/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_NDNB_2_TLV_HPP
#define NDN_NDNB_2_TLV_HPP

#include <ndn-cpp-dev/encoding/block.hpp>
#include <ndn-cpp-dev/name.hpp>

extern "C" {
struct ndn_charbuf;
}

namespace ndn {

void
interest_tlv_to_ndnb(const Block &block, ndn_charbuf *ndnb);

void
data_tlv_to_ndnb(const Block &block, ndn_charbuf *ndnb);

void
sequence_number_tlv_to_ndnb(const Block &block, ndn_charbuf *ndnb);

void
name_to_ndnb(const Name &name, ndn_charbuf *ndnb);

// Internal use only

inline void
name_tlv_to_ndnb(const Block &block, ndn_charbuf *ndnb);

inline void
selectors_tlv_to_ndnb(const Block &block, ndn_charbuf *ndnb);

inline void
exclude_tlv_to_ndnb(const Block &block, ndn_charbuf *ndnb);

inline void
signature_info_and_value_tlv_to_ndnb(const Block &info, const Block &value, ndn_charbuf *ndnb);

inline void
meta_and_signature_info_tlv_to_ndnb(const Block &meta, const Block &signature, ndn_charbuf *ndnb);

}

#endif // NDN_NDNB_2_TLV_HPP
