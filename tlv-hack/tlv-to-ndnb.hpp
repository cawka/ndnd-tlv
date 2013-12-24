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

#include "block.hpp"

extern "C" {
struct ndn_charbuf;
}

namespace ndn {

size_t
interest_tlv_to_ndnb();

void
interest_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb);

void
data_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb);

void
name_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb);

void
selectors_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb);

void
exclude_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb);

void
signature_info_and_value_tlv_to_ndnb(Block &info, Block &value, ndn_charbuf *ndnb);

void
meta_and_signature_info_tlv_to_ndnb(Block &meta, Block &signature, ndn_charbuf *ndnb);

}

#endif // NDN_NDNB_2_TLV_HPP
