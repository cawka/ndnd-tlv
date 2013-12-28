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

#include <ndn-cpp/encoding/block.hpp>

extern "C" {
  struct ndn_charbuf;
  struct ndn_parsed_interest;
  struct ndn_indexbuf;
}

namespace ndn {

namespace NdnbToTlv
{
struct Error : public std::runtime_error { Error(const std::string &what) : std::runtime_error(what) {} };
}

Block
interest_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi, const ndn_indexbuf &comps);

Block
data_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co, const ndn_indexbuf &comps);

inline Block
name_ndnb_to_tlv(const unsigned char *buf, const ndn_indexbuf &comps);

inline Block
selectors_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi);

inline Block
exclude_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi);

inline Block
meta_info_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co);

inline Block
signature_info_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co);

}

#endif // NDN_NDNB_TO_TLV_HPP
