/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */


extern "C" {
#define ndn NDN_HANDLE_CANNOT_BE_USED_HERE
#include <ndn-tlv/ndnd.h>
#include <ndn-tlv/ndn.h>
#include <ndn-tlv/charbuf.h>
#include <ndn-tlv/coding.h>

#include "../ndnd/ndnd_private.h"
#undef ndn
}

#include "ndnb-to-tlv.hpp"
#include <ndn-cpp-dev/name-component.hpp>
#include <ndn-cpp-dev/meta-info.hpp>

namespace ndn {

Block
interest_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi, const ndn_indexbuf &comps)
{
  Block interest(Tlv::Interest);
  
  // Name
  interest.push_back(name_ndnb_to_tlv(buf, comps));

  // Selectors
  Block selectors = selectors_ndnb_to_tlv(buf, pi);
  if (!selectors.elements().empty())
    {
      interest.push_back(selectors);
    }

  // "Guiders"

  // Nonce
  if (pi.offset[NDN_PI_B_Nonce] < pi.offset[NDN_PI_E_Nonce]) {
    const unsigned char *nonce;
    size_t noncesize;
    ndn_ref_tagged_BLOB(NDN_DTAG_Nonce, buf,
                        pi.offset[NDN_PI_B_Nonce],
                        pi.offset[NDN_PI_E_Nonce],
                        &nonce, &noncesize);

    if (noncesize > 4)
      noncesize = 4;

    interest.push_back
      (dataBlock(Tlv::Nonce, nonce, noncesize));
  }

  // Scope
  if (pi.offset[NDN_PI_B_Scope] < pi.offset[NDN_PI_E_Scope]) {

    interest.push_back
      (nonNegativeIntegerBlock(Tlv::Scope, pi.scope));
  }

  // InterestLifetime
  if (pi.offset[NDN_PI_B_InterestLifetime] < pi.offset[NDN_PI_E_InterestLifetime]) {
    uint64_t lifetimeNdnb = ndn_interest_lifetime(buf, &pi);

    uint64_t lifetimeMs = ((lifetimeNdnb) >> 12) * 1000 + static_cast<uint64_t>((lifetimeNdnb & 0xFFF) / 4.096);

    interest.push_back
      (nonNegativeIntegerBlock(Tlv::InterestLifetime, lifetimeMs));
  }

  interest.encode();
  return interest;
}

Block
data_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co, const ndn_indexbuf &comps)
{
  Block data(Tlv::Data);

  // Name
  data.push_back(name_ndnb_to_tlv(buf, comps));

  // MetaInfo
  data.push_back(meta_info_ndnb_to_tlv(buf, co));

  // Content
  {
    const unsigned char *content;
    size_t contentSize;
    int ret = ndn_ref_tagged_BLOB(NDN_DTAG_Content, buf,
                        co.offset[NDN_PCO_B_Content],
                        co.offset[NDN_PCO_E_Content],
                        &content, &contentSize);
    if (ret < 0)
      throw NdnbToTlv::Error("Content required, but does not exist");

    data.push_back
      (dataBlock(Tlv::Content, content, contentSize));
  }

  // "Signature"
  // SignatureInfo
  data.push_back(signature_info_ndnb_to_tlv(buf, co));
  
  // SignatureValue
  {
    const unsigned char *signatureValue;
    size_t signatureValueSize;
    int ret = ndn_ref_tagged_BLOB(NDN_DTAG_SignatureBits, buf,
                        co.offset[NDN_PCO_B_SignatureBits],
                        co.offset[NDN_PCO_E_SignatureBits],
                        &signatureValue, &signatureValueSize);
    if (ret < 0)
      throw NdnbToTlv::Error("Signature required, but does not exist");

    data.push_back
      (dataBlock(Tlv::SignatureValue, signatureValue, signatureValueSize));
  }

  data.encode();
  return data;
}

Block
name_ndnb_to_tlv(const ndn_charbuf *buf)
{
  ndn_indexbuf *idx = ndn_indexbuf_create();
  ndn_name_split (buf, idx);

  Block name = name_ndnb_to_tlv(buf->buf, *idx);
  ndn_indexbuf_destroy(&idx);

  return name;
}


inline Block
name_ndnb_to_tlv(const unsigned char *buf, const ndn_indexbuf &comps)
{
  Block name(Tlv::Name);
  for (unsigned int i = 0; i < comps.n - 1; i++)
  {
    const unsigned char *compPtr;
    size_t size;
    ndn_name_comp_get(buf, &comps, i, &compPtr, &size);

    name.push_back
      (dataBlock(Tlv::NameComponent, compPtr, size));
  }
  name.encode();
  return name;
}

inline Block
selectors_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi)
{
  Block selectors(Tlv::Selectors);

  // MinSuffixComponents
  if (pi.offset[NDN_PI_B_MinSuffixComponents] < pi.offset[NDN_PI_E_MinSuffixComponents]) {
    selectors.push_back
      (nonNegativeIntegerBlock(Tlv::MinSuffixComponents, pi.min_suffix_comps));
  }
  // MaxSuffixComponents
  if (pi.offset[NDN_PI_B_MaxSuffixComponents] < pi.offset[NDN_PI_E_MaxSuffixComponents]) {
    selectors.push_back
      (nonNegativeIntegerBlock(Tlv::MaxSuffixComponents, pi.max_suffix_comps));
  }
  // PublisherPublicKeyLocator (not supported)
  // Exclude
  if (pi.offset[NDN_PI_B_Exclude] < pi.offset[NDN_PI_E_Exclude]) {
    selectors.push_back(exclude_ndnb_to_tlv(buf, pi));
  }
  // ChildSelector
  if (pi.offset[NDN_PI_B_ChildSelector] < pi.offset[NDN_PI_E_ChildSelector]) {
    selectors.push_back
      (nonNegativeIntegerBlock(Tlv::ChildSelector, pi.orderpref));
  }
  // MustBeFresh
  if (pi.offset[NDN_PI_B_AnswerOriginKind] >= pi.offset[NDN_PI_E_AnswerOriginKind] ||
      (pi.answerfrom & 4) == 0) {

    selectors.push_back
      (booleanBlock(Tlv::MustBeFresh));
  }

  selectors.encode();
  return selectors;
}

inline Block
exclude_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi)
{
  Block exclude(Tlv::Exclude);

  ndn_buf_decoder decoder;
  ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder,
                                             buf + pi.offset[NDN_PI_B_Exclude],
                                             pi.offset[NDN_PI_E_Exclude] -
                                             pi.offset[NDN_PI_B_Exclude]);

  ndn_buf_advance(d);

  int r = ndn_buf_match_dtag(d, NDN_DTAG_Any);
  if (r > 0) {
    ndn_buf_advance(d);
    ndn_buf_check_close(d);

    exclude.push_back
      (booleanBlock(Tlv::Any));
  }

  while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
    ndn_buf_advance(d);

    const unsigned char *comp;
    size_t size;
    ndn_buf_match_blob(d, &comp, &size);
    ndn_buf_check_close(d);
    
    exclude.push_back
      (dataBlock(Tlv::NameComponent, comp, size));
    
    r = ndn_buf_match_dtag(d, NDN_DTAG_Any);
    if (r > 0) {
      ndn_buf_advance(d);
      ndn_buf_check_close(d);

      exclude.push_back
        (booleanBlock(Tlv::Any));
    }
  }
  ndn_buf_check_close(d);
  
  exclude.encode();
  return exclude;
}

inline Block
meta_info_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co)
{
  MetaInfo meta;

  // ContentType
  if (co.type == NDN_CONTENT_LINK) {
    meta.setType(Tlv::ContentType_Link);
  }
  else if (co.type == NDN_CONTENT_KEY) {
    meta.setType(Tlv::ContentType_Key);
  }
  else {
    // do nothing
  }

  // FreshnessPeriod
  if (co.offset[NDN_PCO_B_FreshnessSeconds] < co.offset[NDN_PCO_E_FreshnessSeconds]) {
    uint64_t seconds = ndn_fetch_tagged_nonNegativeInteger(NDN_DTAG_FreshnessSeconds,
                                                           buf,
                                                           co.offset[NDN_PCO_B_FreshnessSeconds], co.offset[NDN_PCO_E_FreshnessSeconds]);
    seconds *= 1000;

    meta.setFreshnessPeriod(seconds);
  }

  
  // FinalBlockId
  if (co.offset[NDN_PCO_B_FinalBlockID] != co.offset[NDN_PCO_E_FinalBlockID]) {
    const unsigned char *finalid = NULL;
    size_t finalid_size = 0;
    ndn_ref_tagged_BLOB(NDN_DTAG_FinalBlockID, buf,
                        co.offset[NDN_PCO_B_FinalBlockID],
                        co.offset[NDN_PCO_E_FinalBlockID],
                        &finalid,
                        &finalid_size);

    meta.setFinalBlockId(name::Component(finalid, finalid_size));
  }

  return meta.wireEncode();
}

inline Block
signature_info_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co)
{
  Block info(Tlv::SignatureInfo);

  // SignatureType
  {
    info.push_back(nonNegativeIntegerBlock(Tlv::SignatureType, Tlv::SignatureSha256WithRsa));
  }
  
  // KeyLocator
  {
    Block keyLocator(Tlv::KeyLocator);
    if (co.offset[NDN_PCO_B_KeyName_Name] < co.offset[NDN_PCO_E_KeyName_Name]) {
      size_t length = co.offset[NDN_PCO_E_KeyName_Name] - co.offset[NDN_PCO_B_KeyName_Name];
      
      ndn_indexbuf *indexbuf = ndn_indexbuf_create();
      const ndn_charbuf namebuf = { length, length, const_cast<unsigned char *> (buf + co.offset[NDN_PCO_B_KeyName_Name]) };
      ndn_name_split (&namebuf, indexbuf);

      keyLocator.push_back(name_ndnb_to_tlv(buf + co.offset[NDN_PCO_B_KeyName_Name], *indexbuf));
      
      ndn_indexbuf_destroy(&indexbuf);
    }

    keyLocator.encode();
    info.push_back(keyLocator);
  }
  
  info.encode();
  return info;
}


} // namespace ndn
