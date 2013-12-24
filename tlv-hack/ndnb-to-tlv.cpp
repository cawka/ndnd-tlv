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
#include <ndn/ndnd.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>

#include "../ndnd/ndnd_private.h"
#undef ndn
}

#include "ndnb-to-tlv.hpp"

#include "tlv.hpp"

namespace ndn {

Block
interest_tlv_to_ndnb(const unsigned char *buf, const ndn_parsed_interest &pi, ndn_indexbuf &comps)
{
  Block interest(Tlv::Interest);
  
  // Name
  interest.push_back(name_ndnb_to_tlv(buf, comps));

  // Selectors
  interest.push_back(selectors_ndnb_to_tlv(buf, pi));

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
    
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::Nonce);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(noncesize));
    os.write(reinterpret_cast<const char*>(nonce), noncesize);
    
    interest.push_back(Block(os.buf()));
  }

  // Scope
  if (pi.offset[NDN_PI_B_Scope] < pi.offset[NDN_PI_E_Scope]) {
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::Scope);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(pi.scope));
    Tlv::writeNonNegativeInteger(os, pi.scope);
    
    interest.push_back(Block(os.buf()));
  }

  // InterestLifetime
  if (pi.offset[NDN_PI_B_InterestLifetime] < pi.offset[NDN_PI_E_InterestLifetime]) {
    uint64_t lifetimeNdnb = ndn_interest_lifetime(buf, &pi);

    uint64_t lifetimeMs = ((lifetimeNdnb) >> 12) * 1000 + static_cast<uint64_t>((lifetimeNdnb & 0xFFF) / 4.096);
    
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::InterestLifetime);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(lifetimeMs));
    Tlv::writeNonNegativeInteger(os, lifetimeMs);
    
    interest.push_back(Block(os.buf()));
  }

  interest.encode();
  return interest;
}

Block
data_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co, ndn_indexbuf &comps)
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
    ndn_ref_tagged_BLOB(NDN_DTAG_Content, buf,
                        co.offset[NDN_PCO_B_Content],
                        co.offset[NDN_PCO_E_Content],
                        &content, &contentSize);

    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::Content);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(contentSize));
    os.write(reinterpret_cast<const char*>(content), contentSize);
    
    data.push_back(Block(os.buf()));
  }

  // "Signature"
  // SignatureInfo
  data.push_back(signature_info_ndnb_to_tlv(buf, co));
  
  // SignatureValue
  {
    const unsigned char *signatureValue;
    size_t signatureValueSize;
    ndn_ref_tagged_BLOB(NDN_DTAG_SignatureBits, buf,
                        co.offset[NDN_PCO_E_SignatureBits],
                        co.offset[NDN_PCO_B_SignatureBits],
                        &signatureValue, &signatureValueSize);

    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::Content);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(signatureValueSize));
    os.write(reinterpret_cast<const char*>(signatureValue), signatureValueSize);
    
    data.push_back(Block(os.buf()));
  }

  data.encode();
  return data;
}

inline Block
name_ndnb_to_tlv(const unsigned char *buf, ndn_indexbuf &comps)
{
  Block name(Tlv::Name);
  for (unsigned int i = 0; i < comps.n - 1; i++)
  {
    const unsigned char *compPtr;
    size_t size;
    ndn_name_comp_get(buf, &comps, i, &compPtr, &size);

    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::NameComponent);
    Tlv::writeVarNumber(os, size);
    os.write(reinterpret_cast<const char*>(compPtr), size);
    name.push_back(Block(os.buf()));
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
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::MinSuffixComponents);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(pi.min_suffix_comps));
    Tlv::writeNonNegativeInteger(os, pi.min_suffix_comps);

    selectors.push_back(Block(os.buf()));
  }
  // MaxSuffixComponents
  if (pi.offset[NDN_PI_B_MaxSuffixComponents] < pi.offset[NDN_PI_E_MaxSuffixComponents]) {
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::MaxSuffixComponents);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(pi.max_suffix_comps));
    Tlv::writeNonNegativeInteger(os, pi.max_suffix_comps);

    selectors.push_back(Block(os.buf()));
  }
  // PublisherPublicKeyLocator (not supported)
  // Exclude
  if (pi.offset[NDN_PI_B_Exclude] < pi.offset[NDN_PI_E_Exclude]) {
    selectors.push_back(exclude_ndnb_to_tlv(buf, pi));
  }
  // ChildSelector
  if (pi.offset[NDN_PI_B_ChildSelector] < pi.offset[NDN_PI_E_ChildSelector]) {
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::ChildSelector);
    Tlv::writeVarNumber(os, Tlv::sizeOfNonNegativeInteger(pi.orderpref));
    Tlv::writeNonNegativeInteger(os, pi.orderpref);

    selectors.push_back(Block(os.buf()));
  }
  // MustBeFresh
  if (pi.offset[NDN_PI_B_AnswerOriginKind] >= pi.offset[NDN_PI_E_AnswerOriginKind] ||
      (pi.answerfrom & 4) == 0) {
    
    // MustBeFresh should be set
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::MustBeFresh);
    Tlv::writeVarNumber(os, 0);

    selectors.push_back(Block(os.buf()));
  }

  selectors.encode();
  return selectors;
}

inline Block
exclude_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_interest &pi)
{
  Block exclude(Tlv::Exclude);

  OBufferStream os;

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

    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::Any);
    Tlv::writeVarNumber(os, 0);
    exclude.push_back(Block(os.buf()));
  }

  while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
    ndn_buf_advance(d);

    const unsigned char *comp;
    size_t size;
    ndn_buf_match_blob(d, &comp, &size);
    ndn_buf_check_close(d);
    
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::NameComponent);
    Tlv::writeVarNumber(os, size);
    os.write(reinterpret_cast<const char*>(comp), size);
    exclude.push_back(Block(os.buf()));
    
    r = ndn_buf_match_dtag(d, NDN_DTAG_Any);
    if (r > 0) {
      ndn_buf_advance(d);
      ndn_buf_check_close(d);

      OBufferStream os;
      Tlv::writeVarNumber(os, Tlv::Any);
      Tlv::writeVarNumber(os, 0);
      exclude.push_back(Block(os.buf()));
    }
  }
  ndn_buf_check_close(d);
  
  exclude.encode();
  return exclude;
}

inline Block
meta_info_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co)
{
  Block meta(Tlv::MetaInfo);

  // ContentType
  if (co.type == NDN_CONTENT_LINK) {
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::ContentType);
    Tlv::writeVarNumber(os, 1);
    Tlv::writeNonNegativeInteger(os, Tlv::ContentType_Link);

    meta.push_back(Block(os.buf()));
  }
  else if (co.type == NDN_CONTENT_KEY) {
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::ContentType);
    Tlv::writeVarNumber(os, 1);
    Tlv::writeNonNegativeInteger(os, Tlv::ContentType_Key);

    meta.push_back(Block(os.buf()));
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
    
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::FreshnessPeriod);
    Tlv::writeVarNumber(os, seconds);
    Tlv::writeNonNegativeInteger(os, seconds);

    meta.push_back(Block(os.buf()));
  }
  
  meta.encode();
  return meta;
}

inline Block
signature_info_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co)
{
  Block info(Tlv::SignatureInfo);

  // SignatureType
  {
    OBufferStream os;
    Tlv::writeVarNumber(os, Tlv::SignatureType);
    Tlv::writeVarNumber(os, 1);
    Tlv::writeNonNegativeInteger(os, Tlv::SignatureSha256WithRsa);

    info.push_back(Block(os.buf()));
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
