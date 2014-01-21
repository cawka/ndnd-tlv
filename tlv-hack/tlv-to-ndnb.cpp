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

#include "tlv-to-ndnb.hpp"
#include <ndn-cpp-dev/security/signature-sha256-with-rsa.hpp>

namespace ndn {

void
interest_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb)
{
  block.parse();
  
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Interest, NDN_DTAG);

  // Name
  name_tlv_to_ndnb(block.get(Tlv::Name), ndnb);

  // Selectors
  Block::element_iterator val = block.find(Tlv::Selectors);
  if (val != block.getAll().end())
    {
      selectors_tlv_to_ndnb(*val, ndnb);
    }
  else
    {
      // due to change of the semantics, when TLV selectors are not present, enable NDNb selector to allow stale data
      
      ndn_charbuf_append_tt(ndnb, NDN_DTAG_AnswerOriginKind, NDN_DTAG);
      ndnb_append_number(ndnb, NDN_AOK_DEFAULT | NDN_AOK_STALE);
      ndn_charbuf_append_closer(ndnb); /* </AnswerOriginKind> */
    }

  // Scope
  val = block.find(Tlv::Scope);
  if (val != block.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t scope = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_Scope, "%d", scope);
    }
  
  // InterestLifetime
  val = block.find(Tlv::InterestLifetime);
  if (val != block.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      double tlvLifetime = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end()) / 1000.0;

      // Ndnx timestamp unit is weird 1/4096 second
      // this is from their code
      unsigned lifetime = 4096 * (tlvLifetime + 1.0/8192.0);
      unsigned char buf[3] = {0};
      for (int i = sizeof(buf) - 1; i >= 0; i--, lifetime >>= 8)
        {
          buf[i] = lifetime & 0xff;
        }
      ndnb_append_tagged_blob(ndnb, NDN_DTAG_InterestLifetime, buf, sizeof(buf));
    }
  
  // Nonce
  val = block.find(Tlv::Nonce);
  if (val != block.getAll().end())
    {
      ndnb_append_tagged_blob(ndnb, NDN_DTAG_Nonce, val->value(), val->value_size());
    }
  
  ndn_charbuf_append_closer(ndnb); /* </Interest> */
}

void
data_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb)
{
  block.parse();
  
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_ContentObject, NDN_DTAG);

  // Signature
  signature_info_and_value_tlv_to_ndnb(block.get(Tlv::SignatureInfo), block.get(Tlv::SignatureValue), ndnb);
  // Name
  name_tlv_to_ndnb(block.get(Tlv::Name), ndnb);
  // SignedInfo
  meta_and_signature_info_tlv_to_ndnb(block.get(Tlv::MetaInfo), block.get(Tlv::SignatureInfo), ndnb);
  // Content
  ndnb_append_tagged_blob(ndnb, NDN_DTAG_Content, block.get(Tlv::Content).value(), block.get(Tlv::Content).value_size());
  
  ndn_charbuf_append_closer(ndnb); /* </ContentObject> */
}

void
name_to_ndnb(const Name &name, ndn_charbuf *ndnb)
{
  // Name
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Name, NDN_DTAG);

  for (Name::const_iterator i = name.begin(); i != name.end(); ++i)
    {
      // Component
      ndnb_append_tagged_blob(ndnb, NDN_DTAG_Component, i->getValue().buf(), i->getValue().size());
    }
  
  ndn_charbuf_append_closer(ndnb); /* </Name> */
}

inline void
name_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb)
{
  block.parse();
  
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Name, NDN_DTAG);
  for (Block::element_const_iterator component = block.getAll().begin ();
       component != block.getAll().end ();
       component++)
    {
      ndnb_append_tagged_blob(ndnb, NDN_DTAG_Component, component->value(), component->value_size());
    }
  ndn_charbuf_append_closer(ndnb); /* </Name> */
}

inline void
selectors_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb)
{
  block.parse();
  
  // MinSuffixComponents
  Block::element_iterator val = block.find(Tlv::MinSuffixComponents);
  if (val != block.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_MinSuffixComponents, "%d", value);
    }

  // MaxSuffixComponents
  val = block.find(Tlv::MaxSuffixComponents);
  if (val != block.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_MaxSuffixComponents, "%d", value);
    }

  // Exclude
  val = block.find(Tlv::Exclude);
  if (val != block.getAll().end())
    {
      exclude_tlv_to_ndnb(*val, ndnb);
    }

  // ChildSelector
  val = block.find(Tlv::ChildSelector);
  if (val != block.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_ChildSelector, "%d", value);
    }

  //MustBeFresh aka AnswerOriginKind
  val = block.find(Tlv::MustBeFresh);
  if (val != block.getAll().end())
    {
      // ndn_charbuf_append_tt(ndnb, NDN_DTAG_AnswerOriginKind, NDN_DTAG);
      // ndnb_append_number(ndnb, NDN_AOK_DEFAULT);
      // ndn_charbuf_append_closer(ndnb); /* </AnswerOriginKind> */
    }
  else
    {
      // the default has been changed
      
      ndn_charbuf_append_tt(ndnb, NDN_DTAG_AnswerOriginKind, NDN_DTAG);
      ndnb_append_number(ndnb, NDN_AOK_DEFAULT | NDN_AOK_STALE);
      ndn_charbuf_append_closer(ndnb); /* </AnswerOriginKind> */
    }
}

void
exclude_tlv_to_ndnb(Block &block, ndn_charbuf *ndnb)
{
  block.parse();

  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Exclude, NDN_DTAG);
  for (Block::element_const_iterator component = block.getAll().begin ();
       component != block.getAll().end ();
       component++)
    {
      if (component->type() == Tlv::Any)
        {
          ndn_charbuf_append_tt(ndnb, NDN_DTAG_Any, NDN_DTAG);
          ndn_charbuf_append_closer(ndnb);
        }
      else
        {
          ndnb_append_tagged_blob(ndnb, NDN_DTAG_Component, component->value(), component->value_size());
        }
    }
  ndn_charbuf_append_closer(ndnb); /* </Exclude> */
}

inline void
signature_info_and_value_tlv_to_ndnb(Block &info, Block &value, ndn_charbuf *ndnb)
{
  info.parse();

  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Signature, NDN_DTAG);

  const Block &val = info.get(Tlv::SignatureType);
  Buffer::const_iterator begin = val.value_begin();
  uint64_t signatureType = Tlv::readNonNegativeInteger(val.value_size(), begin, val.value_end());

  switch (signatureType) {
  case Tlv::SignatureSha256WithRsa:
    ndnb_append_tagged_blob(ndnb, NDN_DTAG_SignatureBits, value.value(), value.value_size());
    break;
  case Tlv::DigestSha256:
  default:
    break;
    // not anything that is not SignatureSha256WithRsa is not supported
  }
  
  ndn_charbuf_append_closer(ndnb); /* </Signature> */
}

inline void
meta_and_signature_info_tlv_to_ndnb(Block &metaInfo, Block &signatureInfo, ndn_charbuf *ndnb)
{
  metaInfo.parse();
  signatureInfo.parse();

  static char fakePublisherPublicKeyDigest[32];
  
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);

  ////////////////////////////////////////////////
  // Note:
  // NDNd requires PublisherPublicKeyDigest and Timestamp to be present in each Data packet
  // NDN-TLV does not have these fields, so simply add junk data
  //
  
  // PublisherPublicKeyDigest (fake, required by CCNb)
  ndnb_append_tagged_blob(ndnb, NDN_DTAG_PublisherPublicKeyDigest, fakePublisherPublicKeyDigest, 32);

  // Timestamp
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Timestamp, NDN_DTAG);
  ndnb_append_now_blob(ndnb, NDN_MARKER_NONE);
  ndn_charbuf_append_closer(ndnb);
  
  // ContentType (aka Type)
  Block::element_iterator val = metaInfo.find(Tlv::ContentType);
  if (val != metaInfo.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());

      uint32_t ndnType = NDN_CONTENT_DATA;
      switch (value) {
      case Tlv::ContentType_Link:
        ndnType = NDN_CONTENT_LINK;
        break;
      case Tlv::ContentType_Key:
        ndnType = NDN_CONTENT_KEY;
        break;
      case Tlv::ContentType_Default:
      default:
        // do nothing, assume default ContentType
        break;
      }

      if (ndnType != NDN_CONTENT_DATA)
        {
          ndn_charbuf_append_tt(ndnb, NDN_DTAG_Type, NDN_DTAG);
          ndn_charbuf_append_tt(ndnb, 3, NDN_BLOB);
          ndn_charbuf_append_value(ndnb, ndnType, 3);
          ndn_charbuf_append_closer(ndnb);
        }
    }

  // FreshnessPeriod (aka FreshnessSeconds)
  val = metaInfo.find(Tlv::FreshnessPeriod);
  if (val != metaInfo.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = Tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end()) / 1000;
      ndnb_tagged_putf(ndnb, NDN_DTAG_FreshnessSeconds, "%d", value);    
    }

  // FinalBlockID is optional and is not part of NDN-TLV
  
  // KeyLocator
  {
    SignatureSha256WithRsa signature(signatureInfo);
    // exception will be thrown if some other signature is used

    // Only KeyName key locator is supported for now
    if (signature.getKeyLocator().getType() == KeyLocator::KeyLocator_Name)
      {
        ndn_charbuf_append_tt(ndnb, NDN_DTAG_KeyLocator, NDN_DTAG);
        ndn_charbuf_append_tt(ndnb, NDN_DTAG_KeyName, NDN_DTAG);

        name_to_ndnb(signature.getKeyLocator().getName(), ndnb);
        
        ndn_charbuf_append_closer(ndnb); /* </KeyName> */
        ndn_charbuf_append_closer(ndnb); /* </KeyLocator> */  
      }
  }

  // ExtOpt is optional and is not part of NDN-TLV
  
  ndn_charbuf_append_closer(ndnb); /* </SignedInfo> */  
}

} // namespace ndn
