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

#include "ndnb2tlv.hpp"

using namespace ndn::tlv;

namespace ndn {

void
interest_tlv_to_ndnb(Element &tlv, struct ndn_charbuf *ndnb)
{
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Interest, NDN_DTAG);

  // Name
  name_tlv_to_ndnb(tlv.get(tlv::Name), ndnb);

  // 
  selectors_tlv_to_ndnb(tlv.get(tlv::Selectors), ndnb);

  // Scope
  Element::element_iterator val = tlv.find(tlv::Scope);
  if (val != tlv.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t scope = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_Scope, "%d", scope);
    }
  
  // InterestLifetime
  val = tlv.find(tlv::InterestLifetime);
  if (val != tlv.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      double tlvLifetime = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end()) / 1000.0;

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
  val = tlv.find(tlv::Nonce);
  if (val != tlv.getAll().end())
    {
      ndnb_append_tagged_blob(ndnb, NDN_DTAG_Nonce, val->value(), val->value_size());
    }
  
  ndn_charbuf_append_closer(ndnb); /* </Interest> */
}

void
data_tlv_to_ndnb(Element &tlv, struct ndn_charbuf *ndnb)
{
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_ContentObject, NDN_DTAG);

  // Signature
  signature_info_and_value_tlv_to_ndnb(tlv.get(tlv::SignatureInfo), tlv.get(tlv::SignatureValue), ndnb);
  // Name
  name_tlv_to_ndnb(tlv.get(tlv::Name), ndnb);
  // SignedInfo
  meta_and_signature_info_tlv_to_ndnb(tlv.get(tlv::MetaInfo), tlv.get(tlv::SignatureInfo), ndnb);
  // Content
  ndnb_append_tagged_blob(ndnb, NDN_DTAG_Content, tlv.get(tlv::Content).value(), tlv.get(tlv::Content).value_size());
  
  ndn_charbuf_append_closer(ndnb); /* </ContentObject> */
}

void
name_tlv_to_ndnb(Element &tlv, struct ndn_charbuf *ndnb)
{
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Name, NDN_DTAG);
  for (Element::element_const_iterator component = tlv.getAll().begin ();
       component != tlv.getAll().end ();
       component++)
    {
      ndnb_append_tagged_blob(ndnb, NDN_DTAG_Component, component->value(), component->value_size());
    }
  ndn_charbuf_append_closer(ndnb); /* </Name> */
}

void
selectors_tlv_to_ndnb(Element &tlv, struct ndn_charbuf *ndnb)
{
  tlv.parse();
  
  // MinSuffixComponents
  Element::element_iterator val = tlv.find(tlv::MinSuffixComponents);
  if (val != tlv.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_MinSuffixComponents, "%d", value);
    }

  // MaxSuffixComponents
  val = tlv.find(tlv::MaxSuffixComponents);
  if (val != tlv.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_MaxSuffixComponents, "%d", value);
    }

  // Exclude
  val = tlv.find(tlv::Exclude);
  if (val != tlv.getAll().end())
    {
      exclude_tlv_to_ndnb(*val, ndnb);
    }

  // ChildSelector
  val = tlv.find(tlv::ChildSelector);
  if (val != tlv.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());
      ndnb_tagged_putf(ndnb, NDN_DTAG_ChildSelector, "%d", value);
    }

  //MustBeFresh aka AnswerOriginKind
  val = tlv.find(tlv::MustBeFresh);
  if (val != tlv.getAll().end())
    {
      ndn_charbuf_append_tt(ndnb, NDN_DTAG_AnswerOriginKind, NDN_DTAG);
      ndnb_append_number(ndnb, NDN_AOK_DEFAULT);
      ndn_charbuf_append_closer(ndnb); /* </AnswerOriginKind> */
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
exclude_tlv_to_ndnb(Element &tlv, struct ndn_charbuf *ndnb)
{
  tlv.parse();

  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Exclude, NDN_DTAG);
  for (Element::element_const_iterator component = tlv.getAll().begin ();
       component != tlv.getAll().end ();
       component++)
    {
      if (component->type() == tlv::Any)
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

void
signature_info_and_value_tlv_to_ndnb(Element &info, Element &value, struct ndn_charbuf *ndnb)
{
  info.parse();

  ndn_charbuf_append_tt(ndnb, NDN_DTAG_Signature, NDN_DTAG);

  const Element &val = info.get(tlv::SignatureType);
  Buffer::const_iterator begin = val.value_begin();
  uint64_t signatureType = tlv::readNonNegativeInteger(val.value_size(), begin, val.value_end());

  switch (signatureType) {
  case tlv::SignatureSha256WithRsa:
    ndnb_append_tagged_blob(ndnb, NDN_DTAG_SignatureBits, value.value(), value.value_size());
    break;
  case tlv::DigestSha256:
  default:
    break;
    // not anything that is not SignatureSha256WithRsa is not supported
  }
  
  ndn_charbuf_append_closer(ndnb); /* </Signature> */
}

void
meta_and_signature_info_tlv_to_ndnb(Element &meta, Element &signature, struct ndn_charbuf *ndnb)
{
  meta.parse();
  // already parsed
  // reinterpret_cast<tlv::Element*>(&signature)->parseTlv();

  static char fakePublisherPublicKeyDigest[32];
  
  ndn_charbuf_append_tt(ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);

  // PublisherPublicKeyDigest (fake, required by CCNb)
  ndnb_append_tagged_blob(ndnb, NDN_DTAG_PublisherPublicKeyDigest, fakePublisherPublicKeyDigest, 32);

  // ContentType
  Element::element_iterator val = meta.find(tlv::ContentType);
  if (val != meta.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end());

      uint32_t ndnType = NDN_CONTENT_DATA;
      switch (value) {
      case tlv::ContentType_Link:
        ndnType = NDN_CONTENT_LINK;
        break;
      case tlv::ContentType_Key:
        ndnType = NDN_CONTENT_KEY;
        break;
      case tlv::ContentType_Default:
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

  // FreshnessPeriod aka FreshnessSeconds
  val = meta.find(tlv::FreshnessPeriod);
  if (val != meta.getAll().end())
    {
      Buffer::const_iterator begin = val->value_begin();
      uint64_t value = tlv::readNonNegativeInteger(val->value_size(), begin, val->value_end()) / 1000;
      ndnb_tagged_putf(ndnb, NDN_DTAG_FreshnessSeconds, "%d", value);    
    }

  // KeyLocator
  {
    const Element &signatureTypeElement = signature.get(tlv::SignatureType);
    Buffer::const_iterator begin = signatureTypeElement.value_begin();
    uint64_t signatureType = tlv::readNonNegativeInteger(signatureTypeElement.value_size(),
                                                         begin, signatureTypeElement.value_end());
    if (signatureType == tlv::SignatureSha256WithRsa)
      {
        Element::element_iterator keyLocatorElement = signature.find(tlv::KeyLocator);
        if (keyLocatorElement != signature.getAll().end())
          {
            keyLocatorElement->parse();
            Element::element_iterator name = keyLocatorElement->find(tlv::Name);
            if (name != keyLocatorElement->getAll().end())
              {
                ndn_charbuf_append_tt(ndnb, NDN_DTAG_KeyLocator, NDN_DTAG);
                ndn_charbuf_append_tt(ndnb, NDN_DTAG_KeyName, NDN_DTAG);

                for (Element::element_const_iterator component = name->getAll().begin ();
                     component != name->getAll().end ();
                     component++)
                  {
                    ndnb_append_tagged_blob(ndnb, NDN_DTAG_Component, component->value(), component->value_size());
                  }

                ndn_charbuf_append_closer(ndnb); /* </KeyName> */
                ndn_charbuf_append_closer(ndnb); /* </KeyLocator> */  
              }
          }
      }
  }
    
  ndn_charbuf_append_closer(ndnb); /* </SignedInfo> */  
}

} // namespace ndn
