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

#include "tlv-hack.h"
#include "ndnb2tlv.hpp"

using namespace ndn;

////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" {

ssize_t
tlv_to_ndnb(const unsigned char *buf, size_t length, struct ndn_charbuf *ndnb)
{
  try {
    tlv::Element tlv(reinterpret_cast<const uint8_t*> (buf), length);

    switch (tlv.type()) {
    case tlv::Interest:
        interest_tlv_to_ndnb(tlv, ndnb);
        break;
    case tlv::Data:
        data_tlv_to_ndnb(tlv, ndnb);
        break;
    default:
      return -1;
      break;
    }

    return tlv.size();
  }
  catch (error::Tlv &error) {
    // do nothing
  }
  
  return -1;
}

ssize_t
ndnb_to_tlv(const unsigned char *buf, size_t length, unsigned char *tlvbuf, size_t maxlength)
{
  return -1;
}

}

