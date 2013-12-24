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
  Block name(Tlv::Name);
  for (unsigned int i = 0; i < comps.n - 1; i++)
  {
    const unsigned char *compPtr;
    size_t size;
    ndn_name_comp_get(buf, &comps, i, &compPtr, &size);

    
    
    // Bytes comp;
    // readRaw(comp, compPtr, size);
    // m_comps.push_back(comp);
  }

  return interest;
}

Block
data_ndnb_to_tlv(const unsigned char *buf, const ndn_parsed_ContentObject &co, ndn_indexbuf &comps)
{
  Block data(Tlv::Data);

  return data;
}

} // namespace ndn
