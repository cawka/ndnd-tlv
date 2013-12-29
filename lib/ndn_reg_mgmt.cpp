/**
 * @file ndn_reg_mgmt.c
 * @brief Support for parsing and creating ForwardingEntry elements.
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 *
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009 Palo Alto Research Center, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. You should have received
 * a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#define ndn NDN_HANDLE_CANNOT_BE_USED_HERE
#include <ndn/reg_mgmt.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#undef ndn
}

#include <ndn-cpp/encoding/tlv.hpp>
#include <ndn-cpp/forwarding-entry.hpp>
#include <ndn-cpp/status-response.hpp>

#include "../tlv-hack/tlv-to-ndnb.hpp"
#include "../tlv-hack/ndnb-to-tlv.hpp"

using namespace ndn;

////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" {

struct ndn_forwarding_entry *
ndn_forwarding_entry_parse(const unsigned char *p, size_t size)
{
  ForwardingEntry entry;
  entry.wireDecode(Block(p, size));

  // calloc zeroes memory
  struct ndn_forwarding_entry *result = (struct ndn_forwarding_entry *)calloc(1, sizeof(struct ndn_forwarding_entry));

  // Action
  if (!entry.getAction().empty())
    {
      memcpy(result->store, entry.getAction().c_str(), entry.getAction().size());
      result->store[entry.getAction().size()] = 0;

      result->action = reinterpret_cast<const char*>(result->store);
    }

  // Name
  if (!entry.getPrefix().empty())
    {
      result->name_prefix = ndn_charbuf_create();
      name_to_ndnb(entry.getPrefix(), result->name_prefix);
    }

  // FaceID
  result->faceid = entry.getFaceId();

  // ForwardingFlags
  result->flags = 0;
  if (entry.getForwardingFlags().getActive())
    result->flags |= Tlv::FaceManagement::FORW_ACTIVE;
  if (entry.getForwardingFlags().getChildInherit())
    result->flags |= Tlv::FaceManagement::FORW_CHILD_INHERIT;
  if (entry.getForwardingFlags().getAdvertise())
    result->flags |= Tlv::FaceManagement::FORW_ADVERTISE;
  if (entry.getForwardingFlags().getLast())
    result->flags |= Tlv::FaceManagement::FORW_LAST;
  if (entry.getForwardingFlags().getCapture())
    result->flags |= Tlv::FaceManagement::FORW_CAPTURE;
  if (entry.getForwardingFlags().getLocal())
    result->flags |= Tlv::FaceManagement::FORW_LOCAL;
  if (entry.getForwardingFlags().getTap())
    result->flags |= Tlv::FaceManagement::FORW_TAP;
  if (entry.getForwardingFlags().getCaptureOk())
    result->flags |= Tlv::FaceManagement::FORW_CAPTURE_OK;

  // FreshnessPeriod
  if (entry.getFreshnessPeriod() >= 0)
    {
      result->lifetime = entry.getFreshnessPeriod() / 1000;
    }
  else
    {
      result->lifetime = -1;
    }
  
  return(result);
}

/**
 * Destroy the result of ndn_forwarding_entry_parse().
 */
void
ndn_forwarding_entry_destroy(struct ndn_forwarding_entry **pfe)
{
    if (*pfe == NULL)
        return;
    ndn_charbuf_destroy(&(*pfe)->name_prefix);
    free(*pfe);
    *pfe = NULL;
}

int
ndnb_append_forwarding_entry(struct ndn_charbuf *c,
                             const struct ndn_forwarding_entry *fe)
{
  ForwardingEntry entry;

  if (fe->action != NULL) {
    entry.setAction(fe->action);
  }
  if (fe->name_prefix != NULL && fe->name_prefix->length > 0) {

    Name prefix;
    prefix.wireDecode(name_ndnb_to_tlv(fe->name_prefix));
    entry.setPrefix(prefix);
  }
  // if (fe->ndnd_id_size != 0)
  //     res |= ndnb_append_tagged_blob(c, NDN_DTAG_PublisherPublicKeyDigest,
  //                                       fe->ndnd_id, fe->ndnd_id_size);
  if (fe->faceid != ~0) {
    entry.setFaceId(fe->faceid);
  }
  if (fe->flags >= 0) {
    ForwardingFlags flags;

    flags.setActive(        (fe->flags & Tlv::FaceManagement::FORW_ACTIVE)        ? true : false);
    flags.setChildInherit(  (fe->flags & Tlv::FaceManagement::FORW_CHILD_INHERIT) ? true : false);
    flags.setAdvertise(     (fe->flags & Tlv::FaceManagement::FORW_ADVERTISE)     ? true : false);
    flags.setLast(          (fe->flags & Tlv::FaceManagement::FORW_LAST)          ? true : false);
    flags.setCapture(       (fe->flags & Tlv::FaceManagement::FORW_CAPTURE)       ? true : false);
    flags.setLocal(         (fe->flags & Tlv::FaceManagement::FORW_LOCAL)         ? true : false);
    flags.setTap(           (fe->flags & Tlv::FaceManagement::FORW_TAP)           ? true : false);
    flags.setCaptureOk(     (fe->flags & Tlv::FaceManagement::FORW_CAPTURE_OK)    ? true : false);

    entry.setForwardingFlags(flags);
  }
  if (fe->lifetime >= 0) {
    entry.setFreshnessPeriod(fe->lifetime * 1000);
  }

  int res;
  res = ndn_charbuf_append(c, entry.wireEncode().wire(), entry.wireEncode().size());
  return res;
}

} // extern "C"
