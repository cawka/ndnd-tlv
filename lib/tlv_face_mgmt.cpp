/**
 * @file ndn_face_mgmt.c
 * @brief Support for parsing and creating FaceInstance elements.
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
#include <ndn/face_mgmt.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/sockcreate.h>
#undef ndn
}

#include <ndn-cpp/encoding/tlv.hpp>
#include <ndn-cpp/face-instance.hpp>
#include <ndn-cpp/status-response.hpp>

#include "../tlv-hack/tlv-to-ndnb.hpp"
#include "../tlv-hack/ndnb-to-tlv.hpp"

using namespace ndn;

////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" {

struct ndn_face_instance *
tlv_face_instance_parse(const unsigned char *p, size_t size)
{
  FaceInstance face;
  face.wireDecode(Block(p, size));
  
  struct ndn_face_instance *result;
  // const unsigned char *val;
  // size_t sz;
  int action_off = -1;
  int ndnd_id_off = -1;
  int host_off = -1;
  int port_off = -1;
  int mcast_off = -1;
    
  struct ndn_charbuf *store = ndn_charbuf_create();
  if (store == NULL)
    return(NULL);
  result = reinterpret_cast<struct ndn_face_instance *>(calloc(1, sizeof(*result)));
  if (result == NULL) {
    ndn_charbuf_destroy(&store);
    return(NULL);
  }

  result->store = store;
  if (!face.getAction().empty()) {
    action_off = 0;
    ndn_charbuf_append(result->store, face.getAction().c_str(), face.getAction().size()+1);
  }

  result->faceid = face.getFaceId();
  result->descr.ipproto = face.getIpProto();
  if (!face.getHost().empty()) {
    host_off = result->store->length;
    ndn_charbuf_append(result->store, face.getHost().c_str(), face.getHost().size()+1);
  }
  if (!face.getPort().empty()) {
    port_off = result->store->length;
    ndn_charbuf_append(result->store, face.getPort().c_str(), face.getPort().size()+1);
  }
  if (!face.getMulticastInterface().empty()) {
    mcast_off = result->store->length;
    ndn_charbuf_append(result->store, face.getMulticastInterface().c_str(), face.getMulticastInterface().size()+1);
  }
  result->descr.mcast_ttl = face.getMulticastTtl();
  result->lifetime = face.getFreshnessPeriod() / 1000;
  
  char *b = (char *)store->buf;
  result->action = (action_off == -1) ? NULL : b + action_off;
  result->descr.address = (host_off == -1) ? NULL : b + host_off;
  result->descr.port = (port_off == -1) ? NULL : b + port_off;
  result->descr.source_address = (mcast_off == -1) ? NULL : b + mcast_off;
  
  return(result);
}

int
tlv_append_face_instance(struct ndn_charbuf *c,
                         const struct ndn_face_instance *fi)
{
  FaceInstance face;
  if (fi->action != NULL) {
    face.setAction(fi->action);
  }
  if (fi->faceid != ~0) {
    face.setFaceId(fi->faceid);
  }
  if (fi->descr.ipproto >= 0) {
    face.setIpProto(fi->descr.ipproto);
  }
  if (fi->descr.address != NULL) {
    face.setHost(fi->descr.address);
  }
  if (fi->descr.port != NULL) {
    face.setPort(fi->descr.port);
  }
  if (fi->descr.source_address != NULL) {
    face.setMulticastInterface(fi->descr.source_address);
  }
  if (fi->descr.mcast_ttl >= 0 && fi->descr.mcast_ttl != 1) {
    face.setMulticastTtl(fi->descr.mcast_ttl);
  }
  if (fi->lifetime >= 0) {
    face.setFreshnessPeriod(fi->lifetime * 1000);
  }

  int res = ndn_charbuf_append(c, face.wireEncode().wire(), face.wireEncode().size());  
  return(res);
}

} // extern "C"
