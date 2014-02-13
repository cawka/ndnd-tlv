/**
 * @file ndndc.c
 * @brief Bring up a link to another ndnd.
 *
 * A NDNx program.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2012 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "ndndc.hpp"
#include "ndndc-srv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#if defined(NEED_GETADDRINFO_COMPAT)
#include "getaddrinfo.h"
#include "dummyin6.h"
#endif
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0 /*IEEE Std 1003.1-2001/Cor 1-2002, item XSH/TC1/D6/20*/
#endif

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
using boost::tokenizer;
using boost::escaped_list_separator;

#include "ndnd-id-fetcher.hpp"
#include <ndn-cpp-dev/security/signature-sha256-with-rsa.hpp>
#include <ndn-cpp-dev/util/random.hpp>

namespace ndn {
namespace ndndc {

Controller::Controller(Controller::OnReady onReady,
                       Controller::OnFailure onFailure,
                       int lifetime/* = -1*/)
  : m_lifetime(lifetime)
{
  ;
  NdndIdFetcher fetcher(m_ndndid, onReady, onFailure);
  m_face.expressInterest(Interest(Name("/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY"), 4000.0),
                         fetcher, fetcher);
  
}

Controller::~Controller()
{
}


int
Controller::dispatch(int check_only,
                     const std::string &cmd,
                     const std::string &options,
                     int num_options)
{
  if (cmd == "add") {
    if (num_options >= 0 && (num_options < 3 || num_options > 7))
      return INT_MIN;
    return add(check_only, options);
  }
  if (cmd == "del") {
    if (num_options >= 0 && (num_options < 3 || num_options > 7))
      return INT_MIN;
    return del(check_only, options);
  }
  if (cmd == "create") {
    if (num_options >= 0 && (num_options < 2 || num_options > 5))
      return INT_MIN;
    return create(check_only, options);
  }
  if (cmd == "destroy") {
    if (num_options >= 0 && (num_options < 2 || num_options > 5))
      return INT_MIN;
    return destroy(check_only, options);
  }
  if (cmd == "destroyface") {
    if (num_options >= 0 && num_options != 1)
      return INT_MIN;
    return destroyface(check_only, options);
  }
  if (cmd == "srv") {
    // attempt to guess parameters using SRV record of a domain in search list
    if (num_options >= 0 && num_options != 0)
      return INT_MIN;
    if (check_only) return 0;
    return srv();
  }
  return INT_MIN;
}

namespace {

inline std::string
getNextToken(tokenizer<escaped_list_separator<char> >::iterator &token, tokenizer<escaped_list_separator<char> > cmd_tokens)
{
  while (token != cmd_tokens.end())
    {
      if (token->empty())
        {
          ++token;
          continue;
        }

      std::string retval = *token;
      ++token;
      return retval;
    }

  return "";
}

void
NullPrefixAction(shared_ptr<ForwardingEntry> prefix)
{
}

void
NullFaceAction(shared_ptr<FaceInstance> prefix)
{
}


} // anonymous namespace

/*
 *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *   uri face faceid
 */
int
Controller::add(int check_only,
                const std::string &cmd)
{
  try {
    tokenizer<escaped_list_separator<char> > cmd_tokens(cmd, escaped_list_separator<char> ("\\", " \t", "'\""));
    tokenizer<escaped_list_separator<char> >::iterator token = cmd_tokens.begin();

    std::string cmd_uri      = getNextToken(token, cmd_tokens);
    std::string cmd_proto    = getNextToken(token, cmd_tokens);
    std::string cmd_host     = getNextToken(token, cmd_tokens);
    std::string cmd_port     = getNextToken(token, cmd_tokens);
    std::string cmd_flags    = getNextToken(token, cmd_tokens);
    std::string cmd_mcastttl = getNextToken(token, cmd_tokens);
    std::string cmd_mcastif  = getNextToken(token, cmd_tokens);

    shared_ptr<FaceInstance> face = parse_ndn_face_instance(cmd_proto, cmd_host, cmd_port,
                                                                     cmd_mcastttl, cmd_mcastif, m_lifetime);
    shared_ptr<ForwardingEntry> prefix = parse_ndn_forwarding_entry(cmd_uri,
                                                                             cmd_flags, m_lifetime);
    prefix->setAction("prefixreg");
    
    if (!check_only) {
      if (!boost::iequals(cmd_proto, "face")) {
        face->setAction("newface");
        startFaceAction(face, bind(&Controller::add_or_del_step2, this, _1, prefix));
      }
      else {
        add_or_del_step2(face, prefix);
      }
    }
    
  }
  catch(std::exception &e) {
    std::cerr << "WARN: " << e.what() << std::endl;
    return -1;
  }
    
  return 0;
}

void
Controller::add_or_del_step2(shared_ptr<FaceInstance> face, shared_ptr<ForwardingEntry> prefix)
{
  prefix->setFaceId(face->getFaceId());
  startPrefixAction(prefix, NullPrefixAction);
}

int
Controller::del(int check_only,
                const std::string &cmd)
{
  try {
    tokenizer<escaped_list_separator<char> > cmd_tokens(cmd, escaped_list_separator<char> ("\\", " \t", "'\""));
    tokenizer<escaped_list_separator<char> >::iterator token = cmd_tokens.begin();

    std::string cmd_uri      = getNextToken(token, cmd_tokens);
    std::string cmd_proto    = getNextToken(token, cmd_tokens);
    std::string cmd_host     = getNextToken(token, cmd_tokens);
    std::string cmd_port     = getNextToken(token, cmd_tokens);
    std::string cmd_flags    = getNextToken(token, cmd_tokens);
    std::string cmd_mcastttl = getNextToken(token, cmd_tokens);
    std::string cmd_mcastif  = getNextToken(token, cmd_tokens);

    shared_ptr<FaceInstance> face = parse_ndn_face_instance(cmd_proto, cmd_host, cmd_port,
                                                                     cmd_mcastttl, cmd_mcastif, m_lifetime);
    shared_ptr<ForwardingEntry> prefix = parse_ndn_forwarding_entry(cmd_uri,
                                                                             cmd_flags, m_lifetime);
    prefix->setAction("unreg");

    if (!check_only) {
      if (!boost::iequals(cmd_proto, "face")) {
        face->setAction("newface");
        startFaceAction(face, bind(&Controller::add_or_del_step2, this, _1, prefix));
      }
      else {
        add_or_del_step2(face, prefix);
      }
    }
  }
  catch(std::exception &e) {
    std::cerr << "WARN: " << e.what() << std::endl;
    return -1;
  }
  
  return 0;
}

/*
 *   (udp|tcp) host [port [mcastttl [mcastif]]]
 */
int
Controller::create(int check_only,
                   const std::string &cmd)
{
  try {
    tokenizer<escaped_list_separator<char> > cmd_tokens(cmd, escaped_list_separator<char> ("\\", " \t", "'\""));
    tokenizer<escaped_list_separator<char> >::iterator token = cmd_tokens.begin();

    std::string cmd_proto    = getNextToken(token, cmd_tokens);
    std::string cmd_host     = getNextToken(token, cmd_tokens);
    std::string cmd_port     = getNextToken(token, cmd_tokens);
    std::string cmd_mcastttl = getNextToken(token, cmd_tokens);
    std::string cmd_mcastif  = getNextToken(token, cmd_tokens);

    shared_ptr<FaceInstance> face = parse_ndn_face_instance(cmd_proto, cmd_host, cmd_port,
                                                                     cmd_mcastttl, cmd_mcastif, m_lifetime);

    if (!check_only) {
      face->setAction("newface");
      startFaceAction(face, NullFaceAction);
    }
  }
  catch(std::exception &e) {
    std::cerr << "WARN: " << e.what() << std::endl;
    return -1;
  }
  
  return 0;
}

/*
 *   (udp|tcp) host [port [mcastttl [mcastif]]]
 */
int
Controller::destroy(int check_only,
                    const std::string &cmd)
{
  try {
    tokenizer<escaped_list_separator<char> > cmd_tokens(cmd, escaped_list_separator<char> ("\\", " \t", "'\""));
    tokenizer<escaped_list_separator<char> >::iterator token = cmd_tokens.begin();

    std::string cmd_proto    = getNextToken(token, cmd_tokens);
    std::string cmd_host     = getNextToken(token, cmd_tokens);
    std::string cmd_port     = getNextToken(token, cmd_tokens);
    std::string cmd_mcastttl = getNextToken(token, cmd_tokens);
    std::string cmd_mcastif  = getNextToken(token, cmd_tokens);

    shared_ptr<FaceInstance> face = parse_ndn_face_instance(cmd_proto, cmd_host, cmd_port,
                                                                     cmd_mcastttl, cmd_mcastif, m_lifetime);

    if (!check_only) {
      face->setAction("destroyface");
      startFaceAction(face, NullFaceAction);
    }
  }
  catch(std::exception &e) {
    std::cerr << "WARN: " << e.what() << std::endl;
    return -1;
  }
  
  return 0;
}    

int
Controller::destroyface(int check_only,
                        const std::string &cmd)
{
  int ret_code = 0;
    
  if (cmd.empty()) {
    throw Error("command error");
  }
    
  shared_ptr<FaceInstance> face = parse_ndn_face_instance_from_face(cmd);
  if (!static_cast<bool>(face)) {
    ret_code = -1;
  }
    
  if (ret_code == 0 && check_only == 0) {
    face->setAction("destroyface");
    startFaceAction(face, NullFaceAction);
  }
    
  return ret_code;
}


int
Controller::srv()
{
  int res;
    
  std::string host;
  int port_int = 0;
  std::string proto;
  res = ndndc_query_srv(host, port_int, proto);
  if (res < 0) {
    return -1;
  }
  std::string port = boost::lexical_cast<std::string>(port_int);

  shared_ptr<FaceInstance> face = parse_ndn_face_instance(proto, host, port, "", "", -1);
  shared_ptr<ForwardingEntry> prefix = parse_ndn_forwarding_entry("/", "", m_lifetime);
    
  // crazy operation
  // First. "Create" face, which will do nothing if face already exists
  // Second. Destroy the face
  // Third. Create face for real

  face->setAction("newface");
  startFaceAction(face, bind(&Controller::srv_step2, this, _1, prefix));

  return res;
}

void
Controller::srv_step2(shared_ptr<FaceInstance> face, shared_ptr<ForwardingEntry> prefix)
{
  face->setAction("destroyface");
  startFaceAction(face, bind(&Controller::srv_step3, this, _1, prefix));
}

void
Controller::srv_step3(shared_ptr<FaceInstance> face, shared_ptr<ForwardingEntry> prefix)
{
  face->setAction("newface");
  startFaceAction(face, bind(&Controller::srv_step4, this, _1, prefix));
}

void
Controller::srv_step4(shared_ptr<FaceInstance> face, shared_ptr<ForwardingEntry> prefix)
{
  prefix->setFaceId(face->getFaceId());

  prefix->setAction("prefixreg");
  startPrefixAction(prefix, NullPrefixAction);

  prefix->setPrefix("/autoconf-route");
  startPrefixAction(prefix, NullPrefixAction);
}








shared_ptr<ForwardingEntry>
Controller::parse_ndn_forwarding_entry(const std::string &cmd_uri,
                                       const std::string &cmd_flags,
                                       int freshness)
{
  int res = 0;

  shared_ptr<ForwardingEntry> entry = make_shared<ForwardingEntry>();
  
  /* we will be creating the face to either add/delete a prefix on it */
  if (cmd_uri.empty()) {
    throw Error("command error, missing NDNx URI\n");
  }

  try {
    entry->setPrefix(Name(cmd_uri));
  }
  catch (const std::runtime_error &) {
    throw Error("command error, bad NDNx URI '"+cmd_uri+"'");
  }
    
  if (!cmd_flags.empty()) {
    try {
      int flags = boost::lexical_cast<int>(cmd_flags);

      ForwardingFlags ff;
      ff.setActive      ((flags & Tlv::FaceManagement::FORW_ACTIVE)        ? true : false);
      ff.setChildInherit((flags & Tlv::FaceManagement::FORW_CHILD_INHERIT) ? true : false);
      ff.setAdvertise   ((flags & Tlv::FaceManagement::FORW_ADVERTISE)     ? true : false);
      ff.setLast        ((flags & Tlv::FaceManagement::FORW_LAST)          ? true : false);
      ff.setCapture     ((flags & Tlv::FaceManagement::FORW_CAPTURE)       ? true : false);
      ff.setLocal       ((flags & Tlv::FaceManagement::FORW_LOCAL)         ? true : false);
      ff.setTap         ((flags & Tlv::FaceManagement::FORW_TAP)           ? true : false);
      ff.setCaptureOk   ((flags & Tlv::FaceManagement::FORW_CAPTURE_OK)    ? true : false);

      entry->setForwardingFlags(ff);
    }
    catch(const boost::bad_lexical_cast &) {
      throw Error("command error, invalid flags" + cmd_flags);
    }
  }
    
  entry->setFreshnessPeriod(freshness);
  return (entry);
}


// creates a full structure without action, if proto == "face" only the
// faceid (from cmd_host parameter) and lifetime will be filled in.
shared_ptr<FaceInstance>
Controller::parse_ndn_face_instance(const std::string &cmd_proto,
                                    const std::string &cmd_host,     const std::string &cmd_port,
                                    const std::string &cmd_mcastttl, const std::string &cmd_mcastif,
                                    int freshness)
{
  struct addrinfo hints;
  hints.ai_flags = (AI_ADDRCONFIG);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype=0;
  hints.ai_protocol=0;
  hints.ai_addrlen=0;
  hints.ai_addr=0;
  hints.ai_canonname=0;
  hints.ai_next=0;
    

  struct addrinfo mcasthints;
  mcasthints.ai_flags = (AI_ADDRCONFIG | AI_NUMERICHOST);
  mcasthints.ai_family = AF_UNSPEC;
  mcasthints.ai_socktype=0;
  mcasthints.ai_protocol=0;
  mcasthints.ai_addrlen=0;
  mcasthints.ai_addr=0;
  mcasthints.ai_canonname=0;
  mcasthints.ai_next=0;

  struct addrinfo *raddrinfo = NULL;
  struct addrinfo *mcastifaddrinfo = NULL;
  char rhostnamebuf [NI_MAXHOST];
  char rhostportbuf [NI_MAXSERV];
  int off_address = -1, off_port = -1, off_source_address = -1;
  int res;
  int socktype;

  shared_ptr<FaceInstance> entry = make_shared<FaceInstance>();
  
  if (cmd_proto.empty()) {
    throw Error("command error, missing address type");
  }
  if (boost::iequals(cmd_proto, "udp")) {
    entry->setIpProto(IPPROTO_UDP);
    socktype = SOCK_DGRAM;
  } else if (boost::iequals(cmd_proto, "tcp")) {
    entry->setIpProto(IPPROTO_TCP);
    socktype = SOCK_STREAM;
  } else if (boost::iequals(cmd_proto, "face")) {
    
    unsigned long faceid = boost::lexical_cast<unsigned long>(cmd_host);
    if (faceid > UINT_MAX || faceid == 0) {
      throw Error("command error, face number invalid or out of range '" + cmd_host + "'");
    }
    entry->setFaceId(faceid);
    entry->setFreshnessPeriod(freshness);
    return entry;
    
  } else {
    throw Error("command error, unrecognized address type '" + cmd_proto + "'");
  }
    
  if (cmd_host.empty()) {
    throw Error("command error, missing hostname");
  }

  std::string cmd_port_real= cmd_port;
  if (cmd_port.empty() || cmd_port[0] == 0)
    cmd_port_real = "6363";
  
  hints.ai_socktype = socktype;
  res = getaddrinfo(cmd_host.c_str(), cmd_port_real.c_str(), &hints, &raddrinfo);
  if (res != 0 || raddrinfo == NULL) {
    throw Error("command error, getaddrinfo for host ["+cmd_host+"] port ["+cmd_port_real+"]: "+gai_strerror(res));
  }
  res = getnameinfo(raddrinfo->ai_addr, raddrinfo->ai_addrlen,
                    rhostnamebuf, sizeof(rhostnamebuf),
                    rhostportbuf, sizeof(rhostportbuf),
                    NI_NUMERICHOST | NI_NUMERICSERV);
  freeaddrinfo(raddrinfo);
  if (res != 0) {
    throw Error(std::string("command error, getnameinfo: ") + gai_strerror(res));
  }

  entry->setHost(rhostnamebuf);
  entry->setPort(rhostportbuf);
    
  if (!cmd_mcastttl.empty()) {
    try {
      int ttl = boost::lexical_cast<int>(cmd_mcastttl);
      if(ttl < 0 || ttl > 255) {
        throw Error("command error, invalid multicast ttl: " + cmd_mcastttl);
      }

      entry->setMulticastTtl(ttl);
    }
      
    catch(const boost::bad_lexical_cast &) {
      throw Error("command error, invalid multicast ttl: " + cmd_mcastttl);
    }
  }
    
  if (!cmd_mcastif.empty()) {
    res = getaddrinfo(cmd_mcastif.c_str(), NULL, &mcasthints, &mcastifaddrinfo);
    if (res != 0) {
      throw Error("command error, incorrect multicat interface ["+cmd_mcastif+"]: "
                                "mcastifaddr getaddrinfo: %s" +gai_strerror(res));
    }
        
    res = getnameinfo(mcastifaddrinfo->ai_addr, mcastifaddrinfo->ai_addrlen,
                      rhostnamebuf, sizeof(rhostnamebuf),
                      NULL, 0,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    freeaddrinfo(mcastifaddrinfo);
    if (res != 0) {
      throw Error(std::string("command error, getnameinfo: ") + gai_strerror(res));
    }
    
    entry->setMulticastInterface(rhostnamebuf);
  }
    
  entry->setFreshnessPeriod(freshness);
    
  return entry;
}

shared_ptr<FaceInstance>
Controller::parse_ndn_face_instance_from_face(const std::string &cmd_faceid)
{
  shared_ptr<FaceInstance> entry = make_shared<FaceInstance>();
    
  /* destroy a face - the URI field will hold the face number */
  if (cmd_faceid.empty()) {
    throw Error("command error, missing face number for destroyface");
  }

  try {
    int face = boost::lexical_cast<int>(cmd_faceid);
    if (face < 0) {
      throw Error("command error invalid face number for destroyface: " + cmd_faceid);
    }
    entry->setFaceId(face);
  }
  catch(const boost::bad_lexical_cast &) {
    throw Error("command error invalid face number for destroyface: " + cmd_faceid);
  }
  
  return entry;
}

namespace {

void
onFaceActionSuccess(function< void (shared_ptr<FaceInstance>) > onSuccess,
                    Data& data)
{
  Block content = data.getContent();
  content.parse();

  if (content.elements().empty())
    {
      throw Controller::Error("Error while communicating to the local NDN forwarder");
    }

  Block::element_const_iterator val = content.elements().begin();
  
  switch(val->type())
    {
    case Tlv::FaceManagement::FaceInstance:
      {
        shared_ptr<FaceInstance> entry = make_shared<FaceInstance>();
        entry->wireDecode(*val);

        onSuccess(entry);
        return;
      }
    case Tlv::FaceManagement::StatusResponse:
      {
        // failed :(
        StatusResponse resp;
        resp.wireDecode(*val);
      
        throw Controller::Error("Local NDN forwarder reported error: " + boost::lexical_cast<std::string>(resp));
        return;
      }
    default:
      {
        throw Controller::Error("Error while communicating to the local NDN forwarder");
      }
    }
}

void
onPrefixActionSuccess(function< void (shared_ptr<ForwardingEntry>) > onSuccess,
                      Data& data)
{
  Block content = data.getContent();
  content.parse();

  if (content.elements().empty())
    {
      throw Controller::Error("Error while communicating to the local NDN forwarder");
    }

  Block::element_const_iterator val = content.elements().begin();
  
  switch(val->type())
    {
    case Tlv::FaceManagement::ForwardingEntry:
      {
        shared_ptr<ForwardingEntry> entry = make_shared<ForwardingEntry>();
        entry->wireDecode(*val);

        onSuccess(entry);
        return;
      }
    case Tlv::FaceManagement::StatusResponse:
      {
        // failed :(
        StatusResponse resp;
        resp.wireDecode(*val);
      
        throw Controller::Error("Local NDN forwarder reported error: " + boost::lexical_cast<std::string>(resp));
        return;
      }
    default:
      {
        throw Controller::Error("Error while communicating to the local NDN forwarder");
      }
    }
}

void
onActionFailure()
{
  throw Controller::Error("Error while communicating to the local NDN forwarder");
}

} // anonymous namespace

void
Controller::startFaceAction(shared_ptr<FaceInstance> entry,
                            function< void (shared_ptr<FaceInstance>) > onSuccess)
{
  // Set the ForwardingEntry as the content of a Data packet and sign.
  Data data;
  data.setName(Name().appendVersion(random::generateWord32()));
  data.setContent(entry->wireEncode());
  
  // Create an empty signature, since nobody going to verify it for now
  // @todo In the future, we may require real signatures to do the registration
  SignatureSha256WithRsa signature;
  signature.setValue(Block(Tlv::SignatureValue, make_shared<Buffer>()));
  data.setSignature(signature);

  // Create an interest where the name has the encoded Data packet.
  Name interestName;
  interestName.append("ndnx");
  interestName.append(m_ndndid);
  interestName.append(entry->getAction());
  interestName.append(data.wireEncode());

  Interest interest(interestName);
  interest.setScope(1);
  interest.setInterestLifetime(1000);
  interest.setMustBeFresh(true);

  m_face.expressInterest(interest,
                         bind(onFaceActionSuccess, onSuccess, _2),
                         bind(onActionFailure));
}

void
Controller::startPrefixAction(shared_ptr<ForwardingEntry> entry,
                              function< void (shared_ptr<ForwardingEntry>) > onSuccess)
{
  // Set the ForwardingEntry as the content of a Data packet and sign.
  Data data;
  data.setName(Name().appendVersion(random::generateWord32()));
  data.setContent(entry->wireEncode());
  
  // Create an empty signature, since nobody going to verify it for now
  // @todo In the future, we may require real signatures to do the registration
  SignatureSha256WithRsa signature;
  signature.setValue(Block(Tlv::SignatureValue, make_shared<Buffer>()));
  data.setSignature(signature);

  // Create an interest where the name has the encoded Data packet.
  Name interestName;
  interestName.append("ndnx");
  interestName.append(m_ndndid);
  interestName.append(entry->getAction());
  interestName.append(data.wireEncode());

  Interest interest(interestName);
  interest.setScope(1);
  interest.setInterestLifetime(1000);
  interest.setMustBeFresh(true);

  m_face.expressInterest(interest,
                         bind(onPrefixActionSuccess, onSuccess, _2),
                         bind(onActionFailure));
}


} // namespace ndndc
} // namespace ndn
