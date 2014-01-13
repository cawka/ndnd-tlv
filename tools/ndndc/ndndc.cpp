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
#include "ndndc-log.h"
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

namespace ndn {

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
  // if (cmd == "del") {
  //   if (num_options >= 0 && (num_options < 3 || num_options > 7))
  //     return INT_MIN;
  //   return del(check_only, options);
  // }
  // if (cmd == "create") {
  //   if (num_options >= 0 && (num_options < 2 || num_options > 5))
  //     return INT_MIN;
  //   return create(check_only, options);
  // }
  // if (cmd == "destroy") {
  //   if (num_options >= 0 && (num_options < 2 || num_options > 5))
  //     return INT_MIN;
  //   return destroy(check_only, options);
  // }
  // if (cmd == "destroyface") {
  //   if (num_options >= 0 && num_options != 1)
  //     return INT_MIN;
  //   return destroyface(check_only, options);
  // }
  // if (cmd == "srv") {
  //   // attempt to guess parameters using SRV record of a domain in search list
  //   if (num_options >= 0 && num_options != 0)
  //     return INT_MIN;
  //   if (check_only) return 0;
  //   return srv(NULL, 0);
  // }
  // if (cmd == "renew") {
  //   if (num_options >= 0 && (num_options < 3 || num_options > 7))
  //     return INT_MIN;
  //   return renew(check_only, options);
  // }
  return INT_MIN;
}

namespace {

inline std::string
getNextToken(tokenizer<escaped_list_separator<char> >::iterator &token, tokenizer<escaped_list_separator<char> > cmd_tokens)
{
  if (token != cmd_tokens.end())
    {
      std::string retval = *token;
      token ++;
      return retval;
    }
  else
    return "";
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

    std::string cmd_uri = getNextToken(token, cmd_tokens);
    std::string cmd_proto = getNextToken(token, cmd_tokens);
    std::string cmd_host = getNextToken(token, cmd_tokens);
    std::string cmd_port = getNextToken(token, cmd_tokens);
    std::string cmd_flags = getNextToken(token, cmd_tokens);
    std::string cmd_mcastttl = getNextToken(token, cmd_tokens);
    std::string cmd_mcastif = getNextToken(token, cmd_tokens);

    ptr_lib::shared_ptr<FaceInstance> face = parse_ndn_face_instance(cmd_proto, cmd_host, cmd_port,
                                                                     cmd_mcastttl, cmd_mcastif, m_lifetime);
    ptr_lib::shared_ptr<ForwardingEntry> prefix = parse_ndn_forwarding_entry(cmd_uri,
                                                                             cmd_flags, m_lifetime);
    
    if (!check_only) {
      
      if (!boost::iequals(cmd_proto, "face")) {
        face->setAction("newface");
        startFaceAction(face, func_lib::bind(&Controller::add_step2, this, _1, prefix));
      }
      else {
        add_step2(face, prefix);
      }
    }
    
  }
  catch(std::exception &e) {
    ndndc_warn(__LINE__, e.what());
    return -1;
  }
    
  return 0;
}

void
onPrefixActionSucceed(ptr_lib::shared_ptr<ForwardingEntry> prefix)
{
  std::cout << "Prefix registered [" << prefix->getPrefix() << "]" << std::endl;
}

void
Controller::add_step2(ptr_lib::shared_ptr<FaceInstance> face, ptr_lib::shared_ptr<ForwardingEntry> prefix)
{
  prefix->setFaceId(face->getFaceId());
  startPrefixAction(prefix, onPrefixActionSucceed);
}

// int
// ndndc_del(struct ndndc_data *self,
//           int check_only,
//           const std::string &cmd_orig)
// {
//   int ret_code = -1;
//   std::string &cmd, *cmd_token;
//   std::string &cmd_uri = NULL;
//   std::string &cmd_proto = NULL;
//   std::string &cmd_host = NULL;
//   std::string &cmd_port = NULL;
//   std::string &cmd_flags = NULL;
//   std::string &cmd_mcastttl = NULL;
//   std::string &cmd_mcastif = NULL;
//   struct ndn_face_instance *face = NULL;
//   struct ndn_face_instance *newface = NULL;
//   struct ndn_forwarding_entry *prefix = NULL;
    
//   if (cmd_orig == NULL) {
//     ndndc_warn(__LINE__, "command error\n");
//     return -1;
//   }
    
//   cmd = strdup(cmd_orig);
//   if (cmd == NULL) {
//     ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
//     return -1;
//   }            
//   cmd_token = cmd;
//   GET_NEXT_TOKEN(cmd_token, cmd_uri);
//   GET_NEXT_TOKEN(cmd_token, cmd_proto);
//   GET_NEXT_TOKEN(cmd_token, cmd_host);
//   GET_NEXT_TOKEN(cmd_token, cmd_port);
//   GET_NEXT_TOKEN(cmd_token, cmd_flags);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
//   face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
//                                  cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
//   prefix = parse_ndn_forwarding_entry(self, cmd_uri, cmd_flags, (~0U) >> 1);
//   if (face == NULL || prefix == NULL)
//     goto Cleanup;
    
//   if (!check_only) {
//     if (0 != strcasecmp(cmd_proto, "face")) {
//       newface = ndndc_do_face_action(self, "newface", face);
//       if (newface == NULL) {
//         ndndc_warn(__LINE__, "Cannot create/lookup face");
//         goto Cleanup;
//       }
//       prefix->faceid = newface->faceid;
//       ndn_face_instance_destroy(&newface);
//     } else {
//       prefix->faceid = face->faceid;
//     }
//     ret_code = ndndc_do_prefix_action(self, "unreg", prefix);
//     if (ret_code < 0) {
//       ndndc_warn(__LINE__, "Cannot unregister prefix [%s]\n", cmd_uri);
//       goto Cleanup;
//     }
//   }
//   ret_code = 0;
//  Cleanup:
//   ndn_face_instance_destroy(&face);
//   ndn_forwarding_entry_destroy(&prefix);
//   free(cmd);
//   return (ret_code);
// }

// /*
//  *   (udp|tcp) host [port [mcastttl [mcastif]]]
//  */
// int
// ndndc_create(struct ndndc_data *self,
//              int check_only,
//              const std::string &cmd_orig)
// {
//   int ret_code = -1;
//   std::string &cmd, *cmd_token;
//   std::string &cmd_proto = NULL;
//   std::string &cmd_host = NULL;
//   std::string &cmd_port = NULL;
//   std::string &cmd_mcastttl = NULL;
//   std::string &cmd_mcastif = NULL;
//   struct ndn_face_instance *face = NULL;
//   struct ndn_face_instance *newface = NULL;
    
//   if (cmd_orig == NULL) {
//     ndndc_warn(__LINE__, "command error\n");
//     return -1;
//   }
    
//   cmd = strdup(cmd_orig);
//   if (cmd == NULL) {
//     ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
//     return -1;
//   }            
//   cmd_token = cmd;
//   GET_NEXT_TOKEN(cmd_token, cmd_proto);
//   GET_NEXT_TOKEN(cmd_token, cmd_host);
//   GET_NEXT_TOKEN(cmd_token, cmd_port);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
//   // perform sanity checking
//   face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
//                                  cmd_mcastttl, cmd_mcastif, self->lifetime);
//   if (face == NULL)
//     goto Cleanup;
    
//   if (!check_only) {
//     newface = ndndc_do_face_action(self, "newface", face);
//     if (newface == NULL) {
//       ndndc_warn(__LINE__, "Cannot create/lookup face");
//       goto Cleanup;
//     }
//     ndn_face_instance_destroy(&newface);
//   }
//   ret_code = 0;
//  Cleanup:
//   ndn_face_instance_destroy(&face);
//   free(cmd);
//   return (ret_code);
// }    

// /*
//  *   (udp|tcp) host [port [mcastttl [mcastif]]]
//  */
// int
// ndndc_destroy(struct ndndc_data *self,
//               int check_only,
//               const std::string &cmd_orig)
// {
//   int ret_code = -1;
//   std::string &cmd, *cmd_token;
//   std::string &cmd_proto = NULL;
//   std::string &cmd_host = NULL;
//   std::string &cmd_port = NULL;
//   std::string &cmd_mcastttl = NULL;
//   std::string &cmd_mcastif = NULL;
//   struct ndn_face_instance *face = NULL;
//   struct ndn_face_instance *newface = NULL;
    
//   if (cmd_orig == NULL) {
//     ndndc_warn(__LINE__, "command error\n");
//     return -1;
//   }
    
//   cmd = strdup(cmd_orig);
//   if (cmd == NULL) {
//     ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
//     return -1;
//   }            
//   cmd_token = cmd;
//   GET_NEXT_TOKEN(cmd_token, cmd_proto);
//   GET_NEXT_TOKEN(cmd_token, cmd_host);
//   GET_NEXT_TOKEN(cmd_token, cmd_port);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
//   // perform sanity checking
//   face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
//                                  cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
//   if (face == NULL)
//     goto Cleanup;
    
//   if (!check_only) {
//     // TODO: should use queryface when implemented
//     if (0 != strcasecmp(cmd_proto, "face")) {
//       newface = ndndc_do_face_action(self, "newface", face);
//       if (newface == NULL) {
//         ndndc_warn(__LINE__, "Cannot create/lookup face");
//         goto Cleanup;
//       }
//       face->faceid = newface->faceid;
//       ndn_face_instance_destroy(&newface);
//     }
//     newface = ndndc_do_face_action(self, "destroyface", face);
//     if (newface == NULL) {
//       ndndc_warn(__LINE__, "Cannot destroy face %d or the face does not exist\n", face->faceid);
//       goto Cleanup;
//     }
//     ndn_face_instance_destroy(&newface);
//   }  
//   ret_code = 0;
//  Cleanup:
//   ndn_face_instance_destroy(&face);
//   free(cmd);
//   return ret_code;
// }    

// /*
//  *   (udp|tcp) host [port [mcastttl [mcastif]]]
//  */
// /*
//  *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
//  *   uri face faceid
//  */
// int
// ndndc_renew(struct ndndc_data *self,
//             int check_only,
//             const std::string &cmd_orig)
// {
//   int ret_code = -1;
//   std::string &cmd, *cmd_token;
//   std::string &cmd_uri = NULL;
//   std::string &cmd_proto = NULL;
//   std::string &cmd_host = NULL;
//   std::string &cmd_port = NULL;
//   std::string &cmd_flags = NULL;
//   std::string &cmd_mcastttl = NULL;
//   std::string &cmd_mcastif = NULL;
//   struct ndn_face_instance *face = NULL;
//   struct ndn_face_instance *newface = NULL;
//   struct ndn_forwarding_entry *prefix = NULL;
    
//   if (cmd_orig == NULL) {
//     ndndc_warn(__LINE__, "command error\n");
//     return -1;
//   }
    
//   cmd = strdup(cmd_orig);
//   if (cmd == NULL) {
//     ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
//     return -1;
//   }            
//   cmd_token = cmd;
//   GET_NEXT_TOKEN(cmd_token, cmd_uri);
//   GET_NEXT_TOKEN(cmd_token, cmd_proto);
//   GET_NEXT_TOKEN(cmd_token, cmd_host);
//   GET_NEXT_TOKEN(cmd_token, cmd_port);
//   GET_NEXT_TOKEN(cmd_token, cmd_flags);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
//   GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
//   // perform sanity checking
//   face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
//                                  cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
//   prefix = parse_ndn_forwarding_entry(self, cmd_uri, cmd_flags, self->lifetime);
//   if (face == NULL || prefix == NULL)
//     goto Cleanup;
    
//   if (!check_only) {
//     // look up the old face ("queryface" would be useful)
//     newface = ndndc_do_face_action(self, "newface", face);
//     if (newface == NULL) {
//       ndndc_warn(__LINE__, "Cannot create/lookup face");
//       goto Cleanup;
//     }
//     face->faceid = newface->faceid;
//     ndn_face_instance_destroy(&newface);
//     // destroy the old face
//     newface = ndndc_do_face_action(self, "destroyface", face);
//     if (newface == NULL) {
//       ndndc_warn(__LINE__, "Cannot destroy face %d or the face does not exist\n", face->faceid);
//       goto Cleanup;
//     }
//     ndn_face_instance_destroy(&newface);
//     // recreate the face
//     newface = ndndc_do_face_action(self, "newface", face);
//     if (newface == NULL) {
//       ndndc_warn(__LINE__, "Cannot create/lookup face");
//       goto Cleanup;
//     }
//     prefix->faceid = newface->faceid;
//     ndn_face_instance_destroy(&newface);
//     // and add the prefix to it
//     ret_code = ndndc_do_prefix_action(self, "prefixreg", prefix);
//     if (ret_code < 0) {
//       ndndc_warn(__LINE__, "Cannot register prefix [%s]\n", cmd_uri);
//       goto Cleanup;
//     }
//   }  
//   ret_code = 0;
//  Cleanup:
//   ndn_face_instance_destroy(&face);
//   ndn_forwarding_entry_destroy(&prefix);
//   free(cmd);
//   return (ret_code);
// }


// int
// ndndc_destroyface(struct ndndc_data *self,
//                   int check_only,
//                   const std::string &cmd_orig)
// {
//   int ret_code = 0;
//   std::string &cmd, *cmd_token;
//   std::string &cmd_faceid = NULL;
//   struct ndn_face_instance *face;
//   struct ndn_face_instance *newface;
    
//   if (cmd_orig == NULL) {
//     ndndc_warn(__LINE__, "command error\n");
//     return -1;
//   }
    
//   cmd = strdup(cmd_orig);
//   if (cmd == NULL) {
//     ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
//     return -1;
//   }            
    
//   cmd_token = cmd;    
//   GET_NEXT_TOKEN(cmd_token, cmd_faceid);
    
//   face = parse_ndn_face_instance_from_face(self, cmd_faceid);
//   if (face == NULL) {
//     ret_code = -1;
//   }
    
//   if (ret_code == 0 && check_only == 0) {
//     newface = ndndc_do_face_action(self, "destroyface", face);
//     if (newface == NULL) {
//       ndndc_warn(__LINE__, "Cannot destroy face %d or the face does not exist\n", face->faceid);        
//     }
//     ndn_face_instance_destroy(&newface);
//   }
    
//   ndn_face_instance_destroy(&face);
//   free(cmd);
//   return ret_code;
// }


// int
// ndndc_srv(struct ndndc_data *self,
//           const unsigned std::string &domain,
//           size_t domain_size)
// {
//   std::string &proto = NULL;
//   std::string &host = NULL;
//   int port = 0;
//   char port_str[10];
//   struct ndn_charbuf *uri;
//   struct ndn_charbuf *uri_auto = NULL;
//   struct ndn_face_instance *face;
//   struct ndn_face_instance *newface;
//   struct ndn_forwarding_entry *prefix;
//   struct ndn_forwarding_entry *prefix_auto;
//   int res;
    
//   res = ndndc_query_srv(domain, domain_size, &host, &port, &proto);
//   if (res < 0) {
//     return -1;
//   }
    
//   uri = ndn_charbuf_create();
//   ndn_charbuf_append_string(uri, "ndn:/");
//   if (domain_size != 0) {
//     ndn_uri_append_percentescaped(uri, domain, domain_size);
//   }
    
//   snprintf (port_str, sizeof(port_str), "%d", port);
    
//   /* now process the results */
//   /* pflhead, lineno=0, "add" "ndn:/asdfasdf.com/" "tcp|udp", host, portstring, NULL NULL NULL */
    
//   ndndc_note(__LINE__, " >>> trying:   add %s %s %s %s <<<\n", ndn_charbuf_as_string(uri), proto, host, port_str);
    
//   face = parse_ndn_face_instance(self, proto, host, port_str, NULL, NULL,
//                                  (~0U) >> 1);
    
//   prefix = parse_ndn_forwarding_entry(self, ndn_charbuf_as_string(uri), NULL,
//                                       self->lifetime);
//   if (face == NULL || prefix == NULL) {
//     res = -1;
//     goto Cleanup;
//   }
    
//   // crazy operation
//   // First. "Create" face, which will do nothing if face already exists
//   // Second. Destroy the face
//   // Third. Create face for real
    
//   newface = ndndc_do_face_action(self, "newface", face);
//   if (newface == NULL) {
//     ndndc_warn(__LINE__, "Cannot create/lookup face");
//     res = -1;
//     goto Cleanup;
//   }
    
//   face->faceid = newface->faceid;
//   ndn_face_instance_destroy(&newface);
    
//   newface = ndndc_do_face_action(self, "destroyface", face);
//   if (newface == NULL) {
//     ndndc_warn(__LINE__, "Cannot destroy face");
//   } else {
//     ndn_face_instance_destroy(&newface);
//   }
    
//   newface = ndndc_do_face_action(self, "newface", face);
//   if (newface == NULL) {
//     ndndc_warn(__LINE__, "Cannot create/lookup face");
//     res = -1;
//     goto Cleanup;
//   }
    
//   prefix->faceid = newface->faceid;
//   ndn_face_instance_destroy(&newface);
    
//   res = ndndc_do_prefix_action(self, "prefixreg", prefix);
//   if (res < 0) {
//     ndndc_warn(__LINE__, "Cannot register prefix [%s]\n", ndn_charbuf_as_string(uri));
//   }

//   uri_auto = ndn_charbuf_create();
//   ndn_charbuf_append_string(uri_auto, "ndn:/autoconf-route");
//   prefix_auto = parse_ndn_forwarding_entry(self, ndn_charbuf_as_string(uri_auto), NULL,
//                                            self->lifetime);
//   if (prefix_auto == NULL) {
//     res = -1;
//     goto Cleanup;
//   }

//   prefix_auto->faceid = prefix->faceid;
//   res = ndndc_do_prefix_action(self, "prefixreg", prefix_auto);
//   if (res < 0) {
//     ndndc_warn(__LINE__, "Cannot register prefix_auto [%s]\n", ndn_charbuf_as_string(uri_auto));
//   }
    
//  Cleanup:
//   free(host);
//   ndn_charbuf_destroy(&uri);
//   ndn_charbuf_destroy(&uri_auto);
//   ndn_face_instance_destroy(&face);
//   ndn_forwarding_entry_destroy(&prefix);
//   ndn_forwarding_entry_destroy(&prefix_auto);
//   return res;
// }


ptr_lib::shared_ptr<ForwardingEntry>
Controller::parse_ndn_forwarding_entry(const std::string &cmd_uri,
                                       const std::string &cmd_flags,
                                       int freshness)
{
  int res = 0;

  ptr_lib::shared_ptr<ForwardingEntry> entry = ptr_lib::make_shared<ForwardingEntry>();
  
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
ptr_lib::shared_ptr<FaceInstance>
Controller::parse_ndn_face_instance(const std::string &cmd_proto,
                                    const std::string &cmd_host,     const std::string &cmd_port,
                                    const std::string &cmd_mcastttl, const std::string &cmd_mcastif,
                                    int freshness)
{
  struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG)};
  struct addrinfo mcasthints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG | AI_NUMERICHOST)};
  struct addrinfo *raddrinfo = NULL;
  struct addrinfo *mcastifaddrinfo = NULL;
  char rhostnamebuf [NI_MAXHOST];
  char rhostportbuf [NI_MAXSERV];
  int off_address = -1, off_port = -1, off_source_address = -1;
  int res;
  int socktype;

  ptr_lib::shared_ptr<FaceInstance> entry = ptr_lib::make_shared<FaceInstance>();
  
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
    throw Error("command error, getaddrinfo for host ["+cmd_host+"] port ["+cmd_port+"]: "+gai_strerror(res));
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

ptr_lib::shared_ptr<FaceInstance>
Controller::parse_ndn_face_instance_from_face(const std::string &cmd_faceid)
{
  ptr_lib::shared_ptr<FaceInstance> entry = ptr_lib::make_shared<FaceInstance>();
    
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

void
onFaceActionSuccess(func_lib::function< void (ptr_lib::shared_ptr<FaceInstance>) > onSuccess,
                    const ptr_lib::shared_ptr<Data> &data)
{
  Block content = data->getContent();
  content.parse();

  if (content.getAll().empty())
    {
      throw Controller::Error("Error while communicating to the local NDN forwarder");
    }

  Block::element_iterator val = content.getAll().begin();
  
  switch(val->type())
    {
    case Tlv::FaceManagement::FaceInstance:
      {
        ptr_lib::shared_ptr<FaceInstance> entry = ptr_lib::make_shared<FaceInstance>();
        entry->wireDecode(*val);

        onSuccess(entry);
        return;
      }
    case Tlv::FaceManagement::StatusResponse:
      {
        // failed :(
        StatusResponse resp;
        resp.wireDecode(*val);
      
        throw Controller::Error("Error while communicating to the local NDN forwarder: " + boost::lexical_cast<std::string>(resp));
        return;
      }
    default:
      {
        throw Controller::Error("Error while communicating to the local NDN forwarder");
      }
    }
}

void
onPrefixActionSuccess(func_lib::function< void (ptr_lib::shared_ptr<ForwardingEntry>) > onSuccess,
                    const ptr_lib::shared_ptr<Data> &data)
{
  Block content = data->getContent();
  content.parse();

  if (content.getAll().empty())
    {
      throw Controller::Error("Error while communicating to the local NDN forwarder");
    }

  Block::element_iterator val = content.getAll().begin();
  
  switch(val->type())
    {
    case Tlv::FaceManagement::ForwardingEntry:
      {
        ptr_lib::shared_ptr<ForwardingEntry> entry = ptr_lib::make_shared<ForwardingEntry>();
        entry->wireDecode(*val);

        onSuccess(entry);
        return;
      }
    case Tlv::FaceManagement::StatusResponse:
      {
        // failed :(
        StatusResponse resp;
        resp.wireDecode(*val);
      
        throw Controller::Error("Error while communicating to the local NDN forwarder: " + boost::lexical_cast<std::string>(resp));
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

void
Controller::startFaceAction(ptr_lib::shared_ptr<FaceInstance> entry,
                            func_lib::function< void (ptr_lib::shared_ptr<FaceInstance>) > onSuccess)
{
  std::cout << *entry << std::endl;
  
  // Set the ForwardingEntry as the content of a Data packet and sign.
  Data data;
  data.setContent(entry->wireEncode());
  
  // Create an empty signature, since nobody going to verify it for now
  // @todo In the future, we may require real signatures to do the registration
  SignatureSha256WithRsa signature;
  signature.setValue(Block(Tlv::SignatureValue, ptr_lib::make_shared<Buffer>()));
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

  m_face.expressInterest(interest,
                         func_lib::bind(onFaceActionSuccess, onSuccess, _2),
                         func_lib::bind(onActionFailure));
}

void
Controller::startPrefixAction(ptr_lib::shared_ptr<ForwardingEntry> entry,
                              func_lib::function< void (ptr_lib::shared_ptr<ForwardingEntry>) > onSuccess)
{
  // Set the ForwardingEntry as the content of a Data packet and sign.
  Data data;
  data.setContent(entry->wireEncode());
  
  // Create an empty signature, since nobody going to verify it for now
  // @todo In the future, we may require real signatures to do the registration
  SignatureSha256WithRsa signature;
  signature.setValue(Block(Tlv::SignatureValue, ptr_lib::make_shared<Buffer>()));
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

  m_face.expressInterest(interest,
                         func_lib::bind(onPrefixActionSuccess, onSuccess, _2),
                         func_lib::bind(onActionFailure));
}


} // namespace ndn
