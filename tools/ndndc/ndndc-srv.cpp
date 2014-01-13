/**
 * @file ndndc-srv.c
 * @brief ndndc handling of SRV lookups 
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

#include "ndndc-srv.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#define BIND_8_COMPAT
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <resolv.h>

#ifndef NS_MAXMSG
#define NS_MAXMSG 65535
#endif

#ifndef NS_MAXDNAME
#ifdef MAXDNAME
#define NS_MAXDNAME MAXDNAME
#endif
#endif

#ifndef T_SRV
#define T_SRV 33
#endif

#define OP_REG  0
#define OP_UNREG 1

/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////

int
ndndc_query_srv(std::string &hostp, int &portp, std::string &proto)
{
  union {
    HEADER header;
    unsigned char buf[NS_MAXMSG];
  } ans;
  ssize_t ans_size;
  char srv_name[NS_MAXDNAME];
  int qdcount, ancount, i;
  unsigned char *msg, *msgend;
  unsigned char *end;
  int type = 0, dnsClass = 0, ttl = 0, size = 0, priority = 0, weight = 0, port = 0, minpriority;
  char host[NS_MAXDNAME];
    
  res_init();
    
  /* Step 1: construct the SRV record name, and see if there's a ndn service gateway.
   * 	       Prefer TCP service over UDP, though this might change.
   */
    
  proto = "tcp";
  snprintf(srv_name, sizeof(srv_name), "_ndnx._tcp");
  ans_size = res_search(srv_name, C_IN, T_SRV, ans.buf, sizeof(ans.buf));
    
  if (ans_size < 0) {
    proto = "udp";
    snprintf(srv_name, sizeof(srv_name), "_ndnx._udp");
    ans_size = res_search(srv_name, C_IN, T_SRV, ans.buf, sizeof(ans.buf));
    if (ans_size < 0)
      return (-1);
  }
  if (ans_size > sizeof(ans.buf))
    return (-1);
    
  /* Step 2: skip over the header and question sections */
  qdcount = ntohs(ans.header.qdcount);
  ancount = ntohs(ans.header.ancount);
  msg = ans.buf + sizeof(ans.header);
  msgend = ans.buf + ans_size;
    
  for (i = qdcount; i > 0; --i) {
    if ((size = dn_skipname(msg, msgend)) < 0)
      return (-1);
    msg = msg + size + QFIXEDSZ;
  }
  /* Step 3: process the answer section
   *  return only the most desirable entry.
   *  TODO: perhaps return a list of the decoded priority/weight/port/target
   */
    
  minpriority = INT_MAX;
  for (i = ancount; i > 0; --i) {
    size = dn_expand(ans.buf, msgend, msg, srv_name, sizeof(srv_name));
    if (size < 0) 
      return -1;
    msg = msg + size;
    GETSHORT(type, msg);
    GETSHORT(dnsClass, msg);
    GETLONG(ttl, msg);
    GETSHORT(size, msg);
    if ((end = msg + size) > msgend)
      return (-1);
        
    if (type != T_SRV) {
      msg = end;
      continue;
    }
        
    /* if the priority is numerically lower (more desirable) then remember
     * everything -- note that priority is destroyed, but we don't use it
     * when we register a prefix so it doesn't matter -- only the host
     * and port are necessary.
     */
    GETSHORT(priority, msg);
    if (priority < minpriority) {
      minpriority = priority;
      GETSHORT(weight, msg);
      GETSHORT(port, msg);
      size = dn_expand(ans.buf, msgend, msg, host, sizeof(host));
      if (size < 0)
        return (-1);
    }
    msg = end;
  }
    
  // not used for now
  (void)sizeof(weight);
  (void)sizeof(ttl);
  (void)sizeof(dnsClass);

        
  hostp = host;
  portp = port;
  return (0);
}
