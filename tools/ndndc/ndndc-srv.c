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

#include "ndndc.h"
#include "ndndc-srv.h"
#include "ndndc-log.h"

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

#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/uri.h>
#include <ndn/reg_mgmt.h>

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
// forward declaration for "private" methods
/////////////////////////////////////////////////////////////

enum ndn_upcall_res
incoming_interest(struct ndn_closure *selfp,
                  enum ndn_upcall_kind kind,
                  struct ndn_upcall_info *info);

/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////

void
ndndc_daemonize(struct ndndc_data *ndndc)
{
    struct ndn_closure interest_closure = { .p=&incoming_interest, .data = (void *)ndndc };
    struct ndn_charbuf *temp = ndn_charbuf_create();
    
    /* Set up a handler for interests */
    ndn_name_from_uri(temp, "ndn:/");
    ndn_set_interest_filter_with_flags(ndndc->ndn_handle, temp, &interest_closure,
                                       NDN_FORW_ACTIVE | NDN_FORW_CHILD_INHERIT | NDN_FORW_LAST);
    ndn_charbuf_destroy(&temp);
    
    ndndc_note(__LINE__, "Starting dynamic DNS-based FIB prefix resolution\n");
    ndn_run(ndndc->ndn_handle, -1);
}

int
ndndc_query_srv(const unsigned char *domain, int domain_size,
                char **hostp, int *portp, char **proto)
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
    int type = 0, class = 0, ttl = 0, size = 0, priority = 0, weight = 0, port = 0, minpriority;
    char host[NS_MAXDNAME];
    
    res_init();
    
    /* Step 1: construct the SRV record name, and see if there's a ndn service gateway.
     * 	       Prefer TCP service over UDP, though this might change.
     */
    
    *proto = "tcp";
    if (domain_size != 0) {
        snprintf(srv_name, sizeof(srv_name), "_ndnx._tcp.%.*s", domain_size, domain);
        ans_size = res_query(srv_name, C_IN, T_SRV, ans.buf, sizeof(ans.buf));
    } else {
        snprintf(srv_name, sizeof(srv_name), "_ndnx._tcp");
        ans_size = res_search(srv_name, C_IN, T_SRV, ans.buf, sizeof(ans.buf));
    }
    
    if (ans_size < 0) {
        *proto = "udp";
        if (domain_size != 0) {
            snprintf(srv_name, sizeof(srv_name), "_ndnx._udp.%.*s", domain_size, domain);
            ans_size = res_query(srv_name, C_IN, T_SRV, ans.buf, sizeof(ans.buf));
        } else {
            snprintf(srv_name, sizeof(srv_name), "_ndnx._udp");
            ans_size = res_search(srv_name, C_IN, T_SRV, ans.buf, sizeof(ans.buf));
        }
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
            return (NDN_UPCALL_RESULT_ERR);
        msg = msg + size;
        GETSHORT(type, msg);
        GETSHORT(class, msg);
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
	(void)sizeof(class);
    
    if (hostp) {
        *hostp = strdup(host);
        if (!*hostp)
            return (-1);
    }
    if (portp) {
        *portp = port;
    }
    return (0);
}

enum ndn_upcall_res
incoming_interest(struct ndn_closure *selfp,
                  enum ndn_upcall_kind kind,
                  struct ndn_upcall_info *info)
{
    const unsigned char *ndnb = info->interest_ndnb;
    struct ndn_indexbuf *comps = info->interest_comps;
    const unsigned char *comp0 = NULL;
    size_t comp0_size = 0;
    int res;
    struct ndndc_data *ndndc = (struct ndndc_data *)selfp->data;
    
    if (kind == NDN_UPCALL_FINAL)
        return (NDN_UPCALL_RESULT_OK);
    if (kind != NDN_UPCALL_INTEREST)
        return (NDN_UPCALL_RESULT_ERR);
    if (comps->n < 1)
        return (NDN_UPCALL_RESULT_OK);
    
    
    res = ndn_ref_tagged_BLOB(NDN_DTAG_Component, ndnb, comps->buf[0], comps->buf[1],
                              &comp0, &comp0_size);
    if (res < 0 || comp0_size > (NS_MAXDNAME - 12))
        return (NDN_UPCALL_RESULT_OK);
    if (memchr(comp0, '.', comp0_size) == NULL)
        return (NDN_UPCALL_RESULT_OK);
    
    res = ndndc_srv(ndndc, comp0, comp0_size);
    
    if (res < 0)
        return (NDN_UPCALL_RESULT_ERR);
    
    return (NDN_UPCALL_RESULT_OK);
}
