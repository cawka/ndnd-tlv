/**
 * @file ndn/ndn_private.h
 *
 * Additional operations that are irrevalent for most clients.
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

#ifndef NDN_PRIVATE_DEFINED
#define NDN_PRIVATE_DEFINED

#include <sys/types.h>
#include <stdint.h>

struct ndn;
struct ndn_charbuf;
struct sockaddr_un;
struct sockaddr;
struct ndn_schedule;

/*
 * Dispatch a message as if it had arrived on the socket
 */
void ndn_dispatch_message(struct ndn *h, unsigned char *msg, size_t size);

/*
 * Do any time-based operations
 * Returns number of microseconds before next call needed
 */
int ndn_process_scheduled_operations(struct ndn *h);

/*
 * get or set the schedule in a handle.  Events on this schedule will
 * be run from the ndn_run() calls.
 */
struct ndn_schedule *ndn_get_schedule(struct ndn *h);
struct ndn_schedule *ndn_set_schedule(struct ndn *h, struct ndn_schedule *s);

/*
 * Grab buffered output
 * Caller should destroy returned buffer.
 */
struct ndn_charbuf *ndn_grab_buffered_output(struct ndn *h);

/*
 * set up client sockets for communicating with ndnd
 * In the INET case, the sockaddr passed in must be large enough to
 * hold either an IPv4 or IPv6 address.
 */
void ndn_setup_sockaddr_un(const char *, struct sockaddr_un *);
int ndn_setup_sockaddr_in(const char *, struct sockaddr *, int);

void ndn_set_connect_type(struct ndn *h, const char *name);
const char *ndn_get_connect_type(struct ndn *h);


#endif
