/**
 * @file reg_mgmt.h
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2011 Palo Alto Research Center, Inc.
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

#ifndef NDN_REG_MGMT_DEFINED
#define NDN_REG_MGMT_DEFINED

#include <stddef.h>
#include <ndn/charbuf.h>

struct ndn_forwarding_entry {
    const char *action;
    struct ndn_charbuf *name_prefix;
    const unsigned char *ndnd_id;
    size_t ndnd_id_size;
    unsigned faceid;
    int flags;
    int lifetime;
    unsigned char store[48];
};

/** Refer to doc/technical/Registration.txt for the meaning of these flags */
#define NDN_FORW_ACTIVE         1
#define NDN_FORW_CHILD_INHERIT  2
#define NDN_FORW_ADVERTISE      4
#define NDN_FORW_LAST           8
#define NDN_FORW_CAPTURE       16
#define NDN_FORW_LOCAL         32
#define NDN_FORW_TAP           64
#define NDN_FORW_CAPTURE_OK   128
#define NDN_FORW_PUBMASK (NDN_FORW_ACTIVE        | \
                          NDN_FORW_CHILD_INHERIT | \
                          NDN_FORW_ADVERTISE     | \
                          NDN_FORW_LAST          | \
                          NDN_FORW_CAPTURE       | \
                          NDN_FORW_LOCAL         | \
                          NDN_FORW_TAP           | \
                          NDN_FORW_CAPTURE_OK    )

struct ndn_forwarding_entry *
ndn_forwarding_entry_parse(const unsigned char *p, size_t size);

void ndn_forwarding_entry_destroy(struct ndn_forwarding_entry**);

int ndnb_append_forwarding_entry(struct ndn_charbuf *,
                                 const struct ndn_forwarding_entry*);


#endif
