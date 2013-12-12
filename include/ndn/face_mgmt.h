/**
 * @file ndn/face_mgmt.h
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

#ifndef NDN_FACE_MGMT_DEFINED
#define NDN_FACE_MGMT_DEFINED

#include <stddef.h>
#include <ndn/charbuf.h>
#include <ndn/sockcreate.h>

#define NDN_NO_FACEID (~0U)

struct ndn_face_instance {
    const char *action;
    const unsigned char *ndnd_id;
    size_t ndnd_id_size;
    unsigned faceid;
    struct ndn_sockdescr descr;
    int lifetime;
    struct ndn_charbuf *store;
};

struct ndn_face_instance *ndn_face_instance_parse(const unsigned char *p,
                                                  size_t size);

void ndn_face_instance_destroy(struct ndn_face_instance**);

int ndnb_append_face_instance(struct ndn_charbuf *,
                              const struct ndn_face_instance *);

#endif
