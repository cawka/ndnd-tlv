/**
 * @file ndn/uri.h
 * 
 * ndn-scheme uri conversions.
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008, 2009, 2010, 2013 Palo Alto Research Center, Inc.
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

#ifndef NDN_URI_DEFINED
#define NDN_URI_DEFINED

#include <ndn/charbuf.h>

/* Conversion from ndnb name component to percent-escaped uri component */
void
ndn_uri_append_percentescaped(struct ndn_charbuf *c,
                              const unsigned char *data, size_t size);

/* Conversion from ndnb name component to mixed percent/equals escaped uri component */
void
ndn_uri_append_mixedescaped(struct ndn_charbuf *c,
                              const unsigned char *data, size_t size);

/* Conversion from ndnb to uri */
#define NDN_URI_INCLUDESCHEME   1
#define NDN_URI_MIXEDESCAPE    2
#define NDN_URI_PERCENTESCAPE  4

#define NDN_URI_ESCAPE_MASK    (NDN_URI_MIXEDESCAPE|NDN_URI_PERCENTESCAPE)
#ifndef NDN_URI_DEFAULT_ESCAPE
#define NDN_URI_DEFAULT_ESCAPE NDN_URI_PERCENTESCAPE
#endif

int
ndn_uri_append(struct ndn_charbuf *c,
               const unsigned char *ndnb,
               size_t size,
               int flags);


/* Conversion from uri to ndnb form */
int ndn_name_from_uri(struct ndn_charbuf *c, const char *uri);

#endif
