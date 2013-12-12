/**
 * @file ndn/charbuf.h
 * 
 * Expandable character buffer for counted sequences of arbitrary octets.
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008, 2009 Palo Alto Research Center, Inc.
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

#ifndef NDN_CHARBUF_DEFINED
#define NDN_CHARBUF_DEFINED

#include <stddef.h>
#include <time.h>

struct ndn_charbuf {
    size_t length;
    size_t limit;
    unsigned char *buf;
};

/*
 * ndn_charbuf_create:  allocate a new charbuf
 * ndn_charbuf_create_n: allocate a new charbuf with a preallocated but
 *      uninitialized buffer
 * ndn_charbuf_destroy: destroy a charbuf
 */
struct ndn_charbuf *ndn_charbuf_create(void);
struct ndn_charbuf *ndn_charbuf_create_n(size_t n);
void ndn_charbuf_destroy(struct ndn_charbuf **cbp);

/*
 * ndn_charbuf_reserve: reserve some space in the buffer
 * Grows c->buf if needed and returns a pointer to the new region.
 * Does not modify c->length
 */ 
unsigned char *ndn_charbuf_reserve(struct ndn_charbuf *c, size_t n);

/*
 * ndn_charbuf_reset: reset to empty for reuse
 * Sets c->length to 0
 */
void ndn_charbuf_reset(struct ndn_charbuf *c);

/*
 * ndn_charbuf_append: append character content
 */ 
int ndn_charbuf_append(struct ndn_charbuf *c, const void *p, size_t n);

/*
 * ndn_charbuf_append: append n bytes of val
 * The n low-order bytes are appended in network byte order (big-endian) 
 */ 
int ndn_charbuf_append_value(struct ndn_charbuf *c, unsigned val, unsigned n);


/*
 * ndn_charbuf_append_charbuf: append content from another charbuf
 */ 
int ndn_charbuf_append_charbuf(struct ndn_charbuf *c, const struct ndn_charbuf *i);

/*
 * ndn_charbuf_append: append a string
 * Sometimes you have a null-terminated string in hand...
 */ 
int ndn_charbuf_append_string(struct ndn_charbuf *c, const char *s);

/*
 * ndn_charbuf_putf: formatting output
 * Use this in preference to snprintf to simplify bookkeeping.
 */ 
int ndn_charbuf_putf(struct ndn_charbuf *c, const char *fmt, ...);

/*
 * ndn_charbuf_append_datetime: append a date/time string
 * Appends a dateTime string in canonical form according to
 * http://www.w3.org/TR/xmlschema-2/
 * Return value is 0, or -1 for error.
 * example: 2008-07-22T17:33:14.109Z
 */ 

#define NDN_DATETIME_PRECISION_USEC 6
#define NDN_DATETIME_PRECISION_MAX 6

int ndn_charbuf_append_datetime(struct ndn_charbuf *c, time_t secs, int nsecs);

/*
 * ndn_charbuf_as_string: view charbuf contents as a string
 * This assures that c->buf has a null termination, and simply
 * returns the pointer into the buffer.  If the result needs to
 * persist beyond the next operation on c, the caller is
 * responsible for copying it.
 */ 
char *ndn_charbuf_as_string(struct ndn_charbuf *c);

#endif
