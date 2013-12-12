/**
 * @file ndn_interest.c
 * Accessors and mutators for parsed Interest messages
 */

/*
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2010 Palo Alto Research Center, Inc.
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

#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>

/**
 * @returns the lifetime of the interest in units of 2**(-12) seconds
 * (the same units as timestamps).
 */
intmax_t
ndn_interest_lifetime(const unsigned char *msg,
                      const struct ndn_parsed_interest *pi)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = NULL;
    unsigned start = pi->offset[NDN_PI_B_InterestLifetime];
    size_t size    = pi->offset[NDN_PI_E_InterestLifetime] - start;
    uintmax_t val;
    if (size == 0)
        return(NDN_INTEREST_LIFETIME_SEC << 12);
    d = ndn_buf_decoder_start(&decoder, msg + start, size);
    val = ndn_parse_optional_tagged_binary_number(d, NDN_DTAG_InterestLifetime,
			1, 7, NDN_INTEREST_LIFETIME_SEC << 12);
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(val);
}

/**
 * @returns the lifetime of the interest in units of seconds;
 *          any fractional part is truncated.
 * Not useful for short-lived interests.
 */
int
ndn_interest_lifetime_seconds(const unsigned char *msg,
                              const struct ndn_parsed_interest *pi)
{
    intmax_t val = ndn_interest_lifetime(msg, pi);
    if (val < 0)
        return(val);
    return(val >> 12);
}
