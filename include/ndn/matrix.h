/**
 * @file ndn/matrix.h
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
 *
 * @brief Implements a two-dimension table containing integer values.
 * Although this interface is abstract, the implementation is (or will be)
 * tuned to the needs of ndnd.  Any value not stored will fetch as zero.
 *
 */

#ifndef NDN_MATRIX_DEFINED
#define NDN_MATRIX_DEFINED

#include <stdint.h>

struct ndn_matrix;

struct ndn_matrix_bounds {
    uint_least64_t row_min;
    uint_least64_t row_max;
    unsigned col_min;
    unsigned col_max;
};

struct ndn_matrix *ndn_matrix_create(void);
void ndn_matrix_destroy(struct ndn_matrix **);

intptr_t ndn_matrix_fetch(struct ndn_matrix *m,
                          uint_least64_t row, unsigned col);
void     ndn_matrix_store(struct ndn_matrix *m,
                          uint_least64_t row, unsigned col, intptr_t value);

/*
 * ndn_matrix_getbounds:
 * Fills result with a (not necessarily tight) bounding box for the
 * non-zero elements of m.  Returns -1 in case of error, or a non-negative
 * value for success.
 */
int ndn_matrix_getbounds(struct ndn_matrix *m, struct ndn_matrix_bounds *result);

/*
 * ndn_matrix_trim:
 * Zeros any entries outside the bounds
 */
int ndn_matrix_trim(struct ndn_matrix *m, const struct ndn_matrix_bounds *bounds);
/*
 * ndn_matrix_trim:
 * Zeros entries inside the bounds
 */
int ndn_matrix_clear(struct ndn_matrix *m, const struct ndn_matrix_bounds *bounds);

#endif
