/**
 * @file ndn/extend_dict.h
 *
 * Dictionary extension routines
 *
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

#ifndef NDN_EXTEND_DICT_DEFINED
#define NDN_EXTEND_DICT_DEFINED

#include <ndn/coding.h>

/*
 * Deallocate a dictionary freeing each of the strings and the structure itself
 */

void ndn_destroy_dict(struct ndn_dict **dp);

/*
 * Create a dictionary that is a copy of the one passed in, extended with the
 * index and name pairs loaded from the file passed in.
 */
int ndn_extend_dict(const char *dict_file, struct ndn_dict *d,
                    struct ndn_dict **rdp);

#endif
