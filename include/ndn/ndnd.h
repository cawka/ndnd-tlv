/**
 * @file ndn/ndnd.h
 * 
 * Definitions pertaining to the NDNx daemon.
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

#ifndef NDN_NDND_DEFINED
#define NDN_NDND_DEFINED

#define NDN_DEFAULT_LOCAL_SOCKNAME "/tmp/.ndnd.sock"
#define NDN_LOCAL_PORT_ENVNAME "NDN_LOCAL_PORT"

/**
 * ndnx registered port number
 * see http://www.iana.org/assignments/port-numbers
 */
#define NDN_DEFAULT_UNICAST_PORT_NUMBER 6363U
#define NDN_DEFAULT_UNICAST_PORT       "6363"

/**
 * Link adapters sign on by sending this greeting to ndnd.
 * Not for use over the wire.
 */
#define NDN_EMPTY_PDU "NDN\202\000"
#define NDN_EMPTY_PDU_LENGTH 5
#endif
