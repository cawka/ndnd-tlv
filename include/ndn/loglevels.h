/**
 * @file ndn/loglevels.h
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011, 2012 Palo Alto Research Center, Inc.
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
  
#ifndef NDNL_NONE

/**
 * Levels for deciding whether or not to log.
 */
#define NDNL_NONE       0   /**< No logging at all */
#define NDNL_SEVERE     3   /**< Severe errors */
#define NDNL_ERROR      5   /**< Configuration errors */
#define NDNL_WARNING    7   /**< Something might be wrong */
#define NDNL_INFO       9   /**< Low-volume informational */
#define NDNL_FINE      11   /**< Debugging */
#define NDNL_FINER     13   /**< More debugging */
#define NDNL_FINEST    15   /**< MORE DEBUGGING YET */

#endif
