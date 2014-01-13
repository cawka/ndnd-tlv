/**
 * @file ndndc-log.h
 * @brief logging functions for ndndc.
 *
 * A NDNx program.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2012 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef NDNDC_LOG_H
#define NDNDC_LOG_H
/**
 * @brief Issue note on stderr, controlled by verbose flag
 * @param lineno Line number where problem happened
 * @param format printf-style format line
 */
void
ndndc_note(int lineno, const char *format, ...);

/**
 * @brief Issue warning on stderr
 * @param lineno Line number where problem happened
 * @param format printf-style format line
 */
void
ndndc_warn(int lineno, const char *format, ...);

/**
 * @brief Issue error message on stderr and terminate execution of the app
 * @param lineno Line number where problem happened
 * @param format printf-style format line
 */
void
ndndc_fatal(int lineno, const char *format, ...);

extern int verbose;
#endif // NDNDC_LOG_H
