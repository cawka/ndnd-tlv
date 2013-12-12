/*
 * ndn/fetch.h
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2010-2011 Palo Alto Research Center, Inc.
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

/**
 * @file ndn/fetch.h
 * Streaming access for fetching segmented NDNx data.
 *
 * Supports multiple streams from a single connection and
 * seeking to an arbitrary position within the associated file.
 */

#ifndef NDN_FETCH_DEFINED
#define NDN_FETCH_DEFINED

#include <stdio.h>
#include <ndn/ndn.h>
#include <ndn/uri.h>

/**
 * Creates a new ndn_fetch object using the given ndn connection.
 * If h == NULL, attempts to create a new connection automatically.
 * @returns NULL if the creation was not successful
 *    (only can happen for the h == NULL case).
 */
struct ndn_fetch *
ndn_fetch_new(struct ndn *h);

typedef enum {
	ndn_fetch_flags_None = 0,
	ndn_fetch_flags_NoteGlitch = 1,
	ndn_fetch_flags_NoteAddRem = 2,
	ndn_fetch_flags_NoteNeed = 4,
	ndn_fetch_flags_NoteFill = 8,
	ndn_fetch_flags_NoteFinal = 16,
	ndn_fetch_flags_NoteTimeout = 32,
	ndn_fetch_flags_NoteOpenClose = 64,
	ndn_fetch_flags_NoteAll = 0xffff
} ndn_fetch_flags;

#define NDN_FETCH_READ_ZERO (-3)
#define NDN_FETCH_READ_TIMEOUT (-2)
#define NDN_FETCH_READ_NONE (-1)
#define NDN_FETCH_READ_END (0)

/**
 * Sets the destination for debug output.  NULL disables debug output.
 */
void
ndn_fetch_set_debug(struct ndn_fetch *f, FILE *debug, ndn_fetch_flags flags);

/**
 * Destroys a ndn_fetch object.
 * Only destroys the underlying ndn connection if it was automatically created.
 * Forces all underlying streams to close immediately.
 * @returns NULL in all cases.
 */
struct ndn_fetch *
ndn_fetch_destroy(struct ndn_fetch *f);

/**
 * Polls the underlying streams and attempts to make progress.
 * Scans the streams for those that have data already present, or are at the end
 * of the stream.  If the count is 0, perfoms a ndn_poll on the underlying
 * ndn connection with a 0 timeout.
 *
 * NOTE: periodic calls to ndn_fetch_poll should be performed to update
 * the contents of the streams UNLESS the client is calling ndn_run for
 * the underlying ndn connection.
 * @returns the count of streams that have pending data or have ended.
 */
int
ndn_fetch_poll(struct ndn_fetch *f);

/**
 * Provides an iterator through the underlying streams.
 * Use fs == NULL to start the iteration, and an existing stream to continue
 * the iteration.
 * @returns the next stream in the iteration, or NULL at the end.
 * Note that providing a stale (closed) stream handle will return NULL.
 */
struct ndn_fetch_stream *
ndn_fetch_next(struct ndn_fetch *f, struct ndn_fetch_stream *fs);

/**
 * @returns the underlying ndn connection.
 */
struct ndn *
ndn_fetch_get_ndn(struct ndn_fetch *f);

/**
 * Creates a stream for a named interest.
 * The name should be a ndnb encoded interest.
 * If resolveVersion, then we assume that the version is unresolved, 
 * and an attempt is made to determine the version number using the highest
 * version.  If interestTemplate == NULL then a suitable default is used.
 * The max number of buffers (maxBufs) is a hint, and may be clamped to an
 * implementation minimum or maximum.
 * If assumeFixed, then assume that the segment size is given by the first
 * segment fetched, otherwise segments may be of variable size. 
 * @returns NULL if the stream creation failed,
 *    otherwise returns the new stream.
 */
struct ndn_fetch_stream *
ndn_fetch_open(struct ndn_fetch *f, struct ndn_charbuf *name,
			   const char *id,
			   struct ndn_charbuf *interestTemplate,
			   int maxBufs,
			   int resolveVersion,
			   int assumeFixed);

/**
 * Closes the stream and reclaims any resources used by the stream.
 * The stream object will be freed, so the client must not access it again.
 * @returns NULL in all cases.
 */
struct ndn_fetch_stream *
ndn_fetch_close(struct ndn_fetch_stream *fs);

/**
 * Tests for available bytes in the stream.
 * Determines how many bytes can be read on the given stream
 * without waiting (via ndn_fetch_poll).
 * @returns
 *    NDN_FETCH_READ_TIMEOUT if a timeout occurred,
 *    NDN_FETCH_READ_ZERO if a zero-length segment was found
 *    NDN_FETCH_READ_NONE if no bytes are immediately available
 *    NDN_FETCH_READ_END if the stream is at the end,
 *    and N > 0 if N bytes can be read without performing a poll.
 */
intmax_t
ndn_fetch_avail(struct ndn_fetch_stream *fs);

/**
 * Reads bytes from a stream.
 * Reads at most len bytes into buf from the given stream.
 * Will not wait for bytes to arrive.
 * Advances the read position on a successful read.
 * @returns
 *    NDN_FETCH_READ_TIMEOUT if a timeout occurred,
 *    NDN_FETCH_READ_ZERO if a zero-length segment was found
 *    NDN_FETCH_READ_NONE if no bytes are immediately available
 *    NDN_FETCH_READ_END if the stream is at the end,
 *    and N > 0 if N bytes were read.
 */
intmax_t
ndn_fetch_read(struct ndn_fetch_stream *fs,
			   void *buf,
			   intmax_t len);

/**
 * Resets the timeout indicator, which will cause pending interests to be
 * retried.  The client determines conditions for a timeout to be considered
 * an unrecoverable error.
 */
void
ndn_reset_timeout(struct ndn_fetch_stream *fs);

/**
 * Seeks to a position in a stream.
 * Sets the read position.
 * It is strongly recommended that the seek is only done to a position that
 * is either 0 or has resulted from a successful read.  Otherwise
 * end of stream indicators may be returned for a seek beyond the end.
 * @returns -1 if the seek is to a bad position
 * or if the segment size is variable, otherwise returns 0.
 */
int
ndn_fetch_seek(struct ndn_fetch_stream *fs,
			   intmax_t pos);

/**
 * @returns the current read position (initially 0)
 */
intmax_t
ndn_fetch_position(struct ndn_fetch_stream *fs);

#endif
