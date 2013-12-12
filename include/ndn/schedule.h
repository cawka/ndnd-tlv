/**
 * @file ndn/schedule.h
 * 
 * Event scheduling.
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

#ifndef NDN_SCHEDULE_DEFINED
#define NDN_SCHEDULE_DEFINED

#include <stdint.h>

struct ndn_schedule;
struct ndn_scheduled_event;

/*
 * This is a two-part absolute time value, which might be seconds and 
 * microseconds but does not have to be.  The interpretation depends
 * on the client-provided gettime object.  The distance into the future
 * for which events may be scheduled will be limited by the number of
 * micros that will fit in an int.
 */
struct ndn_timeval {
    long s;
    unsigned micros;
};

struct ndn_gettime;
typedef void (*ndn_gettime_action)(const struct ndn_gettime *, struct ndn_timeval *);
struct ndn_gettime {
    char descr[8];
    ndn_gettime_action gettime;
    unsigned micros_per_base;  /* e.g., 1000000 for seconds, microseconds */
    void *data;                /* for private use by gettime */
};

/*
 * The scheduled action may return a non-positive value
 * if the event should not be scheduled to occur again,
 * or a positive number of micros. If (flags & NDN_SCHEDULE_CANCEL),
 * the action should clean up and not reschedule itself.
 * The clienth is the one passed to ndn_schedule_create; event-specific
 * client data may be stored in ev->evdata and ev->evint.
 */
#define NDN_SCHEDULE_CANCEL 0x10
typedef int (*ndn_scheduled_action)(
    struct ndn_schedule *sched,
    void *clienth,
    struct ndn_scheduled_event *ev,
    int flags);

struct ndn_scheduled_event {
    ndn_scheduled_action action;
    void *evdata;
    intptr_t evint;
};

/*
 * Create and destroy
 */
struct ndn_schedule *ndn_schedule_create(void *clienth,
                                         const struct ndn_gettime *ndnclock);
void ndn_schedule_destroy(struct ndn_schedule **schedp);

/*
 * Accessor for the clock passed into create
 */
const struct ndn_gettime *ndn_schedule_get_gettime(struct ndn_schedule *);

/*
 * ndn_schedule_event: schedule a new event
 */
struct ndn_scheduled_event *ndn_schedule_event(
    struct ndn_schedule *sched,
    int micros,
    ndn_scheduled_action action,
    void *evdata,
    intptr_t evint);

/*
 * ndn_schedule_cancel: cancel a scheduled event
 * Cancels the event (calling action with NDN_SCHEDULE_CANCEL set)
 * Returns -1 if this is not possible.
 */
int ndn_schedule_cancel(struct ndn_schedule *, struct ndn_scheduled_event *);

/*
 * ndn_schedule_run: do any scheduled events
 * This executes any scheduled actions whose time has come.
 * The return value is the number of micros until the next
 * scheduled event, or -1 if there are none.
 */
int ndn_schedule_run(struct ndn_schedule *);

#endif
