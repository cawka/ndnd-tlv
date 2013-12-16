/**
 * @file ndn_schedule.c
 * @brief Support for scheduling events.
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2012 Palo Alto Research Center, Inc.
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
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ndn/schedule.h>

/**
 * Use this unsigned type to keep track of time in the heap.
 *
 * 32 bits can work, but 64 bits are preferable.
 */
typedef uintptr_t heapmicros;
static const heapmicros epochmax = ((heapmicros)(~0))/2;

/**
 * We use a heap structure (as in heapsort) to
 * keep track of the scheduled events to get O(log n)
 * behavior.
 */
struct ndn_schedule_heap_item {
    heapmicros event_time;
    struct ndn_scheduled_event *ev;
};

struct ndn_schedule {
    void *clienth;
    const struct ndn_gettime *clock;
    struct ndn_schedule_heap_item *heap;
    int heap_n;
    int heap_limit;
    int heap_height;    /* this is validated just before use */
    heapmicros now;     /* internal micros corresponding to lasttime  */
    struct ndn_timeval lasttime; /* actual time when we last checked  */
    int time_leap;      /* number of times clock took a large jump */
    int time_ran_backward; /* number of times clock ran backwards */
};

/*
 * update_epoch: reset sched->now to avoid wrapping
 */
static void
update_epoch(struct ndn_schedule *sched)
{
    struct ndn_schedule_heap_item *heap;
    int n;
    int i;
    heapmicros t = sched->now;
    heap = sched->heap;
    n = sched->heap_n;
    for (i = 0; i < n; i++)
        heap[i].event_time -= t;
    sched->now = 0;
}

static void
update_time(struct ndn_schedule *sched)
{
    struct ndn_timeval now = { 0 };
    int elapsed;
    if (sched->clock->gettime == 0)
        return; /* For testing with clock stopped */
    sched->clock->gettime(sched->clock, &now);
    if ((unsigned)now.s - (unsigned)sched->lasttime.s >= INT_MAX/4000000) {
        /* We have taken a backward or large step - do a repair */
        sched->time_leap++;
        sched->lasttime = now;
    }
    elapsed = now.micros - sched->lasttime.micros +
        sched->clock->micros_per_base * (now.s - sched->lasttime.s);
    if (elapsed < 0) {
        elapsed = 0;
        sched->time_ran_backward++;
    }
    else if (elapsed >= epochmax - sched->now)
        update_epoch(sched);
    sched->now += elapsed;
    sched->lasttime = now;
}

struct ndn_schedule *
ndn_schedule_create(void *clienth, const struct ndn_gettime *ndnclock)
{
    struct ndn_schedule *sched;
    if (ndnclock == NULL)
        return(NULL);
    sched = calloc(1, sizeof(*sched));
    if (sched != NULL) {
        sched->clienth = clienth;
        sched->clock = ndnclock;
        update_time(sched);
        sched->time_leap = 0;
    }
    return(sched);
}

void
ndn_schedule_destroy(struct ndn_schedule **schedp)
{
    struct ndn_schedule *sched;
    struct ndn_scheduled_event *ev;
    struct ndn_schedule_heap_item *heap;
    int n;
    int i;
    sched = *schedp;
    if (sched == NULL)
        return;
    *schedp = NULL;
    heap = sched->heap;
    if (heap != NULL) {
        n = sched->heap_n;
        sched->heap = NULL;
        for (i = 0; i < n; i++) {
            ev = heap[i].ev;
            (ev->action)(sched, sched->clienth, ev, NDN_SCHEDULE_CANCEL);
            free(ev);
        }
        free(heap);
    }
    free(sched);
}

const struct ndn_gettime *
ndn_schedule_get_gettime(struct ndn_schedule *schedp) {
    return(schedp->clock);
}

/*
 * heap_insert: insert a new item
 * n is the total heap size, counting the new item
 * h must satisfy (n >> h) == 1
 */
static void
heap_insert(struct ndn_schedule_heap_item *heap, heapmicros micros,
            struct ndn_scheduled_event *ev, int h, int n)
{
    int i;
    for (i = (n >> h); i < n; i = (n >> --h)) {
        if (micros <= heap[i-1].event_time) {
            heapmicros d = heap[i-1].event_time;
            struct ndn_scheduled_event *e = heap[i-1].ev;
            heap[i-1].ev = ev;
            heap[i-1].event_time = micros;
            micros = d;
            ev = e;
        }
    }
    heap[n-1].event_time = micros;
    heap[n-1].ev = ev;
}

/*
 * heap_sift: remove topmost element
 * n is the total heap size, before removal
 */
static void
heap_sift(struct ndn_schedule_heap_item *heap, int n)
{
    int i, j;
    heapmicros micros;
    if (n < 1)
        return;
    micros = heap[n-1].event_time;
    for (i = 1, j = 2; j < n; i = j, j = 2 * j) {
        if (j + 1 < n && heap[j-1].event_time > heap[j].event_time)
            j += 1;
        if (micros < heap[j-1].event_time)
            break;
        heap[i-1] = heap[j-1];
    }
    heap[i-1] = heap[n-1];
    heap[n-1].ev = NULL;
    heap[n-1].event_time = 0;
}

/*
 * reschedule_event: schedule an event
 * ev is already set up and initialized
 */
static struct ndn_scheduled_event *
reschedule_event(
    struct ndn_schedule *sched,
    int micros,
    struct ndn_scheduled_event *ev)
{
    int lim;
    int n;
    int h;
    struct ndn_schedule_heap_item *heap;
    if (micros >= epochmax - sched->now)
        update_epoch(sched);
    heap = sched->heap;
    n = sched->heap_n + 1;
    if (n > sched->heap_limit) {
        lim = sched->heap_limit + n;
        heap = realloc(sched->heap, lim * sizeof(heap[0]));
        if (heap == NULL) return(NULL);
        memset(&(heap[sched->heap_limit]), 0, (lim - n) * sizeof(heap[0]));
        sched->heap_limit = lim;
        sched->heap = heap;
    }
    sched->heap_n = n;
    h = sched->heap_height;
    while ((n >> h) > 1)
        sched->heap_height = ++h;
    while ((n >> h) < 1)
        sched->heap_height = --h;
    heap_insert(heap, sched->now + micros, ev, h, n);
    return(ev);
}

/*
 * ndn_schedule_event: schedule a new event
 */
struct ndn_scheduled_event *
ndn_schedule_event(
    struct ndn_schedule *sched,
    int micros,
    ndn_scheduled_action action,
    void *evdata,
    intptr_t evint)
{
    struct ndn_scheduled_event *ev;
    if (micros < 0)
        return(NULL);
    ev = calloc(1, sizeof(*ev));
    if (ev == NULL) return(NULL);
    ev->action = action;
    ev->evdata = evdata;
    ev->evint = evint;
    update_time(sched);
    return(reschedule_event(sched, micros, ev));
}

/* Use a dummy action in cancelled events */ 
static int
ndn_schedule_cancelled_event(struct ndn_schedule *sched, void *clienth,
                             struct ndn_scheduled_event *ev, int flags)
{
    return(0);
}

/**
 * Cancel a scheduled event.
 *
 * Cancels the event (calling action with NDN_SCHEDULE_CANCEL set)
 * @returns 0 if OK, or -1 if this is not possible.
 */
int
ndn_schedule_cancel(struct ndn_schedule *sched, struct ndn_scheduled_event *ev)
{
    int res;
    if (ev == NULL)
        return(-1);
    res = (ev->action)(sched, sched->clienth, ev, NDN_SCHEDULE_CANCEL);
    if (res > 0)
        abort(); /* Bug in ev->action - bad return value */
    ev->action = &ndn_schedule_cancelled_event;
    ev->evdata = NULL;
    ev->evint = 0;
    return(0);
}

static void
ndn_schedule_run_next(struct ndn_schedule *sched)
{
    struct ndn_scheduled_event *ev;
    heapmicros late;
    int res;
    if (sched->heap_n == 0) return;
    ev = sched->heap[0].ev;
    sched->heap[0].ev = NULL;
    late = sched->now - sched->heap[0].event_time;
    heap_sift(sched->heap, sched->heap_n--);
    res = (ev->action)(sched, sched->clienth, ev, 0);
    if (res <= 0) {
        free(ev);
        return;
    }
    /*
     * Try to reschedule based on the time the
     * event was originally scheduled, but if we have gotten
     * way behind, just use the current time.
     */
    if (late > res)
        res = 1;
    else if (late <= sched->clock->micros_per_base)
        res -= late;
    reschedule_event(sched, res, ev);
}

/*
 * ndn_schedule_run: do any scheduled events
 * This executes any scheduled actions whose time has come.
 * The return value is the number of micros until the next
 * scheduled event, or -1 if there are none.
 */
int
ndn_schedule_run(struct ndn_schedule *sched)
{
    heapmicros ans;
    do {
        while (sched->heap_n > 0 && sched->heap[0].event_time <= sched->now)
            ndn_schedule_run_next(sched);
        update_time(sched);
    } while (sched->heap_n > 0 && sched->heap[0].event_time <= sched->now);
    if (sched->heap_n == 0)
        return(-1);
    ans = sched->heap[0].event_time - sched->now;
    if (ans < INT_MAX)
        return(ans);
    return(INT_MAX);
}

#ifdef TESTSCHEDULE
// cc -g -o testschedule -DTESTSCHEDULE=main -I../include ndn_schedule.c
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

static void
my_gettime(const struct ndn_gettime *self, struct ndn_timeval *result)
{
    struct timeval now = {0};
    gettimeofday(&now, 0);
    result->s = now.tv_sec;
    result->micros = now.tv_usec;
}

static struct ndn_gettime gt = {"getTOD", &my_gettime, 1000000, NULL};

static void
testtick(struct ndn_schedule *sched)
{
    sched->now = sched->heap[0].event_time + 1;
    printf("%ld: ", (long)sched->heap[0].event_time);
    ndn_schedule_run_next(sched);
    printf("\n");
}
static char dd[] = "ABDEFGHI";
#define SARGS struct ndn_schedule *sched, void *clienth, struct ndn_scheduled_event *ev, int flags
static int A(SARGS) { if (flags & NDN_SCHEDULE_CANCEL) return(0);
                      printf("A"); return 70000000; }
static int B(SARGS) { printf("B"); return 0; }
static int C(SARGS) { printf("C"); return 0; }
static int D(SARGS) { if (flags & NDN_SCHEDULE_CANCEL) return(0);
                      printf("D");  return 30000000; }
int TESTSCHEDULE(int argc, char **argv)
{
    struct ndn_schedule *s = ndn_schedule_create(dd+5, &gt);
    int i;
    struct ndn_scheduled_event *victim = NULL;
    int realtime = 0;
    if (argv[0] != NULL)
        realtime = 1;
    if (!realtime)
        gt.gettime = 0;
    ndn_schedule_event(s, 11111, A, dd+4, 11111);
    ndn_schedule_event(s, 1, A, dd, 1);
    ndn_schedule_event(s, 111, C, dd+2, 111);
    victim = ndn_schedule_event(s, 1111111, A, dd+6, 1111111);
    ndn_schedule_event(s, 11, B, dd+1, 11);
    testtick(s);
    ndn_schedule_event(s, 1111, D, dd+3, 1111);
    ndn_schedule_event(s, 111111, B, dd+5, 111111);
    if (realtime) {
        for (;;) {
            i = ndn_schedule_run(s);
            if (i < 0)
                break;
            printf("    %d usec until %ld\n", i, (long)s->heap[0].event_time);
            usleep(i); /* not posix, but this is not compiled by default */
        }
    }
    else {
        for (i = 0; i < 100; i++) {
            if (i == 50) { ndn_schedule_cancel(s, victim); victim = NULL; }
            testtick(s);
        }
    }
    printf("\n");
    ndn_schedule_destroy(&s);
    return(0);
}
#endif
