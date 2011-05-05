/*
 * tick.c
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#include "client.h"
#include "session.h"
#include "tick.h"

uint32_t ticks;
static ev_timer tick_timer;

/**
 * Called every 0.5s.
 */
static void
tick_cb(EV_P_ ev_timer *w, int revents)
{
    void **cb;
    ticks++;
    SET_FOREACH(cb, TIMER_TICK) {
        ((timer_callback *)*cb)(EV_A);
    }
}

void
tick_sysinit(EV_P)
{
    ticks = 0;
    ev_timer_init(&tick_timer, tick_cb, TICK_PERIOD, TICK_PERIOD);
    ev_timer_start(EV_A_ &tick_timer);
}

void
tick_sysuninit(EV_P)
{
    ev_timer_stop(EV_A_ &tick_timer);
}
