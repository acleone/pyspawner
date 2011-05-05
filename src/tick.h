/*
 * tick.h
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#ifndef TICK_H_
#define TICK_H_

#include <ev.h>
#include <stdint.h>
#include "linker_set.h"

#define TICK_PERIOD     0.5
#define TICKS_PER_SEC   (1.0 / TICK_PERIOD)

extern uint32_t ticks;

typedef void (timer_callback)(EV_P);
SET_DECLARE(TIMER_TICK, void);

#endif /* TICK_H_ */
