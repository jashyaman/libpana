/*
 * paa-session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */


typedef enum {
    PAA_STATE_INVALID = -1
} paa_session_state_t;

typedef enum {
    PAA_EVENT_INVALID      = -1,
    PAA_EVENT_RTX_EXPRED   = 1,
    PAA_EVENT_SESS_EXPIRED = 0
} paa_event_t;




