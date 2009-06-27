/*
 * session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */


typedef enum {
    PAC_STATE_INVALID = -1;
    PAC_STATE_INIT    = 0;
} pac_session_state_t;

typedef enum {
    PAC_EVENT_INVALID      = -1;
    PAC_EVENT_RTX_EXPRED   = 1
    PAC_EVENT_SESS_EXPIRED = 0;
} pac_event_t;




void update_pac_session (pac_session_t * sess_handle, pac_event_t event, void * pinfo)
{

}


int pac_packet_handler(const pana_packet_t const * pkt) {
    
}


