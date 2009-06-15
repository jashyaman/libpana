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
    PAC_EVENT_INVALID = -1;
    PAC_EVENT_SESS_EXPIRED = 0;
} pac_event_t;

typedef struct pana_sesion_s {
    uint32_t session_id;
    pac_session_state_t cstate;
    uint32_t seq_rx;
    uint32_t seq_tx;
} pac_session_t;

typedef int (*pac_action_t)(pac_session_t * sh, void * pinfo)

typedef struct pac_fsm_tbl_entry_s {
    pac_session_state_t cstate;
    pac_event_t         event;
    pac_session_state_t nstate;
    pac_action_t        action;
} pac_fsm_tbl_entry_t;

static pac_fsm_tbl_entry_t pac_fsm_tbl[] = {
    {PAC_STATE_INVALID, PAC_EVENT_INVALID, PAC_STATE_INVALID, NULL},
    {}
};

static size_t pac_fsm_size = sizeof(pac_fsm_tbl) / sizeof(pac_fsm_tbl[0]);

static int
find_pac_fsm_state (pac_session_state_t cstate, pac_event_t event)
{
    unsigned int ix = 0;

    while (ix++ < pac_fsm_size) {
        if (pac_fsm_tbl[ix].cstate == cstate &&
            pac_fsm_tbl[ix].event == event) {
            return ix;
        }
    }

    return -1;
}

pac_session_t * create_pana_session (uint32_t session_id)
{
    pac_session_t * out = malloc(sizeof(pac_session_t));
    if (out != NULL) {
        out->session_id = session_id;
        out->cstate = PAC_STATE_INVALID;
    }

    return out;
}

void destroy_pac_session(pac_session_t * sess) {
    free(sess);
}

int update_pac_session (pac_session_t * sess_handle, pac_event_t event, void * pinfo)
{
    int ix = find_pac_fsm_state(sess_handle->cstate, event);

    /*
     * This is an invalid event for this current state so it should be neglected
     */
    if (ix < 0) {
        return -1
    }

    sess_handle->cstate = pac_fsm_tbl[ix].nstate;

    /*
     * TODO: Here we need callback functions
     *       pinfo contains the various info needed for the action
     */
    pac_fsm_tbl[ix].action(sess_handle, pinfo);

    return 0;
}


