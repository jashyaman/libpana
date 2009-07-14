/*
 * session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */

#include <sys/select.h>
#include <fcntl.h>
#include <stdarg.h>

#include "utils/includes.h"
#include "utils/util.h"
#include "utils/bytebuff.h"

#include "libpana.h"
#include "pana_common/packet.h"
#include "pac-session.h"


/* pac context data */
typedef struct pac_ctx {
    
    int sockfd;
    
    rtimer_t rtx_timer;
    rtimer_t reauth_timer;
    rtimer_t session_timer;
    uint16_t stats_flags;
#define SF_CELARED    0
#define SF_NONCE_SENT (1 << 0)
    
    const pac_config_t * pacglobal;   //we want this to be readonly
    
    /* EAP interface */
    eap_peer_config_t * eap_config;
    eap_method_ret_t * eap_ret;
    bytebuff_t * eap_resp_payload;  //store the pending EAP response
    rtimer_t eap_resptimer;
    
    
    /* Events */
    uint32_t event_occured;
#define EV_CLEAR                0
#define EV_PKT_RECVD                   (1 << 0)
#define EV_AUTH_USER            (1 << 1)
#define EV_EAP_RESPONSE         (1 << 2)
#define EV_EAP_DISCARD          (1 << 3)
#define EV_EAP_RESP_TIMEOUT     (1 << 4)
#define EV_EAP_FAILURE          (1 << 5)
#define EV_EAP_SUCCESS          (1 << 6)
#define EV_PANA_PING            (1 << 7)
#define EV_REAUTH               (1 << 8)
#define EV_TERMINATE            (1 << 9)

} pac_ctx_t;

/*
 * WARNING!!! BEFORE USE MUST DECLARE A VARIABLE: 
 *      pac_ctx_t * ctx = (pac_ctx_t *)target_session->ctx;
 */
//  use this regexp on defines:
//  ^#define\s+EV_(\w+)\s+.*$
//  #define $1\t(ctx->event_occured & EV_$1)
//  #define $1_Set()\t(ctx->event_occured |= EV_$1)
//  #define $1_Unset()\t(ctx->event_occured &= ~EV_$1)


#define clear_events()   (ctx->event_occured = EV_CLEAR)

#define PKT_RECVD	        (ctx->event_occured & EV_PKT_RECVD)
#define PKT_RECVD_Set()	        (ctx->event_occured |= EV_PKT_RECVD)
#define AUTH_USER	(ctx->event_occured & EV_AUTH_USER)
#define AUTH_USER_Set()	(ctx->event_occured |= EV_AUTH_USER)
#define EAP_RESPONSE	(ctx->event_occured & EV_EAP_RESPONSE)
#define EAP_RESPONSE_Set()	(ctx->event_occured |= EV_EAP_RESPONSE)
#define EAP_DISCARD	(ctx->event_occured & EV_EAP_DISCARD)
#define EAP_DISCARD_Set()	(ctx->event_occured |= EV_EAP_DISCARD)
#define EAP_RESP_TIMEOUT	(ctx->event_occured & EV_EAP_RESP_TIMEOUT)
#define EAP_RESP_TIMEOUT_Set()	(ctx->event_occured |= EV_EAP_RESP_TIMEOUT)
#define EAP_FAILURE	(ctx->event_occured & EV_EAP_FAILURE)
#define EAP_FAILURE_Set()	(ctx->event_occured |= EV_EAP_FAILURE)
#define EAP_SUCCESS	(ctx->event_occured & EV_EAP_SUCCESS)
#define EAP_SUCCESS_Set()	(ctx->event_occured |= EV_EAP_SUCCESS)
#define PANA_PING	(ctx->event_occured & EV_PANA_PING)
#define PANA_PING_Set()	(ctx->event_occured |= EV_PANA_PING)
#define REAUTH	         (ctx->event_occured & EV_REAUTH)
#define REAUTH_Set()	(ctx->event_occured |= EV_REAUTH)
#define TERMINATE	(ctx->event_occured & EV_TERMINATE)
#define TERMINATE_Set()	(ctx->event_occured |= EV_TERMINATE)


#define NONCE_SENT         (ctx->stats_flags & SF_NONCE_SENT)
#define NONCE_SENT_Set()   (ctx->stats_flags |= SF_NONCE_SENT)
#define NONCE_SENT_Unset() (ctx->stats_flags &= ~SF_NONCE_SENT)



static pana_session_t * pacs;
static pac_config_t * cfg;

typedef enum {
    /* PANA_PHASE_UNITIALISED */
    PAC_STATE_INITIAL,
    
    /* PANA_PHASE_AUTH & PANA_PHASE_REAUTH */
    PAC_STATE_AUTH_PAR_SBIT,
    PAC_STATE_WAIT_PAA,
    PAC_STATE_WAIT_EAP_MSG,
    PAC_STATE_WAIT_EAP_RESULT,
    PAC_STATE_WAIT_EAP_RESULT_CLOSE,
    
    /* PANA_PHASE_ACCESS */
    PAC_STATE_WAIT_PNA_PING,
    PAC_STATE_WAIT_PNA_REAUTH,
    PAC_STATE_OPEN,
    
    
    /* PANA_PHASE_TERMINATE */
    PAC_STATE_SESS_TERM,
    PAC_STATE_CLOSED
} pac_session_state_t;

static void RtxTimerStop() {
    ((pac_ctx_t *)(pacs->ctx))->rtx_timer.enabled = FALSE;
}

/*
 * Register a packet in the retransmit cache.
 */
static void RtxTimerStart(bytebuff_t * respdata) {
    pac_ctx_t * ctx = pacs->ctx;
    if (pacs->pkt_cache != NULL) {
        free_bytebuff(pacs->pkt_cache);
    }
    pacs->pkt_cache = bytebuff_dup(respdata);
    ctx->rtx_timer.deadline = time(NULL) + cfg->rtx_interval;
    ctx->rtx_timer.count = 0;
    ctx->rtx_timer.enabled = TRUE;
}






static void Retransmit() {
    int res;
    pac_ctx_t * ctx = pacs->ctx;

    ctx->rtx_timer.count++;
    if (pacs->pkt_cache != NULL) {
        dbg_asciihexdump(PKT_RTX,"PAcket rtx contents",
                bytebuff_data(pacs->pkt_cache),
                pacs->pkt_cache->used);
        res = send(ctx->sockfd, bytebuff_data(pacs->pkt_cache),
                pacs->pkt_cache->used, 0);
        if (res < 0 || res != pacs->pkt_cache->used) {
            DEBUG("There was a problem when sending the cached pkt");
            dbg_printf(UNEXPECTED_SED_RES,
                    "res was: %d and [errno=%d] : %s",
                    res, errno, strerror(errno));
            
        }
    }
    else {
        DEBUG(/* Something happened to the cached packet???*/);
    }
    
    /* schedule the next retransmission */
    ctx->rtx_timer.deadline = time(NULL) + cfg->rtx_interval;
}

static void Disconnect() {
    pacs->cstate = PAC_STATE_CLOSED;
    DEBUG("Session Disconnecting");
    /* Nothing to do for MD5 */
    /* TODO: sess cleanup */
    
}

#define FAILED_SESS_TIMEOUT   (cfg->failed_sess_timeout)
#define LIFETIME_SESS_TIMEOUT (pacs->session_lifetime)

static void SessionTimerReStart(uint16_t timeout) {
    pac_ctx_t * ctx = pacs->ctx;
    ctx->session_timer.deadline = time(NULL) + timeout;
    ctx->session_timer.enabled = TRUE;
    if (pacs->session_lifetime != 0) {
        ctx->reauth_timer.deadline = time(NULL) +
                (100 * timeout) / cfg->reauth_interval;
        ctx->reauth_timer.enabled = TRUE;
    }
        
        
}

static void SessionTimerStop() {
    pac_ctx_t * ctx = pacs->ctx;
    ctx->session_timer.enabled = FALSE;
}


static void EAP_RespTimerStop() {
    pac_ctx_t * ctx = pacs->ctx;
    ctx->eap_resptimer.enabled = FALSE;
}

static void EAP_RespTimerStart() {
    pac_ctx_t * ctx = pacs->ctx;
    ctx->eap_resptimer.enabled = TRUE;
    ctx->eap_resptimer.deadline = time(NULL) + FAILED_SESS_TIMEOUT;
}


static void EAP_Restart() {
    /* MD5 has no special requirements to restart */
}

static void TxEAP(pana_packet_t * pktin) {
    pac_ctx_t * ctx = pacs->ctx;
    pana_avp_t * eap_payload = NULL;
    struct wpabuf * wtmp = NULL;
    struct wpabuf * eap_resp = NULL;
    
    if (pktin == NULL) {
        return;
    }
    
    
    eap_payload = get_avp_by_code(pktin->pp_avp_list, PAVP_EAP_PAYLOAD, AVP_GET_FIRST);
    if (!eap_payload) {
        return;
    }
    
    wtmp = wpabuf_alloc_ext_data(eap_payload->avp_value, eap_payload->avp_length);
    eap_resp = eap_md5_process(ctx->eap_config, ctx->eap_ret, wtmp);
    wpabuf_free(wtmp);
    free_avp(eap_payload);        
    
    /* Store the pending EAP payload */
    if (eap_resp != NULL) {
        ctx->eap_resp_payload = bytebuff_from_bytes(wpabuf_head_u8(eap_resp),
                                                eap_resp->used);
        EAP_RESPONSE_Set();
    }
    
    if (ctx->eap_ret->ignore){
        EAP_DISCARD_Set();
    }
    
    if (ctx->eap_ret->decision == DECISION_UNCOND_SUCC) {
        EAP_SUCCESS_Set();
    }
    
    wpabuf_free(eap_resp);
    
    
}

static Boolean eap_piggyback() {
    /* This MD5 does not wait for user input */
    return TRUE;
}

static int PAR_RESULT_CODE(pana_packet_t * pktin) {
    int res;
    if (!pktin) {
        return -1;
    }
    pana_avp_t * tmpavp = get_avp_by_code(pktin->pp_avp_list,
            PAVP_RESULT_CODE, AVP_GET_FIRST);
    if (!tmpavp) {
        DEBUG("This packet does'nt have a result code");
        return -1;
    }
    
    res = bytes_to_be32(tmpavp->avp_value);
    
    free_avp(tmpavp);
    return res;
}

static eap_peer_config_t * get_eap_config(pana_eap_peer_config_t * cfg) {
    eap_peer_config_t * out_cfg = NULL;
    if (!cfg) {
        return NULL;
    }
    
    out_cfg = szalloc(eap_peer_config_t);
    if (!out_cfg) {
        return NULL;
    }
    
    out_cfg->identity_len = cfg->identity_len;
    out_cfg->identity = smalloc(cfg->identity_len);
    memcpy(out_cfg->identity, cfg->identity, cfg->identity_len);

    out_cfg->password_len = cfg->password_len;
    out_cfg->password = smalloc(cfg->password_len);
    memcpy(out_cfg->password, cfg->password, cfg->password_len);
    
    return out_cfg;
    
}

static void pac_session_init(pac_config_t * pac_cfg){
    pac_ctx_t * ctx;
    cfg = pac_cfg;
    pacs = szalloc(pana_session_t);
    pacs->ctx = szalloc(pac_ctx_t);
    
    ctx = pacs->ctx;
    ctx->pacglobal = pac_cfg;
    pacs->pac_ip_port = cfg->pac;
    pacs->paa_ip_port = cfg->paa;
    pacs->sa = szalloc(pana_sa_t);
    
    ctx->eap_ret = szalloc(*ctx->eap_ret);
    ctx->eap_config = get_eap_config(pac_cfg->eap_cfg);
    ctx->stats_flags = SF_CELARED;
    
    
    
    RtxTimerStop();
    ctx->reauth_timer.enabled = FALSE;
    pacs->cstate = PAC_STATE_INITIAL;
    AUTH_USER_Set();
    
}

#define AVPLIST(AVP...) pac_avplist_create(pacs, AVP, PAVP_NULL)

static pana_avp_list_t pac_avplist_create(pana_session_t * pacs, pana_avp_codes_t AVP, ...) {
    va_list ap;
    pana_avp_codes_t reqAVP = AVP;
    pana_avp_t * tmp_avp = NULL;
    pac_ctx_t * ctx = NULL;
    pana_avp_list_t tmpavplist = NULL;
    
    if (!pacs) {
        return NULL;
    }
    ctx=pacs->ctx;
    if(!ctx) {
        return NULL;
    }
    
    va_start(ap,AVP);
    do {
        switch (reqAVP) {
        case PAVP_NONCE:
            if (pacs->sa == NULL) {
                break;
            }
            tmp_avp = create_avp(PAVP_NONCE, FAVP_FLAG_CLEARED, 0,
                    pacs->sa->PaC_nonce, sizeof(pacs->sa->PaC_nonce));
            tmpavplist = avp_list_insert(tmpavplist, avp_node_create(tmp_avp));
            break;
        case PAVP_EAP_PAYLOAD:
            if (ctx->eap_resp_payload == NULL) {
                break;
            }
            tmp_avp = create_avp(PAVP_EAP_PAYLOAD, FAVP_FLAG_CLEARED, 0,
                    bytebuff_data(ctx->eap_resp_payload),
                    ctx->eap_resp_payload->used);
            break;
        }
        
        reqAVP = va_arg(ap, pana_avp_codes_t);
    } while (reqAVP != PAVP_NULL);

    va_end(ap);
    
    return tmpavplist;
}

static bytebuff_t *
pac_process(bytebuff_t * datain) {
    pac_ctx_t * ctx =  pacs->ctx;
    
    bytebuff_t * respData;
    pana_packet_t * pkt_in = NULL;
    pana_avp_node_t * tmpavplist = NULL;
    
    
    if (datain != NULL) {
        dbg_hexdump(PKT_RECVD, "Packet-contents:", bytebuff_data(datain), datain->size);
        pkt_in = parse_pana_packet(datain);
        if (pkt_in == NULL) {
            dbg_printf(MSG_ERROR,"Packet is invalid");
            clear_events();
            return NULL;
        }
    }
    
   if (PKT_RECVD) {
//   State: ANY except INITIAL
//   - - - - - - - - - - (liveness test initiated by peer)- - - - - -
//   Rx:PNR[P]                Tx:PNA[P]();               (no change)
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
       if (pacs->cstate != PAC_STATE_INITIAL) {
           if (RX_PNR_P(pkt_in)) {
               /* reset the event status */
               clear_events();
               TX_PNA_P(respData, NULL);
           }
       }

//   State: ANY except WAIT_PNA_PING
//   - - - - - - - - - - - - (liveness test response) - - - - - - - -
//   Rx:PNA[P]                None();                    (no change)
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
       if (pacs->cstate != PAC_STATE_WAIT_PNA_PING){
           if (RX_PNA_P(pkt_in)) {
               clear_events();
               /* just discard the packet because it's not meant occur in this phase */
           }
       }
   }    
//   State: CLOSED
//   - - - - - - - -(Catch all event on closed state) - - - - - - - -
//   ANY                      None();                    CLOSED
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if (pacs->cstate == PAC_STATE_CLOSED){
        clear_events();
        /* just discard the packet because it's not meant occur in this phase */
    }
    
    
    while(ctx->event_occured) {
        switch (pacs->cstate) {
        case PAC_STATE_INITIAL:
//   - - - - - - - - - - (PaC-initiated Handshake) - - - - - - - - -
//   AUTH_USER                Tx:PCI[]();                INITIAL
//                            RtxTimerStart();
//                            SessionTimerReStart
//                              (FAILED_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (AUTH_USER) {
                clear_events();
                TX_PCI(respData, NULL);
                RtxTimerStart(respData);
                SessionTimerReStart(FAILED_SESS_TIMEOUT);
                pacs->cstate = PAC_STATE_INITIAL;
            }
//   - - - - - - -(PAA-initiated Handshake, not optimized) - - - - -
//   Rx:PAR[S] &&             EAP_Restart();             WAIT_PAA
//   !PAR.exists_avp           SessionTimerReStart
//   ("EAP-Payload")              (FAILED_SESS_TIMEOUT);
//                            if (generate_pana_sa())
//                                Tx:PAN[S]("PRF-Algorithm",
//                                   "Integrity-Algorithm");
//                            else
//                                Tx:PAN[S]();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR_S(pkt_in) && !exists_avp(pkt_in, PAVP_EAP_PAYLOAD)) {
                clear_events();
                EAP_Restart();
                SessionTimerReStart(FAILED_SESS_TIMEOUT);
                /* initialise tx_seq and rx_seq*/
                pacs->seq_rx = pkt_in->pp_seq_number;
                pacs->seq_tx = random();
                /* MD5 does not generate MSK so no pana_sa needed */
                TX_PAN_S(respData, NULL);
                pacs->cstate = PAC_STATE_WAIT_PAA;                
            }
//   - - - - - - - -(PAA-initiated Handshake, optimized) - - - - - -
//   Rx:PAR[S] &&             EAP_Restart();             INITIAL
//   PAR.exists_avp            TxEAP();
//   ("EAP-Payload") &&       SessionTimerReStart
//   eap_piggyback()            (FAILED_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR_S(pkt_in) && exists_avp(pkt_in, PAVP_EAP_PAYLOAD) && 
                    eap_piggyback()) {
                clear_events();
                /* initialise tx_seq and rx_seq*/
                pacs->seq_rx = pkt_in->pp_seq_number;
                pacs->seq_tx = random();
                EAP_Restart();
                TxEAP(pkt_in);
                SessionTimerReStart(FAILED_SESS_TIMEOUT);
                pacs->cstate = PAC_STATE_INITIAL;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   Rx:PAR[S] &&             EAP_Restart();             WAIT_EAP_MSG
//   PAR.exists_avp            TxEAP();
//   ("EAP-Payload") &&       SessionTimerReStart
//   !eap_piggyback()           (FAILED_SESS_TIMEOUT);
//                            if (generate_pana_sa())
//                                Tx:PAN[S]("PRF-Algorithm",
//                                  "Integrity-Algorithm");
//                            else
//                                Tx:PAN[S]();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            /*
             * WARNING: This is not working well in this current implementation.
             */
            else if (RX_PAR_S(pkt_in) && exists_avp(pkt_in, PAVP_EAP_PAYLOAD) &&
                    !eap_piggyback()) {
                clear_events();
                /* initialise tx_seq and rx_seq*/
                pacs->seq_rx = pkt_in->pp_seq_number;
                pacs->seq_tx = random();
                EAP_Restart();
                TxEAP(pkt_in);
                SessionTimerReStart(FAILED_SESS_TIMEOUT);
                /* MD5 Does not generate pana_sa */
                TX_PAN_S(respData, NULL);
                
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_RESPONSE             if (generate_pana_sa())    WAIT_PAA
//                                Tx:PAN[S]("EAP-Payload",
//                                  "PRF-Algorithm",
//                                  "Integrity-Algorithm");
//                            else
//                                Tx:PAN[S]("EAP-Payload");
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_RESPONSE) {
                clear_events();
                /* No pana_sa will be generate */
                
                tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD);
                TX_PAN_S(respData, tmpavplist);
                
                pacs->cstate = PAC_STATE_WAIT_PAA;
            } break;
            
        case PAC_STATE_WAIT_PAA:
//   - - - - - - - - - - - - - - -(PAR-PAN exchange) - - - - - - - -
//   Rx:PAR[] &&              RtxTimerStop();            WAIT_EAP_MSG
//   !eap_piggyback()         TxEAP();
//                            EAP_RespTimerStart();
//                            if (NONCE_SENT==Unset) {
//                              NONCE_SENT=Set;
//                              Tx:PAN[]("Nonce");
//                            }
//                            else
//                              Tx:PAN[]();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PAR(pkt_in) && !eap_piggyback()) {
                clear_events();
                TxEAP(pkt_in);
                EAP_RespTimerStart();

                /* MD5 doeas not generate pana_sa */
                if (!(NONCE_SENT)) {
                    if (os_get_random(pacs->sa->PaC_nonce,
                            sizeof(pacs->sa->PaC_nonce)) < 0) {
                        DEBUG("Nonce couldn't be generated");
                    }
                    dbg_hexdump(MSG_SEC, "Generated Nonce contents", 
                            pacs->sa->PaC_nonce, sizeof(pacs->sa->PaC_nonce));
                    
                    NONCE_SENT_Set();                   
                    tmpavplist = AVPLIST(PAVP_NONCE);
                    TX_PAN(respData, tmpavplist);
                } else {
                    TX_PAN(respData, NULL);
                }
                
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   Rx:PAR[] &&              RtxTimerStop();            WAIT_EAP_MSG
//   eap_piggyback()          TxEAP();
//                            EAP_RespTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if(RX_PAR(pkt_in) && eap_piggyback()) {
                clear_events();
                
                RtxTimerStop();
                TxEAP(pkt_in);
                EAP_RespTimerStart();
                
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   Rx:PAN[]                 RtxTimerStop();            WAIT_PAA
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAN(pkt_in)) {
                clear_events();
                
                RtxTimerStop();
                
                pacs->cstate = PAC_STATE_WAIT_PAA;
            }
//   - - - - - - - - - - - - - - -(PANA result) - - - - - - - - - -
//   Rx:PAR[C] &&             TxEAP();                   WAIT_EAP_RESULT
//   PAR.RESULT_CODE==
//     PANA_SUCCESS
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR_C(pkt_in) && PAR_RESULT_CODE(pkt_in) == PANA_SUCCESS) {
                clear_events();
                
                pacs->session_id = pkt_in->pp_session_id;
                pana_avp_t *tmp_avp = get_avp_by_code(pkt_in->pp_avp_list,
                        PAVP_SESSION_LIFET, AVP_GET_FIRST);
                if (tmp_avp != NULL) {
                    pacs->session_lifetime = bytes_to_be32(tmp_avp->avp_value);
                }
                free_avp(tmp_avp);
                
                TxEAP(pkt_in);
                
                pacs->cstate = PAC_STATE_WAIT_EAP_RESULT;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   Rx:PAR[C] &&             if (PAR.exist_avp          WAIT_EAP_RESULT_
//   PAR.RESULT_CODE!=          ("EAP-Payload"))         CLOSE
//     PANA_SUCCESS             TxEAP();
//                            else
//                               alt_reject();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR_C(pkt_in) && PAR_RESULT_CODE(pkt_in) != PANA_SUCCESS) {
                clear_events();
                
                if (exists_avp(pkt_in, PAVP_EAP_PAYLOAD)){
                    TxEAP(pkt_in);
                } else {
                    /* MD5 Does not need any notifications */
                    // pac_alt_reject
                }
                
                pacs->cstate = PAC_STATE_WAIT_EAP_RESULT_CLOSE;
            } break;

        case PAC_STATE_WAIT_EAP_MSG:
//   - - - - - - - - - - (Return PAN/PAR from EAP) - - - - - - - - -
//   EAP_RESPONSE &&          EAP_RespTimerStop()        WAIT_PAA
//   eap_piggyback()          if (NONCE_SENT==Unset) {
//                              Tx:PAN[]("EAP-Payload",
//                                       "Nonce");
//                              NONCE_SENT=Set;
//                            }
//                            else
//                              Tx:PAN[]("EAP-Payload");
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if(EAP_RESPONSE && eap_piggyback()) {
                clear_events();

                EAP_RespTimerStop();
                if (!(NONCE_SENT)) {
                    if (os_get_random(pacs->sa->PaC_nonce,
                            sizeof(pacs->sa->PaC_nonce)) < 0) {
                        DEBUG("Nonce couldn't be generated");
                    }
                    dbg_hexdump(MSG_SEC, "Generated Nonce contents", 
                            pacs->sa->PaC_nonce, sizeof(pacs->sa->PaC_nonce));
                    

                    tmpavplist = AVPLIST(PAVP_NONCE, PAVP_EAP_PAYLOAD);
                    TX_PAN(respData, tmpavplist);
                    NONCE_SENT_Set();                   
                } else {
                    tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD);
                    TX_PAN(respData, tmpavplist);
                }

                pacs->cstate = PAC_STATE_WAIT_PAA;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_RESPONSE &&          EAP_RespTimerStop()        WAIT_PAA
//   !eap_piggyback()         Tx:PAR[]("EAP-Payload");
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if(EAP_RESPONSE && !eap_piggyback()) {
                clear_events();

                EAP_RespTimerStop();
                tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD);
                TX_PAR(respData, tmpavplist);
                RtxTimerStart(respData);
                
                pacs->cstate = PAC_STATE_WAIT_PAA;
                
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_RESP_TIMEOUT &&      Tx:PAN[]();                WAIT_PAA
//   eap_piggyback()
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if(EAP_RESP_TIMEOUT &&
                    eap_piggyback()) {
                clear_events();
                
                TX_PAN(respData, NULL);
                
                pacs->cstate = PAC_STATE_WAIT_PAA;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Rx.PAR[] &&                 TxEAP()                    WAIT_EAP_MSG
//   EAP_DISCARD
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR(pkt_in) && EAP_DISCARD) {
                clear_events();
                
                TxEAP(pkt_in);
                
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_FAILURE              SessionTimerStop();        CLOSED
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_FAILURE) {
                clear_events();
                
                SessionTimerStop();
                Disconnect();
                
                pacs->cstate = PAC_STATE_CLOSED;
            } break;
            
        case PAC_STATE_WAIT_EAP_RESULT:
//   - - - - - - - - - - - - - (EAP Result) - - - - - - - - - - - - -
//   EAP_SUCCESS             if (PAR.exist_avp           OPEN
//                              ("Key-Id"))
//                             Tx:PAN[C]("Key-Id");
//                           else
//                             Tx:PAN[C]();
//                           Authorize();
//                           SessionTimerReStart
//                             (LIFETIME_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (EAP_SUCCESS) {
                clear_events();
                /* MD5 Does not use a key ID */
                TX_PAN_C(respData, NULL);
                /* No need to authorize Authorize()
                 * because we either are granted acces or not */
                SessionTimerReStart(LIFETIME_SESS_TIMEOUT);
                pacs->cstate = PAC_STATE_OPEN;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_FAILURE             Tx:PAN[C]();                CLOSED
//                           SessionTimerStop();
//                           Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_FAILURE) {
                clear_events();
                
                TX_PAN_C(respData, NULL);
                SessionTimerStop();
                Disconnect();
                
                pacs->cstate = PAC_STATE_CLOSED;
            } break;
            
        case PAC_STATE_WAIT_EAP_RESULT_CLOSE:
//   - - - - - - - - - - - - - (EAP Result) - - - - - - - - - - - - -
//   EAP_SUCCESS ||          if (EAP_SUCCESS &&         CLOSED
//   EAP_FAILURE               PAR.exist_avp("Key-Id"))
//                             Tx:PAN[C]("Key-Id");
//                           else
//                             Tx:PAN[C]();
//                           SessionTimerStop();
//                           Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (EAP_SUCCESS || EV_EAP_FAILURE) {
                clear_events();
                
                /* No key Id is used for now */
                TX_PAN_C(respData, NULL);
                SessionTimerStop();
                Disconnect();
                
                pacs->cstate = PAC_STATE_CLOSED;
            } break;
            
        case PAC_STATE_OPEN:
//   - - - - - - - - - - (liveness test initiated by PaC)- - - - - -
//   PANA_PING                Tx:PNR[P]();               WAIT_PNA_PING
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (PANA_PING) {
                clear_events();
                TX_PNR_P(respData, NULL);
                RtxTimerStart(respData);
                
                pacs->cstate = PAC_STATE_WAIT_PNA_PING;
            }
//   - - - - - - - - - (re-authentication initiated by PaC)- - - - - -
//   REAUTH                   NONCE_SENT=Unset;          WAIT_PNA_REAUTH
//                            Tx:PNR[A]();
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (REAUTH) {
                clear_events();
                NONCE_SENT_Unset();
                TX_PNR_A(respData, NULL);
                RtxTimerStart(respData);
                pacs->cstate = PAC_STATE_WAIT_PNA_REAUTH;
            }
//   - - - - - - - - - (re-authentication initiated by PAA)- - - - - -
//   Rx:PAR[]                 EAP_RespTimerStart();      WAIT_EAP_MSG
//                            TxEAP();
//                            if (!eap_piggyback())
//                              Tx:PAN[]("Nonce");
//                            else
//                              NONCE_SENT=Unset;
//                            SessionTimerReStart
//                              (FAILED_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR(pkt_in)) {
                clear_events();
                EAP_RespTimerStart();
                TxEAP(pkt_in);
                if (!eap_piggyback()) {
                    tmpavplist = AVPLIST(PAVP_NONCE);
                    TX_PAN(respData, tmpavplist);
                } else {
                    NONCE_SENT_Unset();
                }
                SessionTimerReStart
                (FAILED_SESS_TIMEOUT);
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - -(Session termination initiated by PAA) - - - - - -
//   Rx:PTR[]                 Tx:PTA[]();                CLOSED
//                            SessionTimerStop();
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PTR(pkt_in)) {
                clear_events();
                TX_PTA(respData, NULL);
                SessionTimerStop();
                Disconnect();
                pacs->cstate = PAC_STATE_CLOSED;
            }
//   - - - - - - - -(Session termination initiated by PaC) - - - - - -
//   TERMINATE                Tx:PTR[]();                SESS_TERM
//                            RtxTimerStart();
//                            SessionTimerStop();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (TERMINATE) {
                clear_events();
                
                TX_PTR(respData, NULL);
                RtxTimerStart(respData);
                SessionTimerStop();
                
                pacs->cstate = PAC_STATE_SESS_TERM;
            } break;
            
        case PAC_STATE_WAIT_PNA_REAUTH:
//   - - - - - - - - -(re-authentication initiated by PaC) - - - - -
//   Rx:PNA[A]                RtxTimerStop();            WAIT_PAA
//                            SessionTimerReStart
//                              (FAILED_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PNA_A(pkt_in)) {
                clear_events();
                RtxTimerStop();
                SessionTimerReStart(FAILED_SESS_TIMEOUT);
                pacs->cstate = PAC_STATE_WAIT_PAA;
            }
//   - - - - - - - -(Session termination initiated by PAA) - - - - - -
//   Rx:PTR[]                 RtxTimerStop();            CLOSED
//                            Tx:PTA[]();
//                            SessionTimerStop();
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PTR(pkt_in)) {
                clear_events();
                RtxTimerStop();
                TX_PTA(respData, NULL);
                SessionTimerStop();
                Disconnect();
                pacs->cstate = PAC_STATE_CLOSED;
            } break;

//   --------------------
        case PAC_STATE_WAIT_PNA_PING:
//   --------------------
//
//   - - - - - - - - -(liveness test initiated by PaC) - - - - - - -
//   Rx:PNA[P]                RtxTimerStop();            OPEN
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PNA_P(pkt_in)) {
                clear_events();
                RtxTimerStop();
                pacs->cstate = PAC_STATE_OPEN;
            }
//   - - - - - - - - - (re-authentication initiated by PAA)- - - - -
//   Rx:PAR[]                 RtxTimerStop();            WAIT_EAP_MSG
//                            EAP_RespTimerStart();
//                            TxEAP();
//                            if (!eap_piggyback())
//                              Tx:PAN[]("Nonce");
//                            else
//                              NONCE_SENT=Unset;
//                            SessionTimerReStart
//                              (FAILED_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAR(pkt_in)) {
                clear_events();
                
                RtxTimerStop();
                EAP_RespTimerStart();
                TxEAP(pkt_in);
                if (!eap_piggyback()) {
                    tmpavplist = AVPLIST(PAVP_NONCE);
                    TX_PAN(respData, tmpavplist);
                } else {
                    NONCE_SENT_Unset();
                }
                SessionTimerReStart
                (FAILED_SESS_TIMEOUT);
                
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - -(Session termination initiated by PAA) - - - - - -
//   Rx:PTR[]                 RtxTimerStop();            CLOSED
//                            Tx:PTA[]();
//                            SessionTimerStop();
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PTR(pkt_in)) {
                clear_events();
                
                RtxTimerStop();
                TX_PTA(respData, NULL);
                SessionTimerStop();
                Disconnect();
                
                pacs->cstate = PAC_STATE_CLOSED;
            } break;
//   ----------------
        case PAC_STATE_SESS_TERM:
//   ----------------
//
//   - - - - - - - -(Session termination initiated by PaC) - - - - -
//   Rx:PTA[]                 Disconnect();              CLOSED
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PTA(pkt_in)) {
                clear_events();
                
                Disconnect();
                
                pacs->cstate = PAC_STATE_CLOSED;
            }
            /* End switch */
        }
    
    }

    
    if (respData == NULL) {
        return NULL;
    }
    
    return respData;
}

int
pac_main(const pac_config_t * const global_cfg) {
    cfg = global_cfg;
    struct sockaddr_in pac_sockaddr;
    struct sockaddr_in nas_sockaddr;
    int sockfd;
    fd_set read_flags;
    struct timeval selnowait = {0 ,0};  //Nonblocking select
    bytebuff_t * rxbuff = NULL;
    bytebuff_t * txbuff = NULL;
    int ret;
    
    pac_ctx_t * ctx = NULL;
    

    
    bzero(&pac_sockaddr, sizeof pac_sockaddr);
    pac_sockaddr.sin_family = AF_INET;
    pac_sockaddr.sin_addr.s_addr = INADDR_ANY; 
    pac_sockaddr.sin_port = cfg->pac.port;
    
    
    bzero(&nas_sockaddr, sizeof nas_sockaddr);
    nas_sockaddr.sin_family = AF_INET;
    nas_sockaddr.sin_addr.s_addr = cfg->paa.ip;
    nas_sockaddr.sin_port = cfg->paa.port;
    
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return ERR_SOCK_ERROR;
    }
    

    if ((bind(sockfd, &pac_sockaddr, sizeof pac_sockaddr)) < 0) {
        close(sockfd);
        return ERR_BIND_SOCK;
    }

    
    if ((connect(sockfd, &nas_sockaddr, sizeof nas_sockaddr)) < 0) {
        close(sockfd);
        return ERR_CONNECT_SOCK;
    }

    /*
     * Setup the sockfd (nonblocking)
     */
       
    if (fcntl(sockfd,F_SETFL, fcntl(sockfd,F_GETFL,0) | O_NONBLOCK) == -1) {
        close(sockfd);
        DEBUG("Could not set the socket as nonblocking");
        dbg_printf(ERR_SETFL_NONBLOCKING,"Could not set the socket as nonblocking");
        return ERR_NONBLOK_SOCK;
    }
    
    FD_ZERO(&read_flags);
    FD_SET(sockfd, &read_flags);
    
    /*
     * Start the PANA session
     */
    pac_session_init(cfg);
    ctx =  pacs->ctx;
    ctx->sockfd = sockfd;
    
    txbuff = pac_process(NULL);
    if (txbuff != NULL) {
        dbg_asciihexdump(PANA_PKT_SENDING,"Contents:",
                bytebuff_data(txbuff), txbuff->used);
        ret = send(sockfd, bytebuff_data(txbuff), txbuff->used, 0);
        if (ret < 0 && ret != txbuff->used) {
            /* will try at retransmission time */
            DEBUG("There was a problem when sending the message.");
        }
        free_bytebuff(txbuff);                

    
    rxbuff = bytebuff_alloc(PANA_PKT_MAX_SIZE);
    while(pacs->cstate != PAC_STATE_CLOSED) {
        
        /* 
         * While there are incoming packets to be processed process them.
         */
        while(select(sockfd + 1, &read_flags, NULL, NULL, &selnowait) > 0 &&
                FD_ISSET(sockfd, &read_flags)) {
            FD_CLR(sockfd, &read_flags);
           
            ret = recv(sockfd, bytebuff_data(rxbuff), rxbuff->size, 0);
            if (ret <= 0) {
                DEBUG(" No bytes were read");
                continue;
            }
            
            rxbuff->used = ret;
            dbg_asciihexdump(PANA_PKT_RECVD,"Contents:",
                    bytebuff_data(rxbuff), rxbuff->used);

            PKT_RECVD_Set();
            txbuff = pac_process(rxbuff);
            if (txbuff != NULL) {
                dbg_asciihexdump(PANA_PKT_SENDING,"Contents:",
                        bytebuff_data(txbuff), txbuff->used);
                ret = send(sockfd, bytebuff_data(txbuff), txbuff->used, 0);
                if (ret < 0 && ret != txbuff->used) {
                    /* will try at retransmission time */
                    DEBUG("There was a problem when sending the message.");
                }
                free_bytebuff(txbuff);                
            }
        }
        
        
//   - - - - - - - - - - - - - (Re-transmissions)- - - - - - - - - -
//   RTX_TIMEOUT &&           Retransmit();              (no change)
//   RTX_COUNTER<
//   RTX_MAX_NUM
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        if (ctx->rtx_timer.enabled && time(NULL) >= ctx->rtx_timer.deadline &&
                ctx->rtx_timer.count < cfg->rtx_max_count) {
            Retransmit();
        }
        
//   - - - - - - - (Reach maximum number of transmissions)- - - - - -
//   (RTX_TIMEOUT &&          Disconnect();              CLOSED
//    RTX_COUNTER>=
//    RTX_MAX_NUM) ||
//   SESS_TIMEOUT
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        if ((ctx->rtx_timer.enabled && time(NULL) >= ctx->rtx_timer.deadline &&
                ctx->rtx_timer.count >= cfg->rtx_max_count) &&
                ctx->session_timer.enabled && time(NULL) >= ctx->session_timer.deadline) {
            Disconnect();
            pacs->cstate = PAC_STATE_CLOSED;
        }
        
        /*
         * Check reauth and start the procedure if required
         */
        if(pacs->cstate == PAC_STATE_OPEN && 
                (ctx->reauth_timer.enabled && time(NULL) >= ctx->reauth_timer.deadline)) {
            REAUTH_Set();
        }
        
    }
    
    free_bytebuff(rxbuff);
    free_bytebuff(txbuff);
    free(ctx->eap_config);
    free(ctx->eap_ret);
    free(pacs->sa);
    free(pacs->ctx);
    free(pacs);
    
    
    close(sockfd);
    }
    
    return 0;
}


