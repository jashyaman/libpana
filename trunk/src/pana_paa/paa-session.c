/*
 * paa-session.c
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
#include "paa-session.h"


/* pac context data */
typedef struct paa_ctx {
    
    int sockfd;
    
    rtimer_t rtx_timer;
    rtimer_t reauth_timer;
    rtimer_t session_timer;
    uint16_t stats_flags;
#define SF_CELARED    0
#define SF_NONCE_SENT           (1 << 0)
#define SF_OPTIMIZED_INIT       (1 << 1) 
    
    const paa_config_t * paaglobal;   //we want this to be readonly
    
    /* EAP interface */
    eap_peer_config_t * eap_config;
    eap_method_ret_t * eap_ret;
    bytebuff_t * eap_resp_payload;  //store the pending EAP response
    rtimer_t eap_resptimer;
    
    
    /* Events */
    uint32_t event_occured;
#define EV_CLEAR                0
#define EV_PKT_RECVD            (1 << 0)
#define EV_REAUTH               (1 << 1)
#define EV_TERMINATE            (1 << 2)
#define EV_PANA_PING            (1 << 3)

#define EV_EAP_SUCCESS          (1 << 4)
#define EV_EAP_FAILURE          (1 << 5)
#define EV_EAP_REQUEST          (1 << 6)
#define EV_EAP_TIMEOUT          (1 << 7)
#define EV_EAP_DISCARD          (1 << 8)

#define EV_RTX_TIMEOUT           (1 << 10)
#define EV_SESS_TIMEOUT          (1 << 11)
#define EV_PAA_FOUND             (1 << 12)

} paa_ctx_t;

/*
 * WARNING!!! BEFORE USE MUST DECLARE A VARIABLE: 
 *      pac_ctx_t * ctx = (pac_ctx_t *)target_session->ctx;
 */
//  use this regexp on EV_ defines:
//  ^#define\s+EV_(\w+)\s+.*$
//  #define $1\t\t(ctx->event_occured & EV_$1)
//  #define $1_Set()\t(ctx->event_occured |= EV_$1)
//  #define $1_Unset()\t(ctx->event_occured &= ~EV_$1)


#define clear_events()   (ctx->event_occured = EV_CLEAR)

#define PKT_RECVD	(ctx->event_occured & EV_PKT_RECVD)
#define PKT_RECVD_Set()	(ctx->event_occured |= EV_PKT_RECVD)
#define REAUTH	(ctx->event_occured & EV_REAUTH)
#define REAUTH_Set()	(ctx->event_occured |= EV_REAUTH)
#define TERMINATE	(ctx->event_occured & EV_TERMINATE)
#define TERMINATE_Set()	(ctx->event_occured |= EV_TERMINATE)
#define PANA_PING	(ctx->event_occured & EV_PANA_PING)
#define PANA_PING_Set()	(ctx->event_occured |= EV_PANA_PING)

#define EAP_SUCCESS	(ctx->event_occured & EV_EAP_SUCCESS)
#define EAP_SUCCESS_Set()	(ctx->event_occured |= EV_EAP_SUCCESS)
#define EAP_FAILURE	(ctx->event_occured & EV_EAP_FAILURE)
#define EAP_FAILURE_Set()	(ctx->event_occured |= EV_EAP_FAILURE)
#define EAP_REQUEST	(ctx->event_occured & EV_EAP_REQUEST)
#define EAP_REQUEST_Set()	(ctx->event_occured |= EV_EAP_REQUEST)
#define EAP_TIMEOUT	(ctx->event_occured & EV_EAP_TIMEOUT)
#define EAP_TIMEOUT_Set()	(ctx->event_occured |= EV_EAP_TIMEOUT)
#define EAP_DISCARD	(ctx->event_occured & EV_EAP_DISCARD)
#define EAP_DISCARD_Set()	(ctx->event_occured |= EV_EAP_DISCARD)

#define RTX_TIMEOUT             (ctx->event_occured & EV_RTX_TIMEOUT)
#define RTX_TIMEOUT_Set()       (ctx->event_occured |= EV_RTX_TIMEOUT)
#define SESS_TIMEOUT            (ctx->event_occured & EV_SESS_TIMEOUT)
#define SESS_TIMEOUT_Set()      (ctx->event_occured |= EV_SESS_TIMEOUT)


#define PAA_FOUND		(ctx->event_occured & EV_PAA_FOUND)
#define PAA_FOUND_Set()	        (ctx->event_occured |= EV_PAA_FOUND)
#define PAA_FOUND_Unset()	(ctx->event_occured &= ~EV_PAA_FOUND)

//  use this regexp on SF_ defines:
//  ^#define\s+SF_(\w+)\s+.*$
//  #define $1\t\t(ctx->event_occured & SF_$1)
//  #define $1_Set()\t(ctx->event_occured |= SF_$1)
//  #define $1_Unset()\t(ctx->event_occured &= ~SF_$1)

#define NONCE_SENT         (ctx->stats_flags & SF_NONCE_SENT)
#define NONCE_SENT_Set()   (ctx->stats_flags |= SF_NONCE_SENT)
#define NONCE_SENT_Unset() (ctx->stats_flags &= ~SF_NONCE_SENT)

#define OPTIMIZED_INIT		(ctx->event_occured & SF_OPTIMIZED_INIT)
#define OPTIMIZED_INIT_Set()	(ctx->event_occured |= SF_OPTIMIZED_INIT)
#define OPTIMIZED_INIT_Unset()	(ctx->event_occured &= ~SF_OPTIMIZED_INIT)


static pana_session_t * pacs_list;
static uint32_t last_sess_id;
static paa_config_t * cfg;

typedef enum {
   PAA_STATE_INITIAL,
   PAA_STATE_WAIT_EAP_MSG,
   PAA_STATE_WAIT_SUCC_PAN,
   PAA_STATE_WAIT_FAIL_PAN,
   
   PAA_STATE_OPEN,
   PAA_STATE_WAIT_PNA_PING,
   PAA_STATE_WAIT_PAN_OR_PAR,

   PAA_STATE_SESS_TERM,
   PAA_STATE_CLOSED
} paa_session_state_t;


static void Disconnect(pana_session_t * pacs) {
    pacs->cstate = PAA_STATE_CLOSED;
    DEBUG("Session Disconnecting");
    /* Nothing to do for MD5 */
    /* TODO: sess cleanup */
    
}

static void TxEAP(pana_session_t * pacs, pana_packet_t * pktin) {
    paa_ctx_t * ctx = pacs->ctx;
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
    /*
     * TODO:
     */
//    eap_resp = eap_md5_process(ctx->eap_config, ctx->eap_ret, wtmp);
    wpabuf_free(wtmp);
    free_avp(eap_payload);        
    
    /* Store the pending EAP payload */
  
    
    wpabuf_free(eap_resp);
}

/*
 * Register a packet in the retransmit cache.
 */
static void RtxTimerStart(pana_session_t * pacs, bytebuff_t * respdata) {
    paa_ctx_t * ctx = pacs->ctx;
    if (pacs->pkt_cache != NULL) {
        free_bytebuff(pacs->pkt_cache);
    }
    pacs->pkt_cache = bytebuff_dup(respdata);
    ctx->rtx_timer.deadline = time(NULL) + cfg->rtx_interval;
    ctx->rtx_timer.count = 0;
    ctx->rtx_timer.enabled = TRUE;
}

static void RtxTimerStop(pana_session_t * pacs) {
    ((paa_ctx_t *)(pacs->ctx))->rtx_timer.enabled = FALSE;
}


#define FAILED_SESS_TIMEOUT   (cfg->failed_sess_timeout)
#define LIFETIME_SESS_TIMEOUT (pacs->session_lifetime)

static void SessionTimerReStart(pana_session_t * pacs, uint16_t timeout) {
    paa_ctx_t * ctx = pacs->ctx;
    ctx->session_timer.deadline = time(NULL) + timeout;
    ctx->session_timer.enabled = TRUE;
       
        
}

static void SessionTimerStop(pana_session_t * pacs) {
    paa_ctx_t * ctx = pacs->ctx;
    ctx->session_timer.enabled = FALSE;
}


static void Retransmit(pana_session_t * pacs) {
    int res;
    paa_ctx_t * ctx = pacs->ctx;

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

static Boolean Authorize(pana_session_t * pacs){
    /*
     * TODO: HERE MUST REGISTER SENDING ACL TO EP
     */
       
    return TRUE;
}

static void EAP_Restart(pana_session_t * pacs) {
    /* MD5 has no special requirements to restart */
    /*
     * TODO:
     */
}

#define PAVP_RESULT_SUCCESS                 (PAVP_RESULT_CODE | (0x10000 << PANA_SUCCESS) )
#define PAVP_RESULT_AUTHENTICATION_REJECTED (PAVP_RESULT_CODE | (0x10000 << PANA_AUTHENTICATION_REJECTED) )
#define PAVP_RESULT_AUTHORIZATION_REJECTED  (PAVP_RESULT_CODE | (0x10000 << PANA_AUTHORIZATION_REJECTED) )


#define AVPLIST(AVP...) paa_avplist_create(pacs, AVP, PAVP_NULL)

static pana_avp_list_t paa_avplist_create(pana_session_t * pacs, uint32_t AVP, ...) {
    va_list ap;
    pana_avp_codes_t reqAVP = AVP;
    pana_avp_t * tmp_avp = NULL;
    paa_ctx_t * ctx = NULL;
    pana_avp_list_t tmpavplist = NULL;
    uint8_t * tmpval = NULL;
    
    if (!pacs) {
        return NULL;
    }
    ctx=pacs->ctx;
    if(!ctx) {
        return NULL;
    }
    
    va_start(ap,AVP);
    do {
        switch (reqAVP & 0xffff) {
        case PAVP_NONCE:
            if (pacs->sa == NULL) {
                break;
            }
            if (os_get_random(pacs->sa->PaC_nonce,
                    sizeof(pacs->sa->PaC_nonce)) < 0) {
                DEBUG("Nonce couldn't be generated");
            }
            dbg_hexdump(MSG_SEC, "Generated Nonce contents", 
                    pacs->sa->PaC_nonce, sizeof(pacs->sa->PaC_nonce));

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
            tmpavplist = avp_list_insert(tmpavplist, avp_node_create(tmp_avp));
            break;
        case PAVP_RESULT_CODE:
            tmpval = szalloc(uint32_t);
            buff_insert_be32(tmpval, (reqAVP >> 16) & 0xffff);
            tmp_avp = create_avp(PAVP_RESULT_CODE, FAVP_FLAG_CLEARED, 0,
                    tmpval, sizeof(uint32_t));
            tmpavplist = avp_list_insert(tmpavplist, avp_node_create(tmp_avp));
            break;
        }
        
        reqAVP = va_arg(ap, pana_avp_codes_t);
    } while (reqAVP != PAVP_NULL);

    va_end(ap);
    
    return tmpavplist;
}



static uint32_t paa_retrieve_sessID(bytebuff_t * datain ) {
    if (!datain) {
        return 0;
    }
    
    return bytes_to_be32(bytebuff_data(datain) + PPL_OFFSET_SESSION_ID);
}


static Boolean is_PCI(bytebuff_t * datain ) {
    if (!datain) {
        return FALSE;
    }
    
    if (bytes_to_be16(bytebuff_data(datain) + PPL_OFFSET_MSG_TYPE) == PMT_PCI) {
        return TRUE;
    }
    
    return FALSE;
    
}

ip_port_t saddr_in_to_ip_port(const struct sockaddr_in * peer_addr) {
    ip_port_t out;
    os_memset(&out, 0, sizeof(ip_port_t));
    out.ip = peer_addr->sin_addr.s_addr;
    out.port = peer_addr->sin_port;
    
    return out;
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

/*
 * Session list functions
 */


void paa_pana_session_free(pana_session_t * sess){
    paa_ctx_t * ctx = sess->ctx;
    if (!sess) {
        return;
    }
    
    free_bytebuff(sess->pkt_cache);
    /*
     * TODO: This shoul be handled properly bu because for now 
     * we use only nonce we don't care
     */
    os_free(sess->sa);

    if (ctx != NULL) {
        os_free(ctx->eap_config->identity);
        os_free(ctx->eap_config->password);
        os_free(ctx->eap_config);
        
        free_bytebuff(ctx->eap_resp_payload);
        os_free(ctx->eap_ret);
        os_free(ctx);
        
    }
    os_free(sess);
    
}

void sess_list_destroy(pana_session_t *sess_list)
{
    pana_session_t * cursor;
    pana_session_t * tmp_head;

    cursor = sess_list;

    while (cursor != NULL) {
        tmp_head = cursor->next;
        paa_pana_session_free(cursor);
        cursor = tmp_head;
    }
}

/*
 * WARNING: these functions do not change the pointers srclist & dstlist.
 * They shoul be used as 
 *      dstlist = avp_list_append(dstlist,srclist);
 *      dstlist = avp_list_insert(dstlist,srclist);
 */
pana_session_t *
sess_list_append (pana_session_t * dst_list,
                 pana_session_t * src_list)
{
    pana_session_t * cursor = dst_list;
    
    if (cursor == NULL) {
        return src_list;
    }
    
    while(cursor->next != NULL) {
        cursor = cursor->next;
    }

    cursor->next = src_list;

    return dst_list;
}

pana_session_t *
sess_list_insert (pana_session_t * dst_list,
                 pana_session_t * src_list)
{
    return sess_list_append(src_list, dst_list);  // :D
}

static pana_session_t * 
paa_get_session_by_sessID(uint32_t sessID){
   pana_session_t * cursor = pacs_list;
   
   for ( ; cursor != NULL ; cursor= cursor->next) {
       if (cursor->session_id == sessID) {
           return cursor;
       }
   }
   
   return NULL;
}

uint32_t paa_get_available_sess_id() {
    uint32_t out = last_sess_id + 1;
    
    while ( (paa_get_session_by_sessID(out) && out != 0) ||
            out != last_sess_id) {
        out++;
    }
    
    if (out == last_sess_id) {
        /* wrapped arround and still no free sessionID */
        DEBUG ("ALL SESSIONS ARE TAKEN (... YEAH RIGHT, ALL 2^32 of them 8X )");
        return 0;
    }
    
    return out;
}



static pana_session_t * 
paa_get_session_by_peeraddr(const ip_port_t * peer_addr) {
   pana_session_t * cursor = pacs_list;
   
   for ( ; cursor != NULL ; cursor= cursor->next) {
       if (cursor->pac_ip_port.port == peer_addr->port && 
               cursor->pac_ip_port.ip == peer_addr->ip) {
           return cursor;
       }
   }
   
   return NULL;
}

static pana_session_t * 
paa_sess_create(paa_config_t * paa_cfg, ip_port_t peer_ip_port)
{
    paa_ctx_t * ctx;
    cfg = paa_cfg;
    pana_session_t * out = NULL;
    
    out = szalloc(pana_session_t);
    out->session_id = paa_get_available_sess_id();
    out->seq_tx = os_random();
    out->ctx = szalloc(paa_ctx_t);
    
    
    ctx = out->ctx;
    ctx->paaglobal = paa_cfg;
    out->pac_ip_port = peer_ip_port;
    out->paa_ip_port = cfg->paa_pana;
    out->sa = szalloc(pana_sa_t);
    
    ctx->eap_config = get_eap_config(paa_cfg->eap_cfg);
    ctx->stats_flags = SF_CELARED;

    /* TODO */
    ctx->eap_ret = szalloc(*ctx->eap_ret);
    
    
    
    ctx->reauth_timer.enabled = FALSE;
    
//   Initialization Action:
//
//     OPTIMIZED_INIT=Set|Unset;
//     NONCE_SENT=Unset;
//     RtxTimerStop();
    
    out->cstate = PAA_STATE_INITIAL;
    OPTIMIZED_INIT_Set();
    NONCE_SENT_Unset();
    RtxTimerStop(out);
    
    out->next = NULL;
    
    return out;
}

/*
 * This funtion elliminates ione session from the global sessions list
 */
static void paa_remove_active_session(pana_session_t * sess) {
    pana_session_t * cursor, *last;
    if (!sess) {
        return;
    }
    
    cursor = pacs_list;
    while (cursor && cursor != sess) {
        last = cursor;
        cursor = cursor->next;
    }

    if (cursor != NULL) {
        last->next = cursor->next;
    } else {
        DEBUG("SESSION NOT IN SESSION LIST");
    }
}


#define generate_pana_sa() (FALSE)
#define new_key_available() (FALSE)

static bytebuff_t *
paa_process(pana_session_t * pacs, bytebuff_t * datain) {
    paa_ctx_t * ctx =  pacs->ctx;
    
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
#define RTX_COUNTER (ctx->rtx_timer.count)
#define RTX_MAX_NUM (cfg->rtx_max_count)
    
//   ----------
//   State: ANY
//   ----------
//   - - - - - - - - - - - - - (Re-transmissions)- - - - - - - - - -
//   RTX_TIMEOUT &&           Retransmit();              (no change)
//   RTX_COUNTER<
//   RTX_MAX_NUM
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if (RTX_TIMEOUT && RTX_COUNTER < RTX_MAX_NUM) {
        clear_events();
        Retransmit(pacs);
    }
//   - - - - - - - (Reach maximum number of transmissions)- - - - - -
//   (RTX_TIMEOUT &&          Disconnect();              CLOSED
//    RTX_COUNTER>=
//    RTX_MAX_NUM) ||
//   SESS_TIMEOUT
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if ((RTX_TIMEOUT && RTX_COUNTER >= RTX_MAX_NUM) || 
        SESS_TIMEOUT) {
        clear_events();
        Disconnect(pacs);
        pacs->cstate = PAA_STATE_CLOSED;
    }
    
    
    if (PKT_RECVD) {
//   -------------------------
//   State: ANY except INITIAL
//   -------------------------
//   - - - - - - - - - - (liveness test initiated by peer)- - - - - -
//   Rx:PNR[P]                Tx:PNA[P]();               (no change)
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
       if (pacs->cstate != PAA_STATE_INITIAL) {
           if (RX_PNR_P(pkt_in)) {
               /* reset the event status */
               clear_events();
               TX_PNA_P(respData, NULL);
           }
       }

//   -------------------------
//   State: ANY except WAIT_PNA_PING
//   -------------------------
//   - - - - - - - - - - - - (liveness test response) - - - - - - - -
//   Rx:PNA[P]                None();                    (no change)
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
       if (pacs->cstate != PAA_STATE_WAIT_PNA_PING){
           if (RX_PNA_P(pkt_in)) {
               clear_events();
               /* just discard the packet because it's not meant occur in this phase */
           }
       }
   }    

//   -------------------------
//   State: CLOSED
//   -------------------------
//   - - - - - - - -(Catch all event on closed state) - - - - - - - -
//   ANY                      None();                    CLOSED
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    if (pacs->cstate == PAA_STATE_CLOSED){
        clear_events();
        /* just discard the packet because it's not meant occur in this phase */
    }

    
    
    while(ctx->event_occured) {
        switch (pacs->cstate) {
//   ------------------------------
//   State: INITIAL (Initial State)
//   ------------------------------
        case  PAA_STATE_INITIAL:
//   ------------------------+--------------------------+------------
//    - - - - - - - - (PCI and PAA initiated PANA) - - - - - - - - -
//   (Rx:PCI[] ||             if (OPTIMIZED_INIT ==      INITIAL
//    PAC_FOUND)                  Set) {
//                              EAP_Restart();
//                              SessionTimerReStart
//                               (FAILED_SESS_TIMEOUT);
//                            }
//                            else {
//                              if (generate_pana_sa())
//                                   Tx:PAR[S]("PRF-Algorithm",
//                                      "Integrity-Algorithm");
//                              else
//                                   Tx:PAR[S]();
//                            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PCI(pkt_in)) {
                clear_events();
                if (OPTIMIZED_INIT) {
                    EAP_Restart(pacs);
                    SessionTimerReStart(pacs, FAILED_SESS_TIMEOUT);
                }
                else {
                    if (generate_pana_sa()) {
                        tmpavplist = AVPLIST(PAVP_PRF_ALG,"Integrity-Algorithm");
                        TX_PAR_S(respData, tmpavplist);
                    }
                    else {
                        TX_PAR_S(respData, NULL);
                    }
                }
                
                pacs->cstate = PAA_STATE_INITIAL;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_REQUEST              if (generate_pana_sa())    INITIAL
//                                Tx:PAR[S]("EAP-Payload",
//                                   "PRF-Algorithm",
//                                   "Integrity-Algorithm");
//                            else
//                                Tx:PAR[S]("EAP-Payload");
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_REQUEST) {
                clear_events();

                if (generate_pana_sa()) {
                    tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD,PAVP_PRF_ALG,"Integrity-Algorithm");
                    TX_PAR_S(respData, tmpavplist);
                }
                else{
                    tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD);
                    TX_PAR_S(respData, tmpavplist);
                }
                RtxTimerStart(pacs, respData);

                pacs->cstate = PAA_STATE_INITIAL;
            }
//   - - - - - - - - - - - - - - (PAN Handling)  - - - - - - - - - -
//   Rx:PAN[S] &&             if (PAN.exist_avp          WAIT_EAP_MSG
//   ((OPTIMIZED_INIT ==         ("EAP-Payload"))
//     Unset) ||                TxEAP();
//   PAN.exist_avp            else {
//     ("EAP-Payload"))         EAP_Restart();
//                              SessionTimerReStart
//                               (FAILED_SESS_TIMEOUT);
//                            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAN_S(pkt_in) && 
                    ((!OPTIMIZED_INIT) || exists_avp(pkt_in, PAVP_EAP_PAYLOAD))) {
                clear_events();

                if (exists_avp(pkt_in, PAVP_EAP_PAYLOAD)) {
                    TxEAP(pacs, pkt_in);
                }
                else {
                    EAP_Restart(pacs);
                    SessionTimerReStart(pacs, FAILED_SESS_TIMEOUT);

                }
                
                pacs->cstate = PAA_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   Rx:PAN[S] &&             None();                    WAIT_PAN_OR_PAR
//   (OPTIMIZED_INIT ==
//     Set) &&
//   ! PAN.exist_avp
//    ("EAP-Payload")
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAN_S(pkt_in) &&(OPTIMIZED_INIT) && 
                    !exists_avp(pkt_in, PAVP_EAP_PAYLOAD)) {
                clear_events();

                // None();

                pacs->cstate = PAA_STATE_WAIT_PAN_OR_PAR;
            } break;
//   -------------------
//   State: WAIT_EAP_MSG
//   -------------------
        case PAA_STATE_WAIT_EAP_MSG:
//   - - - - - - - - - - - -(Receiving EAP-Request)- - - - - - - - -
//   EAP_REQUEST              if (NONCE_SENT==Unset) {   WAIT_PAN_OR_PAR
//                              Tx:PAR[]("Nonce",
//                                       "EAP-Payload");
//                              NONCE_SENT=Set;
//                            }
//                            else
//                              Tx:PAR[]("EAP-Payload");
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (EAP_REQUEST) {
                clear_events();

                if (!NONCE_SENT) {
                    tmpavplist = AVPLIST(PAVP_NONCE, PAVP_EAP_PAYLOAD);
                    TX_PAR(respData, tmpavplist);
                    NONCE_SENT_Set();
                }
                else {
                              tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD);
			TX_PAR(respData, tmpavplist);
             }
                            RtxTimerStart(pacs, respData);
                
                pacs->cstate = PAA_STATE_WAIT_PAN_OR_PAR;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   - - - - - - - - - - -(Receiving EAP-Success/Failure) - - - - -
//   EAP_FAILURE              PAR.RESULT_CODE =          WAIT_FAIL_PAN
//                              PANA_AUTHENTICATION_
//                                  REJECTED;
//                            Tx:PAR[C]("EAP-Payload");
//                            RtxTimerStart();
//                            SessionTimerStop();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_FAILURE) {
                clear_events();


                tmpavplist = AVPLIST(PAVP_RESULT_AUTHENTICATION_REJECTED,
                        PAVP_EAP_PAYLOAD);
                TX_PAR_C(respData, tmpavplist);
                RtxTimerStart(pacs, respData);
                SessionTimerStop(pacs);
                
                pacs->cstate = PAA_STATE_WAIT_FAIL_PAN;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_SUCCESS &&           PAR.RESULT_CODE =          WAIT_SUCC_PAN
//   Authorize()                PANA_SUCCESS;
//                            if (new_key_available())
//                              Tx:PAR[C]("EAP-Payload",
//                                   "Key-Id");
//                            else
//                              Tx:PAR[C]("EAP-Payload");
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_SUCCESS  && Authorize(pacs)) {
                clear_events();
                

                if (new_key_available()) {
                    tmpavplist = AVPLIST(PAVP_RESULT_SUCCESS,
                            PAVP_EAP_PAYLOAD,"Key-Id");
                    TX_PAR_C(respData, tmpavplist);
                } else{
                    tmpavplist = AVPLIST(PAVP_RESULT_SUCCESS, PAVP_EAP_PAYLOAD);
                    TX_PAR_C(respData, tmpavplist);}
                RtxTimerStart(pacs, respData);

                pacs->cstate = PAA_STATE_WAIT_SUCC_PAN;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//   EAP_SUCCESS &&           PAR.RESULT_CODE =          WAIT_FAIL_PAN
//   !Authorize()               PANA_AUTHORIZATION_
//                                REJECTED;
//                            if (new_key_available())
//                              Tx:PAR[C]("EAP-Payload",
//                                   "Key-Id");
//                            else
//                              Tx:PAR[C]("EAP-Payload");
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_SUCCESS && !Authorize(pacs)) {
                clear_events();

                if (new_key_available()) {
                    tmpavplist = AVPLIST(PAVP_RESULT_AUTHORIZATION_REJECTED ,PAVP_EAP_PAYLOAD,"Key-Id");
                    TX_PAR_C(respData, tmpavplist);
                }else{
                    tmpavplist = AVPLIST(PAVP_RESULT_AUTHORIZATION_REJECTED, PAVP_EAP_PAYLOAD);
                    TX_PAR_C(respData, tmpavplist);
                }
                RtxTimerStart(pacs, respData);
                
                pacs->cstate = PAA_STATE_WAIT_FAIL_PAN;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//    - - - - - (Receiving EAP-Timeout or invalid message) - - - - -
//   EAP_TIMEOUT ||           SessionTimerStop();        CLOSED
//   EAP_DISCARD              Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_TIMEOUT || EAP_DISCARD) {
                clear_events();

                SessionTimerStop(pacs);
                Disconnect(pacs);
                
                pacs->cstate = PAA_STATE_CLOSED;
            } break;
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

//   --------------------
//   State: WAIT_SUCC_PAN
//   --------------------
        case PAA_STATE_WAIT_SUCC_PAN:
//   - - - - - - - - - - - - - (PAN Processing)- - - - - - - - - - -
//   Rx:PAN[C]                RtxTimerStop();            OPEN
//                            SessionTimerReStart
//                              (LIFETIME_SESS_TIMEOUT);
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PAN_C(pkt_in)) {
                clear_events();

                RtxTimerStop(pacs);
                SessionTimerReStart(pacs, LIFETIME_SESS_TIMEOUT);

                pacs->cstate = PAA_STATE_OPEN;
            } break;
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

//   --------------------
//   State: WAIT_FAIL_PAN
//   --------------------
        case PAA_STATE_WAIT_FAIL_PAN:
//   - - - - - - - - - - - - - - (PAN Processing)- - - - - - - - - -
//   Rx:PAN[C]                RtxTimerStop();            CLOSED
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PAN_C(pkt_in)) {
                clear_events();

                RtxTimerStop(pacs);
                Disconnect(pacs);
                
                pacs->cstate = PAA_STATE_CLOSED;
            } break;
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

//   -----------
//   State: OPEN
//   -----------
        case PAA_STATE_OPEN:
//   - - - - - - - - (re-authentication initiated by PaC) - - - - - -
//   Rx:PNR[A]                NONCE_SENT=Unset;          WAIT_EAP_MSG
//                            EAP_Restart();
//                            Tx:PNA[A]();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PNR_A(pkt_in)) {
                clear_events();

                NONCE_SENT_Unset();
                EAP_Restart(pacs);
                TX_PNA_A(respData, NULL);

                pacs->cstate = PAA_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - (re-authentication initiated by PAA)- - - - - -
//   REAUTH ||                NONCE_SENT=Unset;          WAIT_EAP_MSG
//   REAUTH_TIMEOUT           EAP_Restart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            /* will require the PaC to reauth */
            else if (REAUTH ) {
                clear_events();

                NONCE_SENT_Unset();
                EAP_Restart(pacs);
                
                pacs->cstate = PAA_STATE_WAIT_EAP_MSG;
            }
//   - - (liveness test based on PNR-PNA exchange initiated by PAA)-
//   PANA_PING                Tx:PNR[P]();               WAIT_PNA_PING
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (PANA_PING) {
                clear_events();

                TX_PNR_P(respData, NULL);
                RtxTimerStart(pacs, respData);
                
                pacs->cstate = PAA_STATE_WAIT_PNA_PING;
            }
//   - - - - - - - - (Session termination initated from PAA) - - - -
//   TERMINATE                Tx:PTR[]();                SESS_TERM
//                            SessionTimerStop();
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (TERMINATE) {
                clear_events();

                TX_PTR(respData, NULL);
                SessionTimerStop(pacs);
                RtxTimerStart(pacs, respData);
                
                pacs->cstate = PAA_STATE_SESS_TERM;
            }
//   - - - - - - - - (Session termination initated from PaC) - - - -
//   Rx:PTR[]                 Tx:PTA[]();                CLOSED
//                            SessionTimerStop();
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PTR(pkt_in)) {
                clear_events();

                TX_PTA(respData, NULL); 
                SessionTimerStop(pacs);
                Disconnect(pacs);
       
                pacs->cstate = PAA_STATE_CLOSED;
            } break;
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

//   --------------------
//   State: WAIT_PNA_PING
//   --------------------
        case PAA_STATE_WAIT_PNA_PING:
//   - - - - - - - - - - - - - -(PNA processing) - - - - - - - - - -
//   Rx:PNA[P]                RtxTimerStop();            OPEN
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PNA_P(pkt_in)) {
                clear_events();

                RtxTimerStop(pacs);
                
                pacs->cstate = PAA_STATE_OPEN;
            }
//   - - - - - - - - (re-authentication initiated by PaC) - - - - - -
//   Rx:PNR[A]                RtxTimerStop();            WAIT_EAP_MSG
//                            NONCE_SENT=Unset;
//                            EAP_Restart();
//                            Tx:PNA[A]();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PNR_A(pkt_in)) {
                clear_events();

                RtxTimerStop(pacs);
                NONCE_SENT_Unset();
                EAP_Restart(pacs);
                TX_PNA_A(respData, NULL);
                
                pacs->cstate = PAA_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - (Session termination initated from PaC) - - - -
//   Rx:PTR[]                 RtxTimerStop();            CLOSED
//                            Tx:PTA[]();
//                            SessionTimerStop();
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if ( RX_PTR(pkt_in)) {
                clear_events();

                RtxTimerStop(pacs);
                TX_PTA(respData, NULL);
                SessionTimerStop(pacs);
                Disconnect(pacs);
                
                pacs->cstate = PAA_STATE_CLOSED;
            } break;
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

//   ----------------------
//   State: WAIT_PAN_OR_PAR
//   ----------------------
        case PAA_STATE_WAIT_PAN_OR_PAR:
//   - - - - - - - - - - - - - (PAR Processing)- - - - - - - - - - -
//   Rx:PAR[]                 TxEAP();                   WAIT_EAP_MSG
//                            RtxTimerStop();
//                            Tx:PAN[]();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PAR(pkt_in)) {
                clear_events();

                TxEAP(pacs, pkt_in); 
                RtxTimerStop(pacs);
                TX_PAN(respData, NULL);
                
                pacs->cstate = PAA_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - (Pass EAP Response to the EAP authenticator)- - - -
//   Rx:PAN[] &&              TxEAP();                   WAIT_EAP_MSG
//   PAN.exist_avp            RtxTimerStop();
//   ("EAP-Payload")
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAN(pkt_in) && exists_avp(pkt_in, PAVP_EAP_PAYLOAD)) {
                clear_events();

                TxEAP(pacs, pkt_in);
                RtxTimerStop(pacs);      

                pacs->cstate = PAA_STATE_WAIT_EAP_MSG;
            }
//   - - - - - - - - - - (PAN without an EAP response) - - - - - - -
//   Rx:PAN[] &&              RtxTimerStop();            WAIT_PAN_OR_PAR
//   !PAN.exist_avp
//   ("EAP-Payload")
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (RX_PAN(pkt_in) && !exists_avp(pkt_in, PAVP_EAP_PAYLOAD)) {
                clear_events();

                RtxTimerStop(pacs);
                
                pacs->cstate = PAA_STATE_WAIT_PAN_OR_PAR;
            }
//   - - - - - - - - - - - -(EAP retransmission) - - - - - - - - - -
//   EAP_REQUEST              RtxTimerStop();            WAIT_PAN_OR_PAR
//                            Tx:PAR[]("EAP-Payload");
//                            RtxTimerStart();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_REQUEST) {
                clear_events();

                RtxTimerStop(pacs);
                tmpavplist = AVPLIST(PAVP_EAP_PAYLOAD);
                TX_PAR(respData, tmpavplist);  
                RtxTimerStart(pacs, respData);
 
                pacs->cstate = PAA_STATE_WAIT_PAN_OR_PAR;
            }
//   - - - - - - - (EAP authentication timeout or failure)- - - - -
//   EAP_FAILURE ||           RtxTimerStop();            CLOSED
//   EAP_TIMEOUT ||           SessionTimerStop();
//   EAP_DISCARD              Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            else if (EAP_FAILURE || EAP_TIMEOUT ||EAP_DISCARD ) {
                clear_events();

                RtxTimerStop(pacs); 
                SessionTimerStop(pacs);
                Disconnect(pacs);
  
                pacs->cstate = PAA_STATE_CLOSED;
            } break;
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

//   ----------------
//   State: SESS_TERM
//   ----------------
        case PAA_STATE_SESS_TERM:
//   - - - - - - - - - - - - - -(PTA processing) - - - - - - - - - -
//   Rx:PTA[]                 RtxTimerStop();            CLOSED
//                            Disconnect();
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            if (RX_PTA(pkt_in)) {
                clear_events();

                RtxTimerStop(pacs);
                Disconnect(pacs);
                
                pacs->cstate = PAA_STATE_CLOSED;
            }
//   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        
        
            /* End switch */
        }
    
    }

    
    if (respData == NULL) {
        return NULL;
    }
    
    return respData;
}







int
paa_main(const paa_config_t * const global_cfg) {
    cfg = global_cfg;
    struct sockaddr_in paa_pana_sockaddr;
    struct sockaddr_in paa_ep_sockaddr;
    struct sockaddr_in ep_sockaddr;
    int pana_sockfd;
    int ep_sockfd;
    fd_set pana_read_flags;
    fd_set ep_read_flags;
    struct timeval selnowait = {0 ,0};  //Nonblocking select
    
    struct sockaddr_in peer_addr;      // used to store the peers addres per packet
    ip_port_t peer_ip_port;      // used to store the peers addres per packet
    bytebuff_t * rxbuff = NULL;
    bytebuff_t * txbuff = NULL;
    int ret;
    
    pana_session_t * pacs;

    paa_ctx_t * ctx = NULL;

    
    bzero(&paa_pana_sockaddr, sizeof paa_pana_sockaddr);
    paa_pana_sockaddr.sin_family = AF_INET;
    paa_pana_sockaddr.sin_addr.s_addr = cfg->paa_pana.ip;
    paa_pana_sockaddr.sin_port = cfg->paa_pana.port;
    

    bzero(&paa_ep_sockaddr, sizeof paa_ep_sockaddr);
    paa_ep_sockaddr.sin_family = AF_INET;
    paa_ep_sockaddr.sin_addr.s_addr = cfg->paa_ep.ip;
    paa_ep_sockaddr.sin_port = cfg->paa_ep.port;
    
    
    bzero(&ep_sockaddr, sizeof ep_sockaddr);
    ep_sockaddr.sin_family = AF_INET;
    ep_sockaddr.sin_addr.s_addr = cfg->paa_ep.ip;
    ep_sockaddr.sin_port = cfg->paa_ep.port;
    
    if ((pana_sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return ERR_SOCK_ERROR;
    }

    if ((ep_sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return ERR_SOCK_ERROR;
    }
    

    if ((bind(pana_sockfd, &paa_pana_sockaddr, sizeof paa_pana_sockaddr)) < 0) {
        close(pana_sockfd);
        return ERR_BIND_SOCK;
    }

    if ((bind(pana_sockfd, &paa_ep_sockaddr, sizeof paa_ep_sockaddr)) < 0) {
        close(pana_sockfd);
        return ERR_BIND_SOCK;
    }

    if ((connect(ep_sockfd, &ep_sockaddr, sizeof ep_sockaddr)) < 0) {
        close(ep_sockfd);
        return ERR_CONNECT_SOCK;
    }

    /*
     * Setup the sockfds (nonblocking)
     */

    if (fcntl(pana_sockfd,F_SETFL, fcntl(pana_sockfd,F_GETFL,0) | O_NONBLOCK) == -1) {
        close(pana_sockfd);
        DEBUG("Could not set the socket as nonblocking");
        dbg_printf(ERR_SETFL_NONBLOCKING,"Could not set the socket as nonblocking");
        return ERR_NONBLOK_SOCK;
    }
    FD_ZERO(&pana_read_flags);
    FD_SET(pana_sockfd, &pana_read_flags);

    if (fcntl(ep_sockfd,F_SETFL, fcntl(ep_sockfd,F_GETFL,0) | O_NONBLOCK) == -1) {
        close(ep_sockfd);
        DEBUG("Could not set the socket as nonblocking");
        dbg_printf(ERR_SETFL_NONBLOCKING,"Could not set the socket as nonblocking");
        return ERR_NONBLOK_SOCK;
    }
    FD_ZERO(&ep_read_flags);
    FD_SET(ep_sockfd, &ep_read_flags);
    
    rxbuff = bytebuff_alloc(PANA_PKT_MAX_SIZE);

    /*
     * The PAA will keep on going
     */
    while(TRUE) {

        /*
         * While there are incoming pana packets to be processed process them.
         */
        while(select(pana_sockfd + 1, &pana_read_flags, NULL, NULL, &selnowait) > 0 &&
                FD_ISSET(pana_sockfd, &pana_read_flags)) {
            FD_CLR(pana_sockfd, &pana_read_flags);

            ret = recvfrom(pana_sockfd, bytebuff_data(rxbuff), rxbuff->size, 0,
                    &peer_addr, sizeof peer_addr);
            if (ret <= 0) {
                DEBUG(" No bytes were read");
                continue;
            }
            rxbuff->used = ret;
            dbg_asciihexdump(PANA_PKT_RECVD,"Contents:",
                    bytebuff_data(rxbuff), rxbuff->used);
            
            /*
             * TODO: program this block
             */
            peer_ip_port = saddr_in_to_ip_port(&peer_addr);
            
            if (is_PCI(rxbuff) & !paa_get_session_by_peeraddr(&peer_ip_port)) {
                pacs = paa_sess_create(cfg, peer_ip_port);
                if (pacs != NULL) {
                    pacs_list = sess_list_insert(pacs_list, pacs);
                    PKT_RECVD_Set();
                    txbuff = paa_process(pacs, rxbuff);
                    if (pacs->cstate == PAA_STATE_CLOSED) {
                        paa_remove_active_session(pacs);
                    }
                }
                else {
                    DEBUG("New session could not be created");
                }
            }
            
            
            pacs = paa_get_session_by_sessID(paa_retrieve_sessID(rxbuff));
            if (pacs != NULL) {
                if (pacs->pac_ip_port.ip == peer_ip_port.ip &&
                        pacs->pac_ip_port.port == peer_ip_port.port) {
                    PKT_RECVD_Set();
                    txbuff = paa_process(pacs, rxbuff);
                    if (pacs->cstate == PAA_STATE_CLOSED) {
                        paa_remove_active_session(pacs);
                    }

                }
                else {
                    DEBUG("!!!!!!!!!!!!!SESSION Hjacking Attempted!!!!!!!!!!!!!!!!!!");
                }
            }
            else {
                DEBUG("Wrong session requested");
            }
            
            if (txbuff != NULL) {
                dbg_asciihexdump(PANA_PKT_SENDING,"Contents:",
                        bytebuff_data(txbuff), txbuff->used);
                ret = send(pana_sockfd, bytebuff_data(txbuff), txbuff->used, 0);
                if (ret < 0 && ret != txbuff->used) {
                    /* will try at retransmission time */
                    DEBUG("There was a problem when sending the message.");
                }
                free_bytebuff(txbuff);
            }
            
            
        }

        /*
         * Then check timers for each session
         */
#define TIMER_EXPIRED(timer) ((timer).enabled && time(NULL) >= (timer).deadline)
        
    for (pacs = pacs_list; pacs != NULL; pacs = pacs->next) {
        ctx = pacs->ctx;
        if (ctx == NULL) {
            dbg_printf(MALFORMED_SESSION, "This session is missing context");
            continue;
        }
        
        if (TIMER_EXPIRED(ctx->rtx_timer)) {
            RTX_TIMEOUT_Set();
            paa_process(pacs, NULL);
            if (pacs->cstate == PAA_STATE_CLOSED) {
                paa_remove_active_session(pacs);
            }
        }
        
        if (TIMER_EXPIRED(ctx->session_timer)) {
            SESS_TIMEOUT_Set();
            paa_process(pacs, NULL);
            if (pacs->cstate == PAA_STATE_CLOSED) {
                paa_remove_active_session(pacs);
            }
        }
    }
    
    /*
     * TODO CLeanup
     */

    }
}


