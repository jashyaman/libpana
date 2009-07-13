/*
 * session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */

#include <sys/select.h>
#include <fcntl.h>

#include "utils/includes.h"
#include "utils/util.h"
#include "utils/bytebuff.h"

#include "libpana.h"
#include "pana_common/packet.h"
#include "pac-session.h"


/* pac context data */
typedef struct pac_ctx {
    rtimer_t rtx_timer;
    rtimer_t reauth_timer;
    pana_phase_t cphase;
    const pac_config_t * pacglobal;   //we want this to be readonly
    
    /* EAP interface */
    eap_peer_config_t * eap_config;
    eap_method_ret_t * eap_ret;
    bytebuff_t * eap_resp_payload;
    
    /* Events */
    uint32_t event_occured;
#define EV_CLEAR        0
#define EV_RX           (1 << 0)
#define EV_AUTH_USER    (1 << 1)
#define EV_EAP_RESPONSE (1 << 2)

} pac_ctx_t;





static pana_session_t * pacs;
static pac_config_t * cfg;

typedef enum {
    /* PANA_PHASE_UNITIALISED */
    PAC_STATE_INITIAL,
    
    /* PANA_PHASE_AUTH */
    PAC_STATE_AUTH_PAR_SBIT,
    PAC_STATE_WAIT_PAA,
    PAC_STATE_WAIT_EAP_MSG,
    
    /* PANA_PHASE_ACCESS */
    PAC_STATE_WAIT_PNA_PING,
    
    /* PANA_PHASE_REAUTH */
    
    /* PANA_PHASE_TERMINATE */
    PAC_STATE_TERMINATED
} pac_session_state_t;

static void pac_stop_rtx_timer() {
    ((pac_ctx_t *)(pacs->ctx))->rtx_timer.enabled = FALSE;
}

static void pac_register_for_rtx(bytebuff_t * respdata) {
    pac_ctx_t * ctx = pacs->ctx;
    pacs->pkt_cache = bytebuff_dup(respdata);
    ctx.rtx_timer.deadline = time(NULL) + cfg->rtx_interval;
    ctx.rtx_timer.count = 0;
    ctx.rtx_timer.enabled = TRUE;
}

static void pac_cache_pkt(bytebuff_t * respdata) {
    pacs->pkt_cache = bytebuff_dup(respdata);
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
    
    out_cfg->identity = strdup(cfg->identity);
    out_cfg->identity_len = cfg->identity_len;
    out_cfg->password = strdup(cfg->password);
    out_cfg->password_len = cfg->password_len;
    
    return out_cfg;
    
}

static int pac_session_init(pac_config_t * pac_cfg){
    pac_ctx_t * ctx;
    cfg = pac_cfg;
    pacs = szalloc(pana_session_t);
    pacs->ctx = szalloc(pac_ctx_t);
    
    ctx = pacs->ctx;
    pacs->cstate = PAC_STATE_INITIAL;
    pacs->pac_ip_port = cfg->pac;
    pacs->paa_ip_port = cfg->paa;
    
    ctx->pacglobal = pac_cfg;
    pac_stop_rtx_timer();
    
    ctx->reauth_timer.enabled = FALSE;
    ctx->cphase = PANA_PHASE_UNITIALISED;
    
    ctx->eap_ret = szalloc(*ctx->eap_ret);
    ctx->eap_config = get_eap_config(pac_cfg->eap_cfg);
    
    
}


static void pac_Retransmit() {
    int res;
    pac_ctx_t * ctx = pacs->ctx;

    ctx->rtx_timer.count++;
    if (pacs->pkt_cache != NULL) {
        res = send(sockfd, bytebuff_data(pacs->pkt_cache),
                pacs->pkt_cache->used, 0);
        if (res < 0 && res != pacs->pkt_cache->used) {
            DEBUG("There was a problem when sending the cached pkt");
        }
    }
    else {
        DEBUG(/* Something happened to the cached packet???*/);
    }
}

static void pac_Disconnect() {
    /* TODO: sess cleanup */
    
}

#define FAILED_SESS_TIMEOUT   (cfg->failed_sess_timeout)

static void pac_SessionTimerReStart(uint16_t timeout) {
    pac_ctx_t * ctx = pacs->ctx;
    ctx->reauth_timer.deadline = time(NULL) + timeout
    ctx->reauth_timer.enabled = TRUE;
}

static void pac_EAP_Restart() {
    /* MD5 has no special requirements to restart */
}

static void pac_TxEAP(pana_packet_t * pktin) {
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
    
    ctx->eap_resp_payload = bytebuff_from_bytes(wpabuf_head_u8(eap_resp),
                                                eap_resp->used);
    wpabuf_free(eap_resp);
    
    ctx->event_occured |= EV_EAP_RESPONSE;
    
}

static void pac_eap_piggyback() {
    /* This MD5 does not wait for user input */
    return TRUE;
}


static bytebuff_t * create_PCI() {
    
    pana_packet_t *outpkt;
    bytebuff_t * ret;
    
    outpkt = construct_pana_packet(PFLAGS_NONE, PMT_PCI, 0, 0, NULL);
    if (outpkt == NULL) {
        return NULL;
    }

    ret = serialize_pana_packet(outpkt);
    free_pana_packet(outpkt);
    
    return ret;
}

static bytebuff_t *
pac_process_packet(bytebuff_t * datain) {
    pac_ctx_t * ctx =  pacs->ctx;
    pac_config_t * pacglobal = ctx->pacglobal;
    
    bytebuff_t * respdata;
    pana_packet_t * pkt_in = NULL;
    pana_packet_t * pkt_out = NULL;
    pana_avp_node_t * tmpavplist = NULL;
    pana_avp_t * tmp_avp = NULL;
    
    
    if (datain != NULL) {
        dbg_hexdump(PKT_RECVD, "Packet-contents:", bytebuff_data(datain), datain->size);
        pkt_in = parse_pana_packet(datain);
        if (pkt_in == NULL) {
            dbg_printf(MSG_ERROR,"Packet is invalid");
            ctx->event_occured = EV_CLEAR;
            return NULL;
        }
    }
    
    /*
   State: ANY except INITIAL
   - - - - - - - - - - (liveness test initiated by peer)- - - - - -
   Rx:PNR[P]                Tx:PNA[P]();               (no change)
     */
    if (pacs->cstate != PAC_STATE_INITIAL) {
        if (RX_PNR_P(pkt_in)) {
            TX_PNA_P(pkt_out, NULL);
            respdata = serialize_pana_packet(pkt_out);
            /* reset the event status */
            ctx->event_occured = FALSE;
        }
    }
    
    
    /*
   State: ANY except WAIT_PNA_PING
   ------------------------+--------------------------+------------
   - - - - - - - - - - - - (liveness test response) - - - - - - - -
   Rx:PNA[P]                None();                    (no change)
     */
    if (pacs->cstate != PAC_STATE_WAIT_PNA_PING){
        if (RX_PNA_P(pkt_in)) {
            /* just discard the packet because it's not meant occur in this phase */
            ctx->event_occured = FALSE;
        }
    }
    
    /*
   State: CLOSED
   ------------------------+--------------------------+------------
   - - - - - - - -(Catch all event on closed state) - - - - - - - -
   ANY                      None();                    CLOSED
     */

    if (pacs->cstate == PAC_STATE_CLOSED){
        /* just discard the packet because it's not meant occur in this phase */
        ctx->event_occured = FALSE;
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
            if (ctx->event_occured | EV_AUTH_USER) {
                ctx->event_occured = EV_CLEAR;
                TX_PCI(pkt_out, NULL);
                respdata = serialize_pana_packet(pkt_out);
                pac_register_for_rtx(respdata);
                pac_SessionTimerReStart(FAILED_SESS_TIMEOUT);
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
                ctx->event_occured = EV_CLEAR;
                pac_EAP_Restart();
                pac_SessionTimerReStart(FAILED_SESS_TIMEOUT);
                /* MD5 does not generate MSK so no pana_sa needed */
                TX_PAN_S(pkt_out, NULL);
                respdata = serialize_pana_packet(pkt_out);
                pacs->cstate = PAC_STATE_WAIT_PAA;                
            }
//   - - - - - - - -(PAA-initiated Handshake, optimized) - - - - - -
//   Rx:PAR[S] &&             EAP_Restart();             INITIAL
//   PAR.exists_avp            TxEAP();
//   ("EAP-Payload") &&       SessionTimerReStart
//   eap_piggyback()            (FAILED_SESS_TIMEOUT);
            else if (RX_PAR_S(pkt_in) && exists_avp(pkt_in, PAVP_EAP_PAYLOAD) && 
                    pac_eap_piggyback()) {
                ctx->event_occured = EV_CLEAR;
                pac_EAP_Restart();
                pac_TxEAP(pkt_in);
                pac_SessionTimerReStart(FAILED_SESS_TIMEOUT);
                pacs->cstate = PAC_STATE_INITIAL;
            }
            
//   Rx:PAR[S] &&             EAP_Restart();             WAIT_EAP_MSG
//   PAR.exists_avp            TxEAP();
//   ("EAP-Payload") &&       SessionTimerReStart
//   !eap_piggyback()           (FAILED_SESS_TIMEOUT);
//                            if (generate_pana_sa())
//                                Tx:PAN[S]("PRF-Algorithm",
//                                  "Integrity-Algorithm");
//                            else
//                                Tx:PAN[S]();
            /*
             * WARNING: This is not working well in this current implementation.
             */
            else if (RX_PAR_S(pkt_in) && exists_avp(pkt_in, PAVP_EAP_PAYLOAD) &&
                    !pac_eap_piggyback()) {
                ctx->event_occured = EV_CLEAR;
                pac_EAP_Restart();
                pac_TxEAP(pkt_in);
                pac_SessionTimerReStart(FAILED_SESS_TIMEOUT);
                /* MD5 Does not generate pana_sa */
                TX_PAN_S(pkt_out, NULL);
                pacs->cstate = PAC_STATE_WAIT_EAP_MSG;
            }
//   EAP_RESPONSE             if (generate_pana_sa())    WAIT_PAA
//                                Tx:PAN[S]("EAP-Payload",
//                                  "PRF-Algorithm",
//                                  "Integrity-Algorithm");
//                            else
//                                Tx:PAN[S]("EAP-Payload");
            else if (ctx->event_occured | EV_EAP_RESPONSE) {
                ctx->event_occured = EV_CLEAR;
                /* No pana_sa will be generate */
                tmp_avp = create_avp(PAVP_EAP_PAYLOAD, F_AVP_FLAG_CLEARED, 0,
                                     bytebuff_data(ctx->eap_resp_payload),
                                     ctx->eap_resp_payload.used);
                                     
                tmpavplist = avp_node_create(tmp_avp);
                TX_PAN_S(pkt_out, tmpavplist);
                respdata = serialize_pana_packet(pkt_out);
                
                free_avp(tmp_avp);
                free_pana_packet(pkt_out);
                
                pacs->cstate = PAC_STATE_WAIT_PAA;
            }
            break;

        
        
            
            
//        /*
//         * State is uninitialised. The PCI was sent and an aswer has returned.
//         */
//        case PAC_STATE_CLOSED:
//            if (pkt_in->pp_message_type == PMT_PAR &&
//                    pkt_in->pp_flags & (PFLAG_S | PFLAG_R)) {
//                pac_stop_rtx_timer();
//                pacs->session_id = pkt_in->pp_session_id;
//                pacs->seq_rx = pkt_in -> pp_seq_number;
//                pacs->seq_tx = os_random();
//
//                tmp_avp = create_avp(PAVP_V_IDENTITY, F_AVP_FLAG_VENDOR, PANA_VENDOR_UPB,
//                        cfg->eap_cfg->identity, cfg->eap_cfg->identity_len);
//
//                tmpavplist = avp_node_create(tmp_avp);
//                free_avp(tmp_avp);
//
//                /* PRF & INT_ALG are not set because MD5 does'nt export a MSK*/
//
//                pkt_out = construct_pana_packet(PFLAG_S, PMT_PAN,
//                        pacs->session_id, pacs->seq_tx, tmpavplist);
//
//
//                respdata = serialize_pana_packet(pkt_out);
//
//                pac_cache_pkt(respdata);
//                free_pana_packet(pkt_out);
//
//                /* Change the state */
//                ctx->cphase = PANA_PHASE_AUTH;
//                pacs->cstate = PAC_STATE_AUTH_PAR_SBIT;
//            };
//            break;
//        case 

        }
    
    }

    
    if (respdata == NULL) {
        return NULL;
    }
    
    ctx->rtx_timer.count++;
    ctx->rtx_timer.deadline = time(NULL) + pacglobal->rtx_interval;
    ctx->rtx_timer.enabled = TRUE;
    
    
    return respdata;
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
    
    pac_ctx_t * ctx =  pacs->ctx;
    

    
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
       
    if (fcntl(sockfd,F_SETFL, fcntl(sockfd,F_GETFL,0) | O_NONBLOCK) < 1) {
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
    
    txbuff = create_PCI();
    if (txbuff != NULL) {
        send(sockfd, bytebuff_data(txbuff), txbuff->used, 0);
        pac_register_for_rtx(txbuff);
        free_bytebuff(txbuff);
    }
    
    rxbuff = bytebuff_alloc(PANA_PKT_MAX_SIZE);
    while(pacs->cstate != PAC_STATE_TERMINATED) {
        
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

            txbuff = pac_process_packet(rxbuff);
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
        
        
        /* 
         * Check rtx_timer
         */
        
 /*
   - - - - - - - - - - - - - (Re-transmissions)- - - - - - - - - -
   RTX_TIMEOUT &&           Retransmit();              (no change)
   RTX_COUNTER<
   RTX_MAX_NUM
 */
        if (ctx->rtx_timer.enabled && time(NULL) >= ctx->rtx_timer.deadline
                && ctx->rtx_timer.count < cfg->rtx_max_count) {
            pac_Retransmit();
            
        }
        
/*
   - - - - - - - (Reach maximum number of transmissions)- - - - - -
   (RTX_TIMEOUT &&          Disconnect();              CLOSED
    RTX_COUNTER>=
    RTX_MAX_NUM) ||
   SESS_TIMEOUT
   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
*/
        if (ctx->rtx_timer.enabled && time(NULL) >= ctx->rtx_timer.deadline
                && ctx->rtx_timer.count >= cfg->rtx_max_count) {
            pac_Disconnect();
            
        }
        
        /*
         * Check reauth and start the procedure if required
         */
        if (ctx->reauth_timer.enabled && ctx->reauth_timer.deadline > time(NULL) &&
                ctx->cphase == PANA_PHASE_ACCESS) {
            pacs->
            
        }
        
        
        
    }
    
    close(sockfd);
}


