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
    
    /* Events */
    Boolean event_occured;
} pac_ctx_t;



static pana_session_t * pacs;
static pac_config_t * cfg;

typedef enum {
    /* PANA_PHASE_UNITIALISED */
    PAC_STATE_INITIAL,
    
    /* PANA_PHASE_AUTH */
    PAC_STATE_AUTH_PAR_SBIT,
    
    /* PANA_PHASE_ACCESS */
    PAC_STATE_WAIT_PNA_PING
    
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
    
    
    
    dbg_hexdump(PKT_RECVD, "Packet-contents:", bytebuff_data(datain), datain->size);
    pkt_in = parse_pana_packet(datain);
    if (pkt_in == NULL) {
        dbg_printf(MSG_ERROR,"Packet is invalid");
        return NULL;
    }
    
    /*
   State: ANY except INITIAL
   - - - - - - - - - - (liveness test initiated by peer)- - - - - -
   Rx:PNR[P]                Tx:PNA[P]();               (no change)
     */
    if (pacs->cstate != PAC_STATE_INITIAL) {
        if (RX_PNR_P(pkt_in)) {
            TX_PNA_P()
        }
    }
    
    
    while(ctx->event_occured) {

        switch(pacs->cstate) {
        /*
         * State is uninitialised. The PCI was sent and an aswer has returned.
         */
        case PAC_STATE_CLOSED:
            if (pkt_in->pp_message_type == PMT_PAR &&
                    pkt_in->pp_flags & (PFLAG_S | PFLAG_R)) {
                pac_stop_rtx_timer();
                pacs->session_id = pkt_in->pp_session_id;
                pacs->seq_rx = pkt_in -> pp_seq_number;
                pacs->seq_tx = os_random();

                tmp_avp = create_avp(PAVP_V_IDENTITY, F_AVP_FLAG_VENDOR, PANA_VENDOR_UPB,
                        cfg->eap_cfg->identity, cfg->eap_cfg->identity_len);

                tmpavplist = avp_node_create(tmp_avp);
                free_avp(tmp_avp);

                /* PRF & INT_ALG are not set because MD5 does'nt export a MSK*/

                pkt_out = construct_pana_packet(PFLAG_S, PMT_PAN,
                        pacs->session_id, pacs->seq_tx, tmpavplist);


                respdata = serialize_pana_packet(pkt_out);

                pac_cache_pkt(respdata);
                free_pana_packet(pkt_out);

                /* Change the state */
                ctx->cphase = PANA_PHASE_AUTH;
                pacs->cstate = PAC_STATE_AUTH_PAR_SBIT;
            };
            break;
        case 

        }
    
    }

    
    if (respdata == NULL) {
        return NULL;
    }
    
    if (pacs->pkt_cache) {
        free(pacs->pkt_cache);
    }
    pacs->pkt_cache = bytebuff_dup(respdata);

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
    
}

