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


/* pac context data */
typedef struct pac_ctx {
    rtx_timer_t rtimer;
    const pac_config_t * pacglobal;   //we want this to be readonly
} pac_ctx_t;



static pana_session_t * pacs;
static pac_config_t * cfg;

typedef enum {
    PAC_STATE_CLOSED,
    PAC_STATE_TERMINATED
} pac_session_state_t;


int pac_session_init(pac_config_t * pac_cfg){
    pac_ctx_t * ctx;
    cfg = pac_cfg;
    pacs = szalloc(pana_session_t);
    pacs->ctx = szalloc(pac_ctx_t);
    
    ctx = pacs->ctx;
    pacs->cstate = PAC_STATE_CLOSED;
    pacs->pac_ip_port = cfg->pac;
    pacs->paa_ip_port = cfg->paa;
    
    ctx->pacglobal = pac_cfg;
    ctx->rtimer.enabled = FALSE;
    
    
}

bytebuff_t * create_PCI() {
    
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

bytebuff_t *
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
    }
    
    switch(pacs->cstate) {
    case PAC_STATE_CLOSED:
        if (pkt_in->pp_message_type == PMT_PAR &&
                pkt_in->pp_flags & (PFLAG_S | PFLAG_R)) {
            pacs->session_id = pkt_in->pp_session_id;
            pacs->seq_rx = pkt_in -> pp_seq_number;
            pacs->seq_tx = os_random();
            
            tmp_avp = create_avp(PAVP_V_IDENTITY, F_AVP_FLAG_VENDOR, PANA_VENDOR_UPB,
                    cfg->eap_cfg->identity, cfg->eap_cfg->identity_len);
            
            tmpavplist = avp_node_create(tmp_avp);
            
            pkt_out = construct_pana_packet(PFLAG_S | PFLAG_R,
                        PMT_PAN, pacs->session_id, pacs->seq_tx, tmpavplist);
            
            free_avp(tmp_avp);
            
            respdata = serialize_pana_packet(pkt_out);
            free_pana_packet(pkt_out);
        }
    }
    
    if (respdata == NULL) {
        return NULL;
    }
    
    if (pacs->pkt_cache) {
        free(pacs->pkt_cache);
    }
    pacs->pkt_cache = bytebuff_dup(respdata);

    ctx->rtimer.count++;
    ctx->rtimer.deadline = time(NULL) + pacglobal->rtx_interval;
    ctx->rtimer.enabled = TRUE;
    
    
    
}

int
pac_main(const pac_config_t * const global_cfg) {
    cfg = global_cfg;
    struct sockaddr_in pac_sockaddr;
    struct sockaddr_in nas_sockaddr;
    int sockfd;
    fd_set read_flags;
    struct timeval selwait = {0 ,0};  //Nonblocking select
    bytebuff_t * tmpbuff = NULL;

    
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
    
    tmpbuff = create_PCI();
    if (tmpbuff != NULL) {
        send(sockfd, bytebuff_data(tmpbuff), tmpbuff->used, 0);
        free_bytebuff(tmpbuff);
    }
    
    while(pacs->cstate != PAC_STATE_TERMINATED) {
        while(select(sockfd + 1, &read_flags, NULL, NULL, NULL) > 0) {
            
        }
        /* while pkts available() {
         *      out_pkt = process_pkt(pkt_in)
         *      if (outpkt != NULL) {
         *      send(outpkt)
         *  }
         */ 
        /* check rtx_timers -> if deadline expired RTX() */
        
        
    }
    
    close(sockfd);
}




