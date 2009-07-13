/*
 * paa-session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */


#include "utils/includes.h"
#include "utils/util.h"
#include "utils/bytebuff.h"

#include "libpana.h"
#include "pana_common/packet.h"


/* pac context data */
typedef struct paa_ctx {
    rtimer_t rtimer;
    const paa_config_t * paaglobal;   //we want this to be readonly
} paa_ctx_t;


typedef struct pana_session_node_s {
    pana_session_t node;
    struct pana_session_node_s * next;
}pana_session_node_t;

static pana_session_node_t * pacs_list;  // This will be a list of sessions
static paa_config_t * cfg;
static uint32_t last_sessid = 0;

typedef enum {
    PAC_STATE_CLOSED,
    PAC_STATE_PCI_RECVD
} pac_session_state_t;

static pana_session_t * get_session_by_srcaddr(ip_port_t * srcaddr) {
    pana_session_node_t * cursor = pacs_list;
    for (cursor ; cursor != NULL ; cursor = cursor->next) {
        if (cursor->node.pac_ip_port.ip == srcaddr->ip &&
                cursor->node.pac_ip_port.port == srcaddr->port) {
            return &(cursor->node);
        }
    }
    return NULL;
}

static pana_session_t * get_session_by_sessid(uint32_t sessid) {
    pana_session_node_t * cursor = pacs_list;
    for (cursor ; cursor != NULL ; cursor = cursor->next) {
        if (cursor->node.session_id == sessid) {
            return &(cursor->node);
        }
    }
    return NULL;
}


static uint32_t find_free_sessid() {
    while (get_session_by_sessid(++last_sessid)) {
        /* NOTHING, the last_sess_is is already incremented*/
    }
    return last_sessid;
}

/* create a session for each new client */

pana_session_t * pac_session_create(ip_port_t * srcaddr) {
    pana_session_t * out = NULL;
    paa_ctx_t * ctx;
    
    out = szalloc(pana_session_t);
    if (out == NULL) {
        return NULL;
    }
    
    out->ctx = szalloc(paa_ctx_t);
    if (out->ctx == NULL) {
        free(out);
        return NULL;
    }
    ctx = out->ctx;
    ctx->paaglobal = cfg;
    out->cstate = PAC_STATE_PCI_RECVD;
    out->paa_ip_port = cfg->paa;
    out->seq_tx = random();
    last_sessid = find_free_sessid();
    out->session_id = last_sessid;
    //out

}




bytebuff_t * 
paa_process_packet(bytebuff_t * datain, ip_port_t * srcaddr) {
    pana_packet_t * inpkt = NULL;
    
    inpkt = parse_pana_packet(datain);
    if (inpkt == NULL){
        dbg_printf(BAD_PKT, "Invalid packet recieved. Dropped");
        return NULL;
    }
    
    /* check to see if it's a PCI pkt */
    if (inpkt->pp_flags == PFLAGS_NONE && inpkt->pp_message_type == PMT_PCI) {
        /* check to see if this client is'n alredy registered */
        if (get_session_by_srcaddr(srcaddr)) {
            dbg_printf(BAD_PKT, "Malformed PCI recieved from client alredy registerd.");
            free_pana_packet(inpkt);
            return NULL;            
        }
        /* This is a new cleint so a seesion should be created for him */
        
    }
    
}


int
paa_main(const paa_config_t * const global_cfg) {
    /* two comms -> 2 sockfd */
    struct sockaddr_in ep_sockaddr;
    struct sockaddr_in paa_sockaddr;
    int pana_sockfd;
    int ep_sockfd;

    
    bzero(&paa_sockaddr, sizeof paa_sockaddr);
    paa_sockaddr.sin_family = AF_INET;
    paa_sockaddr.sin_addr.s_addr = INADDR_ANY; 
    paa_sockaddr.sin_port = htons(global_cfg->paa.port);
    
    
    bzero(&ep_sockaddr, sizeof ep_sockaddr);
    ep_sockaddr.sin_family = AF_INET;
    ep_sockaddr.sin_addr.s_addr = global_cfg->ep.ip;
    ep_sockaddr.sin_port = htons(global_cfg->ep.port);
    
    if ((pana_sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return ERR_SOCK_ERROR;
    }
    

    if ((bind(pana_sockfd, &paa_sockaddr, sizeof paa_sockaddr)) < 0) {
        close(pana_sockfd);
        return ERR_BIND_SOCK;
    }

    
    if ((connect(pana_sockfd, &ep_sockaddr, sizeof ep_sockaddr)) < 0) {
        close(pana_sockfd);
        return ERR_CONNECT_SOCK;
    }
    
    /*
     * Start the PANA session
     */
    while (TRUE) {
        /* while pkts available() {
         *      out_pkt = process_pkt(pkt_in)
         *      if (outpkt != NULL) -> send(outpkt)
         *      if (authorized) -> send_toacl;
         *      if (revoke) -> send_toacl;
         *      
         *      
         *  }
         */ 
        /* iterate through rtx_imers -> if (EXPIRED) {
         *                      RTX()
         *  } 
         */
        /* while acks_availabel() {
         *      process_ack() -> remove from ep_rtx_queue
         * }
         * iterate through ep_timers {rtx-req}
         */
        
        
        /*
         * req:
         * ID(1) | CMD(1) | IP(4) | MAC(6) | TTL(4)
         * ack:
         * ID(1)
         */
        
        
        
    }
    
    close(pana_sockfd);
}

