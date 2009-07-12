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
#include "packet.h"


/* pac context data */
typedef struct pac_ctx {
    rtx_timer_t rtimer;
    uint16_t rtx_interval;
    uint8_t  rtx_max_count;
    uint8_t  reauth_interval;
} pac_ctx_t;



static pana_session_t * pacs_list;  // This will be a list of sessions
static paa_config_t * cfg;

typedef enum {
    PAC_STATE_CLOSED   
} pac_session_state_t;


int
paa_main(const paa_config_t * const global_cfg) {
    struct sockaddr_in ep_sockaddr;
    struct sockaddr_in paa_sockaddr;
    int sockfd;

    
    bzero(&paa_sockaddr, sizeof paa_sockaddr);
    paa_sockaddr.sin_family = AF_INET;
    paa_sockaddr.sin_addr.s_addr = INADDR_ANY; 
    paa_sockaddr.sin_port = htons(global_cfg->paa.port);
    
    
    bzero(&ep_sockaddr, sizeof ep_sockaddr);
    ep_sockaddr.sin_family = AF_INET;
    ep_sockaddr.sin_addr.s_addr = global_cfg->ep.ip;
    ep_sockaddr.sin_port = htons(global_cfg->ep.port);
    
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return ERR_SOCK_ERROR;
    }
    

    if ((bind(sockfd, &paa_sockaddr, sizeof paa_sockaddr)) < 0) {
        close(sockfd);
        return ERR_BIND_SOCK;
    }

    
    if ((connect(sockfd, &ep_sockaddr, sizeof ep_sockaddr)) < 0) {
        close(sockfd);
        return ERR_CONNECT_SOCK;
    }
    
    /*
     * Start the PANA session
     */
    
    close(sockfd);
}

