/*
 * session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */

#include "libpana.h"
#include "packet.h"
#include "utils/util.h"

static pana_session_t * pacs;

typedef enum {
    PAC_STATE_CLOSED   
} pac_session_state_t;


int pac_session_init(ip_port_t * pac, ip_port_t * paa){
    pacs = malloc(sizeof(pana_session_t));
    pacs->cstate = PAC_STATE_CLOSED;
    pacs->pac_ip_port = *pac;
    pacs->paa_ip_port = *paa;  
}

int create_PCI(uint8_t ** pciout, size_t * outlen) {
    
    pana_packet_t *outpkt;
    int ret;
    
    outpkt = construct_pana_packet(PFLAGS_NONE, PMT_PCI, 0, 0, NULL);
    if (outpkt == NULL) {
        return -1;
    }
    
    ret = serialize_pana_packet(outpkt, pciout, outlen);
    
    return ret;
}

int process_packet(uint8_t * datain, size_t datalen,
                   uint8_t ** resp, size_t * resplen) {
    
    int res;
    pana_packet_t * pkt_in;
    
    res = parse_pana_packet(datain, datalen, pkt_in);
    if (res < 0) {
        dbg_printf(MSG_ERROR,"Pachet is invalid");
    }
    
    switch(pacs->cstate) {
    case PAC_STATE_CLOSED:
        if (pkt_in->pp_message_type == PMT_PAR &&
                pkt_in->pp_flags & (PFLAG_S | PFLAG_R)) {
            pacs->session_id = pkt_in->pp_session_id;
            pacs->seq_rx = pkt_in -> pp_seq_number;
            pacs->seq_tx = os_random();
            
        }
    }
    
}




