/*
 * session.c
 *
 *  Created on: Apr 20, 2009
 *      Author: alex
 */

#include "utils/includes.h"
#include "utils/util.h"
#include "utils/bytebuff.h"

#include "libpana.h"
#include "packet.h"





static pana_session_t * pacs;
static pac_config_t * cfg;

typedef enum {
    PAC_STATE_CLOSED   
} pac_session_state_t;


int pac_session_init(pac_config_t * pac_cfg){
    cfg = pac_cfg;
    pacs = malloc(sizeof(pana_session_t));
    pacs->cstate = PAC_STATE_CLOSED;
    pacs->pac_ip_port = cfg->pac;
    pacs->paa_ip_port = cfg->paa;  
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

int pac_process_packet(uint8_t * datain, size_t datalen,
                   uint8_t ** resp, size_t * resplen) {
    
    int res;
    pana_packet_t * pkt_in = NULL;
    pana_packet_t * pkt_out = NULL;
    pana_avp_node_t * tmpavplist = NULL;
    pana_avp_t * tmp_avp = NULL;
    
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
            
            tmp_avp = create_avp(PAVP_V_IDENTITY, F_AVP_FLAG_VENDOR, PANA_VENDOR_UPB,
                    cfg->eap_cfg->identity, cfg->eap_cfg->identity_len);
            
            tmpavplist = avp_node_create(tmp_avp);
            
            pkt_out = construct_pana_packet(PFLAG_S | PFLAG_R,
                        PMT_PAN, pacs->session_id, pacs->seq_tx, tmpavplist);
            
            free_avp(tmp_avp);
            
        }
    }
    
}




