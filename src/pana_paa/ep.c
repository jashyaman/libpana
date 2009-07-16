/*
 * ep.c
 *
 *  Created on: Jul 15, 2009
 *      Author: alex
 */

/* EP Packet construction and processing */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include "utils/util.h"
#include "utils/bytebuff.h"
#include "ep.h"

int ep_get_ack(uint8_t * pkt_in){
    if (!pkt_in) {
        return -1;
    }
    return pkt_in[0];
}

bytebuff_t * serialize_ep_pkt(ep_rule_t * rule, uint8_t id) {
    bytebuff_t * out = NULL;
    if (!rule) {
        return NULL;
    }
    
    if (!(out = bytebuff_alloc(EP_PKT_SIZE))) {
        return NULL;
    }
    buff_insert_u8(bytebuff_data(out) + EP_PKT_OFFSET_ID, id);
    buff_insert_u8(bytebuff_data(out) + EP_PKT_OFFSET_CMD, rule->cmd);
    memcpy(bytebuff_data(out) + EP_PKT_OFFSET_MAC,
            rule->mac, sizeof rule->mac);
    buff_insert_be32(bytebuff_data(out) + EP_PKT_OFFSET_IP, rule->ip);
    buff_insert_be32(bytebuff_data(out) + EP_PKT_OFFSET_TTL, rule->ttl);
    
    out->used = EP_PKT_SIZE;
    return out;
    
}
