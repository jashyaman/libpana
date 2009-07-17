/*
 * ep.h
 *
 *  Created on: Jul 15, 2009
 *      Author: alex
 */

#ifndef EP_H_
#define EP_H_
#include "pana_common/pana_common.h"
/* EP strucutres */

typedef enum {
    EP_COMMAND_SET = 1,
    EP_COMMAND_REVOKE = 0
} ep_command_t;

typedef struct ep_rule_s {
    uint8_t mac[6];
    uint32_t ip;
    uint8_t cmd;
    uint32_t ttl;
    
    rtimer_t rtx_timer;
} ep_rule_t;



enum {
    EP_PKT_OFFSET_ID = 0,
    EP_PKT_OFFSET_CMD = 1,
    EP_PKT_OFFSET_MAC = 2,
    EP_PKT_OFFSET_IP = 8,
    EP_PKT_OFFSET_TTL = 12,
    
    /* total length */
    EP_PKT_SIZE = 16
};

int ep_get_ack(uint8_t * pkt_in);

bytebuff_t * serialize_ep_pkt(ep_rule_t * rule, uint8_t id);

#endif /* EP_H_ */
