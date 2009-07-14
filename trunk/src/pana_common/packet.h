/*
 * packet.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef PACKET_H_
#define PACKET_H_

#include "pana_common.h"


typedef pana_avp_node_t * pana_avp_list_t;





pana_avp_t * create_avp(uint16_t code, uint16_t flags, uint32_t vendorid,
                        uint8_t * value, uint16_t length);

void free_avp (pana_avp_t * avp);

pana_avp_node_t * avp_node_create(const pana_avp_t * node);

void avp_list_destroy(pana_avp_node_t *avp_list);

pana_avp_node_t *
avp_list_append (pana_avp_node_t * dst_list,
                 pana_avp_node_t * src_list);

pana_avp_node_t *
avp_list_insert (pana_avp_node_t * dst_list,
                 pana_avp_node_t * src_list);

Boolean exists_avp(pana_packet_t * pktin, pana_avp_codes_t avpcode);

#define AVP_GET_FIRST 0
#define AVP_GET_NEXT  1


pana_avp_t * get_avp_by_code(pana_avp_list_t src, pana_avp_codes_t code, uint8_t flag);

pana_packet_t * parse_pana_packet (bytebuff_t * buff);

bytebuff_t * serialize_pana_packet (const pana_packet_t * const pkt);


pana_packet_t *
construct_pana_packet (uint16_t flags,
                       uint16_t message_type,
                       uint32_t session_id,
                       uint32_t seq_number,
                       pana_avp_node_t *avp_list);

void free_pana_packet(pana_packet_t * pkt);





#endif /* PACKET_H_ */
