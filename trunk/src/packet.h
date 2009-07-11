/*
 * packet.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef PACKET_H_
#define PACKET_H_

int parse_pana_packet (uint8_t * const buf, uint16_t len,
                       pana_packet_t * out);

int serialize_pana_packet (const pana_packet_t * const pkt,
                           unsigned char ** pout, unsigned int * len);

pana_packet_t *
construct_pana_packet (uint16_t flags,
                       uint16_t message_type,
                       uint32_t session_id,
                       uint32_t seq_number,
                       pana_avp_node_t *avp_list);

int free_pana_packet(pana_packet_t * pkt);





#endif /* PACKET_H_ */
