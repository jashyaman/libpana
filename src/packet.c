/*
 * packet.c
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <netinet/in.h>

#include <libpana.h>

static uint8_t * PAD = {0x00, 0x00, 0x00, 0x00};

static inline uint16_t ceil_to_dwords(const uint16_t length) {
    return (length & 0xFFFC) + (length & 0x003) ? 0x0040 : 0x0000;
}

static inline uint16_t pads_to_dword(const uint16_t length) {
    /*
     * basically it finds the remainder after a division by four
     * which is the value of the last 2 bits.
     */
    return (length & 0x0003)
}

static inline uint16_t bytes_to_u16 (const unsigned char * const buf) {
    //return (buf[0] << 8 | buf[1]);
    return *((uint16_t *) buf);
}

static inline uint32_t bytes_to_u32 (const unsigned char * const buf) {
    //return (buf[0] << 24 | buf[1] << 16  | buf[2] << 8 | buf[3]);
    return *((uint32_t *) buf);
}

/*
 * AVP list management functions
 */
static int avp_list_destroy(pana_avp_node_t *avp_list)
{
    pana_avp_node_t * cursor;
    pana_avp_node_t * tmp_head;

    cursor = avp_list;

    while (cursor != NULL) {
        tmp_head = cursor->next;
        free(cursor->node.avp_value);
        free(cursor);
        cursor = tmp_head;
    }

    return 0;
}

static int avp_list_append (pana_avp_node_t **dst_list,
                            pana_avp_node_t * src_list)
{
    pana_avp_node_t ** cursor = dst_list;

    while(*cursor != NULL) {
        cursor = &(*cursor->next);
    }

    *cursor = src_list;

    return 0;
}

static int avp_list_insert (pana_avp_node_t **dst_list,
                            pana_avp_node_t * src_list)
{
    pana_avp_node_t ** cursor = &src_list;

    if (src_list == NULL) {
        return 0
    }

    while(*cursor != NULL) {
        cursor = &(*cursor->next);
    }

    *cursor = *dst_list;
    *dst_list = src_list;

    return 0;
}

/*
 * Packet functions
 */

/*
 * Parse a packet from an octet-stream
 */
int
parse_pana_packet (const unsigned char * const buf, const unsigned int len,
                  pana_packet_t * out)
{
    const unsigned char * p = buf;
    pana_avp_node_t ** cursor = NULL;
    pana_avp_node_t * tmp_node = NULL;

    /*
     * Copy the fixed fields of the PANA converting each one
     * to host byte order except for the flags an reserved fields.
     */
    out->pp_reserved = bytes_to_u16(p + PPL_OFFSET_RESERVED);
    out->pp_message_length = ntohs(bytes_to_u16(p + PPL_OFFSET_MSG_LENGTH));
    out->pp_flags = bytes_to_u16(p + PPL_OFFSET_FLAGS);
    out->pp_message_type = ntohs(bytes_to_u16(p + PPL_OFFSET_MSG_TYPE));

    out->pp_session_id = ntohl(bytes_to_u32(p + PPL_OFFSET_SESSION_ID));
    out->pp_seq_number = ntohl(bytes_to_u32(p + PPL_OFFSET_SEQ_NUMBER));
    p += PPL_OFFSET_AVP;

    if (out->pp_message_length != len) {
        return -1;
    }

    /*
     * Start processing the AVP's
     */
    out->pp_avp_list = NULL;
    cursor = &(out->pp_avp_list);

    while (p < buf + len) {

        tmp_node = malloc(sizeof(pana_avp_node_t));
        if (!tmp_node) {
            return -1;
        }

        bzero(tmp_node, sizeof(pana_avp_node_t));

        tmp_node->next = NULL;
        *cursor = tmp_node;
        cursor = &(*cursor->next);

        tmp_node->node.avp_code = ntohs(bytes_to_u16(p + PAL_OFFSET_AVP_CODE));
        tmp_node->node.avp_flags = bytes_to_u16(p + PAL_OFFSET_AVP_FLAGS);
        tmp_node->node.avp_length = ntohs(bytes_to_u16(p + PAL_OFFSET_AVP_LENGTH));
        tmp_node->node.avp_reserved = bytes_to_u16(p + PAL_OFFSET_AVP_RESERVED);

        if (tmp_node->node.avp_flags | F_AVP_FLAG_VENDOR) {
            tmp_node->node.avp_vendor_id = ntohs(bytes_to_u32(p + PAL_OFFSET_AVP_VENDOR_ID));
            p += PAL_OFFSET_AVP_VENDOR_VALUE;
        } else {
            p += PAL_OFFSET_AVP_VALUE;
        }

        tmp_node->node.avp_value = malloc(tmp_node->node.avp_length);
        if (!tmp_node->node.avp_value) {
            return -1;
        }
        memcpy(tmp_node->node.avp_value, p, tmp_node->node.avp_length);

        p += tmp_node->node.avp_length;
    }

    return 0;
}

/*
 * Transform a pana_packet_t structure in a byte-stream form
 */
int
serialize_pana_packet (const pana_packet_t * const pkt,
                       unsigned char ** pout, unsigned int * len)
{
    unsigned char * out;
    pana_avp_node_t ** cursor = NULL;

    out = malloc(pkt->pp_message_length);
    if (!out) {
        return -1;
    }

    *pout = out;
    *len = pkt->pp_message_length;

    memcpy(out + PPL_OFFSET_RESERVED, pkt->pp_reserved, sizeof(uint16_t));
    memcpy(out + PPL_OFFSET_MSG_LENGTH, htons(pkt->pp_message_length), sizeof(uint16_t));
    memcpy(out + PPL_OFFSET_FLAGS, pkt->pp_flags, sizeof(uint16_t));
    memcpy(out + PPL_OFFSET_MSG_TYPE, htons(pkt->pp_message_type), sizeof(uint16_t));
    memcpy(out + PPL_OFFSET_SESSION_ID, htonl(pkt->pp_session_id), sizeof(uint32_t));
    memcpy(out + PPL_OFFSET_SEQ_NUMBER, htonl(pkt->pp_seq_number), sizeof(uint32_t));
    out += PPL_OFFSET_AVP;

    /*
     * Start writing the AVPs
     */
    cursor = &(pkt->pp_avp_list);
    while (*cursor != NULL) {
        memcpy(out + PAL_OFFSET_AVP_CODE, cursor->node.avp_code, sizeof(uint16_t));
        memcpy(out + PAL_OFFSET_AVP_FLAGS, cursor->node.avp_flags, sizeof(uint16_t));
        memcpy(out + PAL_OFFSET_AVP_LENGTH, cursor->node.avp_length, sizeof(uint16_t));
        memcpy(out + PAL_OFFSET_AVP_RESERVED, cursor->node.avp_reserved, sizeof(uint16_t));

        if (cursor->node.avp_flags | F_AVP_FLAG_VENDOR) {
            memcpy(out + PAL_OFFSET_AVP_VENDOR_ID, cursor->node.avp_vendor_id, sizeof(uint32_t));
            out += PAL_OFFSET_AVP_VENDOR_VALUE;
        } else {
            out += PAL_OFFSET_AVP_VALUE;
        }

        memcpy(out, cursor->node.avp_value, cursor->node.avp_length);
        /*
         * Pad to dword boundary
         */
        memcpy(out, PAD, pads_to_dword(cursor->node.avp_length));
        out += ceil_to_dwords(cursor->node.avp_length);
        cursor = &(*cursor->next);
    }
}

/*
 * Construct a PANA packet from fields
 */
pana_packet_t *
construct_pana_packet (uint16_t flags,
                       uint16_t message_type,
                       uint32_t session_id,
                       uint32_t seq_number,
                       pana_avp_node_t *avp_list)
{
    pana_avp_node_t ** cursor = NULL;
    pana_packet_t * out = malloc(sizeof(pana_packet_t));
    uint32_t msg_length = 0;

    if (out == NULL) {
        return NULL;
    }

    bzero(out, sizeof(pana_packet_t));
    out->pp_flags = flags;
    out->pp_message_type = message_type;
    out->pp_session_id = session_id;
    out->pp_seq_number = seq_number;
    out->pp_avp_list = avp_list;

    /*
     * Calculate the length of the message
     */
    msg_length += PPL_OFFSET_AVP;

    cursor = &avp_list;
    while (*cursor != NULL) {
        msg_length += (cursor->node.avp_flags | F_AVP_FLAG_VENDOR) ?
                PAL_OFFSET_AVP_VENDOR_VALUE : PAL_OFFSET_AVP_VALUE;
        msg_length += ceil_to_dwords(cursor->node.avp_length);
        cursor = &(*cursor->next);
    }

    out->pp_message_length = msg_length;

    return out;
}

/*
 * Frees a pana_packet_t structure
 */
int
free_pana_packet(pana_packet_t * pkt){
    avp_list_destroy(pkt->pp_avp_list);
    free(pkt);

    return 0;
}
