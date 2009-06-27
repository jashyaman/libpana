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

static inline uint16_t round_to_dwords(const uint16_t length) {
    return (length & 0xFFFC) + (length & 0x003) ? 0x0004 : 0x0000;
}

static inline uint16_t pads_to_dword(const uint16_t length) {
    /*
     * basically it finds the required padding bytes to a dword boundary
     */
    return (4 - (length & 0x003)) & 0x003;
}

static inline uint16_t bytes_to_u16 (const unsigned char * const buf) {
    //return (buf[0] << 8 | buf[1]);
    return *((uint16_t *) buf);
}

static inline uint32_t bytes_to_u32 (const unsigned char * const buf) {
    //return (buf[0] << 24 | buf[1] << 16  | buf[2] << 8 | buf[3]);
    return *((uint32_t *) buf);
}

static inline void serialize_u16 (uint8_t * out_buf, uint16_t val) {
    *(uint16_t* out_buf) = val;
}

static inline void serialize_u32 (uint8_t * out_buf, uint32_t val) {
    *(uint32_t* out_buf) = val;
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
parse_pana_packet (const uint8_t * const buf, uint16_t len,
                  pana_packet_t * out)
{
    const unsigned char * p = buf;
    pana_avp_node_t ** cursor = NULL;
    pana_avp_node_t * tmp_node = NULL;

    /*
     * Copy the fixed fields of the PANA converting each one
     * to host byte order except for the flags an reserved fields.
     */
    out->pp_reserved       = ntohs(bytes_to_u16(p + PPL_OFFSET_RESERVED));
    out->pp_message_length = ntohs(bytes_to_u16(p + PPL_OFFSET_MSG_LENGTH));
    out->pp_flags          = ntohs(bytes_to_u16(p + PPL_OFFSET_FLAGS));
    out->pp_message_type   = ntohs(bytes_to_u16(p + PPL_OFFSET_MSG_TYPE));

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

        tmp_node->node.avp_code     = ntohs(bytes_to_u16(p + PAL_OFFSET_AVP_CODE));
        tmp_node->node.avp_flags    = ntohs(bytes_to_u16(p + PAL_OFFSET_AVP_FLAGS));
        tmp_node->node.avp_length   = ntohs(bytes_to_u16(p + PAL_OFFSET_AVP_LENGTH));
        tmp_node->node.avp_reserved = ntohs(bytes_to_u16(p + PAL_OFFSET_AVP_RESERVED));

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

    serialize_u16(out + PPL_OFFSET_RESERVED,    htons(pkt->pp_reserved));
    serialize_u16(out + PPL_OFFSET_MSG_LENGTH,  htons(pkt->pp_message_length));
    serialize_u16(out + PPL_OFFSET_FLAGS,       htons(pkt->pp_flags));
    serialize_u16(out + PPL_OFFSET_MSG_TYPE,    htons(pkt->pp_message_type));
    serialize_u32(out + PPL_OFFSET_SESSION_ID,  htonl(pkt->pp_session_id));
    serialize_u32(out + PPL_OFFSET_SEQ_NUMBER,  htonl(pkt->pp_seq_number));
    out += PPL_OFFSET_AVP;

    /*
     * Start writing the AVPs
     */
    cursor = &(pkt->pp_avp_list);
    while (*cursor != NULL) {
        serialize_u16(out + PAL_OFFSET_AVP_CODE,     htons(cursor->node.avp_code));
        serialize_u16(out + PAL_OFFSET_AVP_FLAGS,    htons(cursor->node.avp_flags));
        serialize_u16(out + PAL_OFFSET_AVP_LENGTH,   htons(cursor->node.avp_length));
        serialize_u16(out + PAL_OFFSET_AVP_RESERVED, htons(cursor->node.avp_reserved));

        if (cursor->node.avp_flags | F_AVP_FLAG_VENDOR) {
            serialize_u32(out + PAL_OFFSET_AVP_VENDOR_ID, htonl(cursor->node.avp_vendor_id));
            out += PAL_OFFSET_AVP_VENDOR_VALUE;
        } else {
            out += PAL_OFFSET_AVP_VALUE;
        }

        memcpy(out, &cursor->node.avp_value, cursor->node.avp_length);
        /*
         * Pad to dword boundary
         */
        memcpy(out, PAD, pads_to_dword(cursor->node.avp_length));
        out += round_to_dwords(cursor->node.avp_length);
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
        msg_length += round_to_dwords(cursor->node.avp_length);
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

void libpana_pac_packet_handler (uint8_t * data, uint16_t length) {
    pana_packet_t tpkt;
    
    if(parse_pana_packet(data, length, &tpkt)==0) {
        pac_packet_handler(&tpkt);
    }
}

void libpana_paa_packet_handler (uint8_t * data, uint16_t length) {
    pana_packet_t tpkt;
    
    if(parse_pana_packet(data, length, &tpkt)==0) {
        paa_packet_handler(&tpkt);
    }
}


