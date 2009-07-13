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


#include "../include/libpana.h"
#include "packet.h"

static uint8_t PAD[4] = {0x00, 0x00, 0x00, 0x00};

static inline uint16_t round_to_dwords(const uint16_t length) {
    return (length & 0xFFFC) + (length & 0x003) ? 0x0004 : 0x0000;
}

static inline uint16_t pads_to_dword(const uint16_t length) {
    /*
     * basically it finds the required padding bytes to a dword boundary
     */
    return (4 - (length & 0x003)) & 0x003;
}


/*
 * AVP list management functions
 */
pana_avp_t * create_avp(uint16_t code, uint16_t flags, uint32_t vendorid,
                        uint8_t * value, uint16_t length) {
    pana_avp_t * out = smalloc(pana_avp_t);
    if (out == NULL) {
        return NULL;
    }
    out->avp_code = code;
    out->avp_flags = flags;
    out->avp_vendor_id = vendorid;
    out->avp_value = value;
    out->avp_length = length;  
}

void free_avp (pana_avp_t * avp) {
    if (avp == NULL) {
        return;
    }
    
    if (avp->avp_value != NULL) {
        free(avp->avp_value);
    }
    free(avp);
}

pana_avp_node_t * avp_node_create(const pana_avp_t * node) {
    pana_avp_node_t * out = smalloc(pana_avp_node_t);
    if (out == NULL) {
        return NULL;
    }
    out->node = *node;
    out->next = NULL;
    return out;
}

void avp_list_destroy(pana_avp_node_t *avp_list)
{
    pana_avp_node_t * cursor;
    pana_avp_node_t * tmp_head;

    cursor = avp_list;

    while (cursor != NULL) {
        tmp_head = cursor->next;
        if (cursor->node.avp_value != NULL) {
            free(cursor->node.avp_value);
        }
        free(cursor);
        cursor = tmp_head;
    }
}

/*
 * WARNING: these functions do not change the pointers srclist & dstlist.
 * They shoul be used as 
 *      dstlist = avp_list_append(dstlist,srclist);
 *      dstlist = avp_list_insert(dstlist,srclist);
 */
pana_avp_node_t *
avp_list_append (pana_avp_node_t * dst_list,
                 pana_avp_node_t * src_list)
{
    pana_avp_node_t * cursor = dst_list;
    
    if (cursor == NULL) {
        return src_list;
    }
    
    while(cursor->next != NULL) {
        cursor = cursor->next;
    }

    cursor->next = src_list;

    return dst_list;
}

pana_avp_node_t *
avp_list_insert (pana_avp_node_t * dst_list,
                 pana_avp_node_t * src_list)
{
    return avp_list_append(src_list, dst_list);  // :D
}

static pana_avp_list get_avp_last_pos = NULL;

pana_avp_t * get_avp_by_code(pana_avp_list src, pana_avp_codes_t code, uint8_t flag) {
    pana_avp_t * resp = NULL;
    pana_avp_node_t * cursor;

    if (flag == AVP_GET_NEXT) {
        cursor = get_avp_last_pos;
    }
    else if (flag == AVP_GET_FIRST) {
        cursor = src;
    }
    else {
        return NULL;
    }
    
    for (cursor; cursor != NULL; cursor = cursor->next) {
        if (cursor->node.avp_code == code) {
            get_avp_last_pos = cursor->next;
            return &(cursor->node);
        }
    }
    
    /* no matching AVP remained */
    get_avp_last_pos = NULL;
}

/*
 * Packet functions
 */

Boolean exists_avp(pana_packet_t * pktin, pana_avp_codes_t avpcode) {
    pana_avp_node_t * cursor;
    if (pktin == NULL || pktin->pp_avp_list == NULL) {
        return FALSE;
    }
    
    cursor = pktin->pp_avp_list;
    for (cursor ; cursor !=NULL ; cursor = cursor->next) {
        if (cursor->node.avp_code == avpcode) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Parse a packet from an octet-stream
 */
pana_packet_t *
parse_pana_packet (bytebuff_t * buff)
{
    const uint8_t * sx = NULL;
    const uint8_t * px = NULL;
    pana_avp_node_t * tmpavplist = NULL;
    pana_avp_node_t * tmp_node = NULL;
    pana_packet_t * out = NULL;
    
    
    if (buff == NULL) {
        return NULL;
    }
    
    px = bytebuff_data(buff);
    sx = px;
    
    out = malloc(sizeof(pana_packet_t));
    if (out == NULL) {
        return NULL;
    }
    
    /*
     * Copy the fixed fields of the PANA converting each one
     * to host byte order except for the flags an reserved fields.
     */
    out->pp_reserved       = bytes_to_be16(px + PPL_OFFSET_RESERVED);
    out->pp_message_length = bytes_to_be16(px + PPL_OFFSET_MSG_LENGTH);
    out->pp_flags          = bytes_to_be16(px + PPL_OFFSET_FLAGS);
    out->pp_message_type   = bytes_to_be16(px + PPL_OFFSET_MSG_TYPE);

    out->pp_session_id = bytes_to_be32(px + PPL_OFFSET_SESSION_ID);
    out->pp_seq_number = bytes_to_be32(px + PPL_OFFSET_SEQ_NUMBER);
    px += PPL_OFFSET_AVP;

    if (out->pp_message_length != buff->used) {
        free(out);
        return NULL;
    }

    /*
     * Start processing the AVP's
     */
    out->pp_avp_list = NULL;
    

    while (px < sx + buff->used) {

        tmp_node = szalloc(pana_avp_node_t);
        if (!tmp_node) {
            avp_list_destroy(tmpavplist);
            free(out);
            return NULL;
        }

        tmp_node->next = NULL;

        tmp_node->node.avp_code     = bytes_to_be16(px + PAL_OFFSET_AVP_CODE);
        tmp_node->node.avp_flags    = bytes_to_be16(px + PAL_OFFSET_AVP_FLAGS);
        tmp_node->node.avp_length   = bytes_to_be16(px + PAL_OFFSET_AVP_LENGTH);
        tmp_node->node.avp_reserved = bytes_to_be16(px + PAL_OFFSET_AVP_RESERVED);

        if (tmp_node->node.avp_flags & FAVP_FLAG_VENDOR) {
            tmp_node->node.avp_vendor_id = ntohs(bytes_to_be32(px + PAL_OFFSET_AVP_VENDOR_ID));
            px += PAL_OFFSET_AVP_VENDOR_VALUE;
        } else {
            px += PAL_OFFSET_AVP_VALUE;
        }

        tmp_node->node.avp_value = malloc(tmp_node->node.avp_length);
        if (tmp_node->node.avp_value == NULL) {
            free(tmp_node);
            avp_list_destroy(tmpavplist);
            return NULL;
        }
        memcpy(tmp_node->node.avp_value, px, tmp_node->node.avp_length);
        tmpavplist = avp_list_insert(tmpavplist, tmp_node);

        px += tmp_node->node.avp_length;
    }

    return 0;
}

/*
 * Transform a pana_packet_t structure in a byte-stream form
 */
bytebuff_t *
serialize_pana_packet (const pana_packet_t * const pkt)
{
    bytebuff_t * out;
    uint8_t * pos;
    pana_avp_node_t * cursor = NULL;
    
    if (pkt == NULL) {
        return NULL;
    }

    out = bytebuff_alloc(pkt->pp_message_length);
    if (out == NULL) {
        return NULL;
    }

    pos = bytebuff_data(out);
    pkt->pp_message_length;

    buff_insert_be16(pos + PPL_OFFSET_RESERVED,    pkt->pp_reserved);
    buff_insert_be16(pos + PPL_OFFSET_MSG_LENGTH,  pkt->pp_message_length);
    buff_insert_be16(pos + PPL_OFFSET_FLAGS,       pkt->pp_flags);
    buff_insert_be16(pos + PPL_OFFSET_MSG_TYPE,    pkt->pp_message_type);
    buff_insert_be32(pos + PPL_OFFSET_SESSION_ID,  pkt->pp_session_id);
    buff_insert_be32(pos + PPL_OFFSET_SEQ_NUMBER,  pkt->pp_seq_number);
    pos += PPL_OFFSET_AVP;

    /*
     * Start writing the AVPs
     */
    cursor = pkt->pp_avp_list;
    while (cursor != NULL) {
        buff_insert_be16(pos + PAL_OFFSET_AVP_CODE,     cursor->node.avp_code);
        buff_insert_be16(pos + PAL_OFFSET_AVP_FLAGS,    cursor->node.avp_flags);
        buff_insert_be16(pos + PAL_OFFSET_AVP_LENGTH,   cursor->node.avp_length);
        buff_insert_be16(pos + PAL_OFFSET_AVP_RESERVED, cursor->node.avp_reserved);

        if (cursor->node.avp_flags & FAVP_FLAG_VENDOR) {
            buff_insert_be32(pos + PAL_OFFSET_AVP_VENDOR_ID, cursor->node.avp_vendor_id);
            pos += PAL_OFFSET_AVP_VENDOR_VALUE;
        } else {
            pos += PAL_OFFSET_AVP_VALUE;
        }

        memcpy(pos, cursor->node.avp_value, cursor->node.avp_length);
        /*
         * Pad to dword boundary
         */
        memcpy(pos, PAD, pads_to_dword(cursor->node.avp_length));
        pos += round_to_dwords(cursor->node.avp_length);
        cursor =cursor->next;
    }
    out->used = pos - bytebuff_data(out);
    return out;
}

/*
 * Construct a PANA packet from fields
 */
pana_packet_t *
construct_pana_packet (uint16_t message_type,
                       uint16_t flags,
                       uint32_t session_id,
                       uint32_t seq_number,
                       pana_avp_node_t *avp_list)
{
    pana_avp_node_t * cursor = NULL;
    pana_packet_t * out = szalloc(pana_packet_t);
    uint32_t msg_length = 0;

    if (out == NULL) {
        return NULL;
    }

    out->pp_flags = flags;
    out->pp_message_type = message_type;
    out->pp_session_id = session_id;
    out->pp_seq_number = seq_number;
    out->pp_avp_list = avp_list;

    /*
     * Calculate the length of the message
     */
    msg_length += PPL_OFFSET_AVP;

    cursor = avp_list;
    while (cursor != NULL) {
        msg_length += (cursor->node.avp_flags | FAVP_FLAG_VENDOR) ?
                PAL_OFFSET_AVP_VENDOR_VALUE : PAL_OFFSET_AVP_VALUE;
        msg_length += round_to_dwords(cursor->node.avp_length);
        cursor = cursor->next;
    }

    out->pp_message_length = msg_length;

    return out;
}

/*
 * Frees a pana_packet_t structure
 */
void
free_pana_packet(pana_packet_t * pkt){
    avp_list_destroy(pkt->pp_avp_list);
    free(pkt);
}


