/*
 * libpana.h
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#ifndef LIBPANA_H_
#define LIBPANA_H_

#include <sys/types.h>

#define NULL 0

#define F_AVP_FLAG_VENDOR 0x80

enum pana_avp_layout {
    PAL_OFFSET_AVP_CODE         = 0;
    PAL_OFFSET_AVP_FLAGS        = 2;
    PAL_OFFSET_AVP_LENGTH       = 4;
    PAL_OFFSET_AVP_RESERVED     = 6;
    PAL_OFFSET_AVP_VALUE        = 8;
    PAL_OFFSET_AVP_VENDOR_ID    = 8;
    PAL_OFFSET_AVP_VENDOR_VALUE = 12;
};

typedef struct pana_avp_s {
    uint16_t avp_code;
    uint16_t avp_flags;
    uint16_t avp_length;
    uint16_t avp_reserved;
    uint32_t avp_vendor_id;
    uint8_t avp_value[];
} pana_avp_t;

typedef struct pana_avp_node_s {
    pana_avp_t node;
    struct pana_avp_node_s * next;
} pana_avp_node_t;

#define PANA_PKT_HEADER_SIZE 16

enum pana_packet_layout {
    PPL_OFFSET_RESERVED         = 0;
    PPL_OFFSET_MSG_LENGTH       = 2;
    PPL_OFFSET_FLAGS            = 4;
    PPL_OFFSET_MSG_TYPE         = 6;
    PPL_OFFSET_SESSION_ID       = 8;
    PPL_OFFSET_SEQ_NUMBER       = 12;
    PPL_OFFSET_AVP              = 16;
};


typedef struct pana_packet_s {
    /*
     * Packet header
     */
    uint16_t pp_reserved;
    uint16_t pp_message_length;
    uint16_t pp_flags;
    uint16_t pp_message_type;
    uint32_t pp_session_id;
    uint32_t pp_seq_number;
    /*
     * AVP list
     */
    pana_avp_node_t *pp_avp_list;
} pana_packet_t;



#endif /* LIBPANA_H_ */
