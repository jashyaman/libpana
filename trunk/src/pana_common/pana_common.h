/*
 * pana_common.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef PANA_COMMON_H_
#define PANA_COMMON_H_

#include <sys/types.h>
#include "utils/util.h"
#include "utils/bytebuff.h"

//#include "eap_common/eap_config.h"

#define FAVP_FLAG_VENDOR 0x8000
#define FAVP_FLAG_CLEARED 0x0000

#define PFLAGS_NONE  0x0000       // Cleared Flags
#define PFLAG_R      0x8000       // Request
#define PFLAG_S      0x4000       // Start
#define PFLAG_C      0x2000       // Complete
#define PFLAG_A      0x1000       // re-Authrtcation
#define PFLAG_P      0x0800       // Ping
#define PFLAG_I      0x0400       // IP Reconfiguration

enum pana_message_types {
    PMT_PCI     = 1,            // PANA-Client-Initiation
    PMT_PAR     = 2,            // PANA-Auth-Request
    PMT_PAN     = 2,            // PANA-Auth-Answer
    PMT_PTR     = 3,            // PANA-Termination-Request
    PMT_PTA     = 3,            // PANA-Termination-Answer
    PMT_PNR     = 4,            // PANA-Notification-Request
    PMT_PNA     = 4             // PANA-Notification-Answer
};

typedef enum pana_avp_codes {
    PAVP_NULL           = 0,
    PAVP_AUTH           = 1,
    PAVP_EAP_PAYLOAD    = 2,
    PAVP_INTEGRITY_ALG  = 3,
    PAVP_KEY_ID         = 4,
    PAVP_NONCE          = 5,
    PAVP_PRF_ALG        = 6,
    PAVP_RESULT_CODE    = 7,
    PAVP_SESSION_LIFET  = 8,
    PAVP_TERM_CAUSE     = 9,
    
    /* Vendor codes for UPB*/
    PAVP_V_IDENTITY     = 1
} pana_avp_codes_t;

enum {
    PANA_VENDOR_RESERVED = 0,
    PANA_VENDOR_UPB = 27355 /* University Politechnical of Bucharest */
};

enum pana_result_codes {
    PANA_SUCCESS                 = 0,
    PANA_AUTHENTICATION_REJECTED = 1,
    PANA_AUTHORIZATION_REJECTED  = 2
};

enum pana_termination_causes {
    PTC_LOGOUT          = 1,
    PTC_ADMINISTRATIVE  = 4,
    PTC_SESSION_TIMEOUT = 8
};

#define PANA_SESSION_MIN_TIMEOUT  60     // Session timeout permitted limits in seconds
#define PANA_SESSION_MAX_TIMEOUT  36000 

enum pana_avp_layout {
    PAL_OFFSET_AVP_CODE         = 0,
    PAL_OFFSET_AVP_FLAGS        = 2,
    PAL_OFFSET_AVP_LENGTH       = 4,
    PAL_OFFSET_AVP_RESERVED     = 6,
    PAL_OFFSET_AVP_VALUE        = 8,
    PAL_OFFSET_AVP_VENDOR_ID    = 8,
    PAL_OFFSET_AVP_VENDOR_VALUE = 12
};

typedef struct pana_avp_s {
    uint16_t avp_code;
    uint16_t avp_flags;
    uint16_t avp_length;
    uint16_t avp_reserved;
    uint32_t avp_vendor_id;
    uint8_t * avp_value;
} pana_avp_t;

typedef struct pana_avp_node_s {
    pana_avp_t node;
    struct pana_avp_node_s * next;

} pana_avp_node_t;

#define PANA_PKT_HEADER_SIZE 16
#define PANA_PKT_MAX_SIZE    1500       // Roughly equal to MTU

enum pana_packet_layout {
    PPL_OFFSET_RESERVED         = 0,
    PPL_OFFSET_MSG_LENGTH       = 2,
    PPL_OFFSET_FLAGS            = 4,
    PPL_OFFSET_MSG_TYPE         = 6,
    PPL_OFFSET_SESSION_ID       = 8,
    PPL_OFFSET_SEQ_NUMBER       = 12,
    PPL_OFFSET_AVP              = 16
};

enum pana_prf_codes {
    PRF_HMAC_MD5    = 1,
    PRF_HMAC_SHA1   = 2,
    PRF_HMAC_TIGER  = 3,
    PRF_AES128_XCBC = 4
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

/*
 * Session definitions
 */
typedef struct pana_sa_s {
    uint8_t PaC_nonce[20];
    uint8_t PAA_nonce[20];
    uint8_t MSK[64];
    uint32_t KEY_ID;
    uint8_t * PANA_AUTH_KEY;    // Length will depend on the prf+ chosen
    uint32_t prf;
    uint32_t integrity_alg;
} pana_sa_t;



typedef struct pana_sesion_s {
    uint32_t session_id;
    ip_port_t pac_ip_port;
    ip_port_t paa_ip_port;
    int cstate;
    uint32_t seq_rx;
    uint32_t seq_tx;
    bytebuff_t * pkt_cache;
    uint32_t session_lifetime;
    pana_sa_t * sa;
    void * ctx;         // Other specifi options for PaC and PAA
} pana_session_t;

typedef enum pana_phase {
    PANA_PHASE_UNITIALISED,
    PANA_PHASE_AUTH,
    PANA_PHASE_ACCESS,
    PANA_PHASE_REAUTH,
    PANA_PHASE_TERMINATE
} pana_phase_t;



typedef struct {
    uint8_t count;
    time_t deadline; // Deadline in Epoch :)
    Boolean enabled;
} rtimer_t;


#endif /* PANA_COMMON_H_ */
