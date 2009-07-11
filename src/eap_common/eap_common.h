/*
 * EAP common peer/server definitions
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef EAP_COMMON_H
#define EAP_COMMON_H

#include "wpabuf.h"

struct eap_hdr {
        u8 code;
        u8 identifier;
        u16 length; /* including code and identifier; network byte order */
        /* followed by length-4 octets of data */
} __attribute__ ((packed));


enum { EAP_CODE_REQUEST = 1, EAP_CODE_RESPONSE = 2, EAP_CODE_SUCCESS = 3,
       EAP_CODE_FAILURE = 4 };

typedef enum {
        EAP_TYPE_NONE = 0,
        EAP_TYPE_IDENTITY = 1 /* RFC 3748 */,
        EAP_TYPE_NOTIFICATION = 2 /* RFC 3748 */,
        EAP_TYPE_NAK = 3 /* Response only, RFC 3748 */,
        EAP_TYPE_MD5 = 4, /* RFC 3748 */
        EAP_TYPE_OTP = 5 /* RFC 3748 */,
        EAP_TYPE_GTC = 6, /* RFC 3748 */
        EAP_TYPE_EXPANDED = 254 /* RFC 3748 */,
        EAP_TYPE_EXPERIMENTAL = 255 /* EXPERIMENTAL - type not yet allocated*/
} EapType;


/* SMI Network Management Private Enterprise Code for vendor specific types */
enum {
        EAP_VENDOR_IETF = 0,
        EAP_VENDOR_MICROSOFT = 0x000137 /* Microsoft */,
        EAP_VENDOR_WFA = 0x00372A /* Wi-Fi Alliance */
};

#define EAP_MSK_LEN 64
#define EAP_EMSK_LEN 64


const u8 * eap_hdr_validate(int vendor, EapType eap_type,
			    const struct wpabuf *msg, size_t *plen);
struct wpabuf * eap_msg_alloc(int vendor, EapType type, size_t payload_len,
			      u8 code, u8 identifier);
void eap_update_len(struct wpabuf *msg);
u8 eap_get_id(const struct wpabuf *msg);
EapType eap_get_type(const struct wpabuf *msg);

#endif /* EAP_COMMON_H */
