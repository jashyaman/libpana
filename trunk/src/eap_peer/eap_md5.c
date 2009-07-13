/*
 * EAP peer method: EAP-MD5 (RFC 3748 and RFC 1994)
 * Copyright (c) 2004-2006, Jouni Malinen <j@w1.fi>
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

#include "utils/includes.h"
#include "utils/util.h"

#include "eap_common/eap_config.h"
#include "eap_common/eap_common.h"
#include "eap_common/chap.h"


//static struct wpabuf * eap_md5_process(struct eap_peer_config *cfg,
//                                       void *priv,
//                                       struct eap_method_ret *ret,
//                                       const struct wpabuf *reqData)

struct wpabuf * eap_md5_process(struct eap_peer_config *cfg,
                                       struct eap_method_ret *ret,
                                       const struct wpabuf *reqData)
{
	struct wpabuf *resp;
	const uint8_t *pos, *challenge, *password;
	uint8_t *rpos, id;
	size_t len, challenge_len, password_len;

	password = cfg->password;
	password_len = cfg->password_len;
	
	if (password == NULL) {
		dbg_printf(MSG_INFO, "EAP-MD5: Password not configured");
		ret->ignore = TRUE;
		return NULL;
	}

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MD5, reqData, &len);
	if (pos == NULL || len == 0) {
		dbg_printf(MSG_INFO, "EAP-MD5: Invalid frame (pos=%p len=%lu)",
			   pos, (unsigned long) len);
		ret->ignore = TRUE;
		return NULL;
	}

	/*
	 * CHAP Challenge:
	 * Value-Size (1 octet) | Value(Challenge) | Name(optional)
	 */
	challenge_len = *pos++;
	if (challenge_len == 0 || challenge_len > len - 1) {
		dbg_printf(MSG_INFO, "EAP-MD5: Invalid challenge "
			   "(challenge_len=%lu len=%lu)",
			   (unsigned long) challenge_len, (unsigned long) len);
		ret->ignore = TRUE;
		return NULL;
	}
	ret->ignore = FALSE;
	challenge = pos;
	dbg_hexdump(MSG_MSGDUMP, "EAP-MD5: Challenge",
		    challenge, challenge_len);

	dbg_printf(MSG_DEBUG, "EAP-MD5: Generating Challenge Response");
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_UNCOND_SUCC;
	ret->allowNotifications = TRUE;

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MD5, 1 + CHAP_MD5_LEN,
			     EAP_CODE_RESPONSE, eap_get_id(reqData));
	if (resp == NULL)
		return NULL;

	/*
	 * CHAP Response:
	 * Value-Size (1 octet) | Value(Response) | Name(optional)
	 */
	wpabuf_put_u8(resp, CHAP_MD5_LEN);

	id = eap_get_id(resp);
	rpos = wpabuf_put(resp, CHAP_MD5_LEN);
	chap_md5(id, password, password_len, challenge, challenge_len, rpos);
	dbg_hexdump(MSG_MSGDUMP, "EAP-MD5: Response", rpos, CHAP_MD5_LEN);

	return resp;
}

/*
int eap_peer_md5_register(void)
{
        struct eap_method *eap;
        int ret;

        eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
                                    EAP_VENDOR_IETF, EAP_TYPE_MD5, "MD5");
        if (eap == NULL)
                return -1;

        eap->init = eap_md5_init;
        eap->deinit = eap_md5_deinit;
        eap->process = eap_md5_process;

        ret = eap_peer_method_register(eap);
        if (ret)
                eap_peer_method_free(eap);
        return ret;
}
*/