/*
 * hostapd / EAP-MD5 server
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

#include "util/includes.h"

#include "eap_common/chap.h"


#define CHALLENGE_LEN 16

struct eap_md5_data {
	uint8_t challenge[CHALLENGE_LEN];
	enum { CONTINUE, SUCCESS, FAILURE } state;
};


static void * eap_md5_init()
{
	struct eap_md5_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = CONTINUE;

	return data;
}


static void eap_md5_reset(void *priv)
{
	struct eap_md5_data *data = priv;
	os_free(data);
}


static struct wpabuf * eap_md5_buildReq(void *priv, u8 id)
{
	struct eap_md5_data *data = priv;
	struct wpabuf *req;

	if (os_get_random(data->challenge, CHALLENGE_LEN)) {
		dbg_printf(MSG_ERROR, "EAP-MD5: Failed to get random data");
		data->state = FAILURE;
		return NULL;
	}

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MD5, 1 + CHALLENGE_LEN,
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		dbg_printf(MSG_ERROR, "EAP-MD5: Failed to allocate memory for "
			   "request");
		data->state = FAILURE;
		return NULL;
	}

	wpabuf_put_u8(req, CHALLENGE_LEN);
	wpabuf_put_data(req, data->challenge, CHALLENGE_LEN);
	dbg_hexdump(MSG_MSGDUMP, "EAP-MD5: Challenge", data->challenge,
		    CHALLENGE_LEN);

	data->state = CONTINUE;

	return req;
}


static Boolean eap_md5_check(void *priv, struct wpabuf *respData)
{
	const uint8_t *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MD5, respData, &len);
	if (pos == NULL || len < 1) {
		dbg_printf(MSG_INFO, "EAP-MD5: Invalid frame");
		return TRUE;
	}
	if (*pos != CHAP_MD5_LEN || 1 + CHAP_MD5_LEN > len) {
		dbg_printf(MSG_INFO, "EAP-MD5: Invalid response "
			   "(response_len=%d payload_len=%lu",
			   *pos, (unsigned long) len);
		return TRUE;
	}

	return FALSE;
}


static void eap_md5_process(struct eap_peer_config *cfg, void *priv,
			    struct wpabuf *respData)
{
	struct eap_md5_data *data = priv;
	const uint8_t *pos;
	size_t plen;
	uint8_t hash[CHAP_MD5_LEN], id;

	if (cfg == NULL || cfg->password == NULL) {
		dbg_printf(MSG_INFO, "EAP-MD5: Plaintext password not "
			   "configured");
		data->state = FAILURE;
		return;
	}

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MD5, respData, &plen);
	if (pos == NULL || *pos != CHAP_MD5_LEN || plen < 1 + CHAP_MD5_LEN)
		return; /* Should not happen - frame already validated */

	pos++; /* Skip response len */
	dbg_hexdump(MSG_MSGDUMP, "EAP-MD5: Response", pos, CHAP_MD5_LEN);

	id = eap_get_id(respData);
	chap_md5(id, cfg->password, cfg->password_len,
		 data->challenge, CHALLENGE_LEN, hash);

	if (os_memcmp(hash, pos, CHAP_MD5_LEN) == 0) {
		dbg_printf(MSG_DEBUG, "EAP-MD5: Done - Success");
		data->state = SUCCESS;
	} else {
		dbg_printf(MSG_DEBUG, "EAP-MD5: Done - Failure");
		data->state = FAILURE;
	}
}


static Boolean eap_md5_isDone(void *priv)
{
	struct eap_md5_data *data = priv;
	return data->state != CONTINUE;
}


static Boolean eap_md5_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_md5_data *data = priv;
	return data->state == SUCCESS;
}

/*
int eap_server_md5_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_MD5, "MD5");
	if (eap == NULL)
		return -1;

	eap->init = eap_md5_init;
	eap->reset = eap_md5_reset;
	eap->buildReq = eap_md5_buildReq;
	eap->check = eap_md5_check;
	eap->process = eap_md5_process;
	eap->isDone = eap_md5_isDone;
	eap->isSuccess = eap_md5_isSuccess;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
*/
