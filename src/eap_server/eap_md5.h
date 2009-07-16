/*
 * eap_md5.h
 *
 *  Created on: Jul 15, 2009
 *      Author: alex
 */

#ifndef EAP_MD5_H_
#define EAP_MD5_H_

#include "eap_common/eap_common.h"
#include "eap_common/eap_config.h"

void * eap_md5_init();
void eap_md5_reset(void *priv);
struct wpabuf * eap_md5_buildReq(void *priv, uint8_t id);
Boolean eap_md5_check(void *priv, struct wpabuf *respData);
void eap_md5_process(struct eap_peer_config *cfg, void *priv,
                            struct wpabuf *respData);
Boolean eap_md5_isDone(void *priv);
Boolean eap_md5_isSuccess(void *priv);
Boolean eap_md5_isFailure(void *priv);

#endif /* EAP_MD5_H_ */
