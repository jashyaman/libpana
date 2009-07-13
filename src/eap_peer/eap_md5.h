/*
 * eap_md5.h
 *
 *  Created on: Jul 13, 2009
 *      Author: alex
 */

#ifndef EAP_MD5_H_
#define EAP_MD5_H_


#include "eap_common/eap_common.h"
#include "eap_common/eap_config.h"


struct wpabuf * eap_md5_process(struct eap_peer_config *cfg,
                                       struct eap_method_ret *ret,
                                       const struct wpabuf *reqData);

#endif /* EAP_MD5_H_ */
