/*
 * eap_md5.h
 *
 *  Created on: Jul 13, 2009
 *      Author: alex
 */

#ifndef EAP_MD5_H_
#define EAP_MD5_H_

typedef enum {
        DECISION_FAIL, DECISION_COND_SUCC, DECISION_UNCOND_SUCC
} EapDecision;

typedef enum {
        METHOD_NONE, METHOD_INIT, METHOD_CONT, METHOD_MAY_CONT, METHOD_DONE
} EapMethodState;

struct eap_method_ret {
        Boolean ignore; //Whether method decided to drop the current packed (OUT)
        EapMethodState methodState; //Method-specific state (IN/OUT)
        EapDecision decision; //Authentication decision (OUT)
        Boolean allowNotifications;
};

struct wpabuf * eap_md5_process(struct eap_peer_config *cfg,
                                       struct eap_method_ret *ret,
                                       const struct wpabuf *reqData);

#endif /* EAP_MD5_H_ */
