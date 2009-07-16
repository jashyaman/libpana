/*
 * paa-session.h
 *
 *  Created on: Jul 15, 2009
 *      Author: alex
 */

#ifndef PAASESSION_H_
#define PAASESSION_H_

#include "pana_common/pana_common.h"
#include "eap_server/eap_md5.h"
#include "ep.h"


#define RX(msgtype, msgflags, pktin) \
    ((pktin)->pp_message_type == (msgtype) && (pktin)->pp_flags == (msgflags))

#define RX_PCI(pktin)   RX(PMT_PCI, (PFLAGS_NONE), pktin)

#define RX_PAR_S(pktin) RX(PMT_PAR, (PFLAG_R | PFLAG_S), pktin)
#define RX_PAR(pktin)   RX(PMT_PAR, (PFLAG_R), pktin)
#define RX_PAR_C(pktin) RX(PMT_PAR, (PFLAG_R | PFLAG_C), pktin)


#define RX_PAN_S(pktin) RX(PMT_PAN, (PFLAGS_NONE | PFLAG_S), pktin)
#define RX_PAN(pktin)   RX(PMT_PAN, (PFLAGS_NONE), pktin)
#define RX_PAN_C(pktin) RX(PMT_PAN, (PFLAG_C), pktin)


#define RX_PNR_P(pktin) RX(PMT_PNR, (PFLAG_R | PFLAG_P), pktin)
#define RX_PNR_A(pktin) RX(PMT_PNR, (PFLAG_R | PFLAG_A), pktin)

#define RX_PNA_P(pktin) RX(PMT_PNA, (PFLAG_P), pktin)
#define RX_PNA_A(pktin) RX(PMT_PNA, (PFLAG_A), pktin)

#define RX_PTR(pktin)   RX(PMT_PTR, (PFLAG_R), pktin)
#define RX_PTA(pktin)   RX(PMT_PTA, PFLAGS_NONE, pktin)



#define TX(pacs, msgtype, msgflags, avplist, respbuff) \
 do {\
      pana_packet_t * pkt__ = construct_pana_packet((msgtype), (msgflags), pacs->session_id, pacs->seq_tx++, avplist);\
      respbuff = serialize_pana_packet(pkt__);\
      free_pana_packet(pkt__);\
 } while(0)


/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * WARNING for these to wor you need a session variable named pacs
 * to denote the current sesstion
 */

#define TX_PCI(respbuff, avplist)   TX(pacs, PMT_PCI, PFLAGS_NONE, avplist, respbuff)

#define TX_PAR_S(respbuff, avplist) TX(pacs, PMT_PAR, (PFLAG_R | PFLAG_S), avplist, respbuff)
#define TX_PAR(respbuff, avplist)   TX(pacs, PMT_PAR, PFLAG_R, avplist, respbuff)
#define TX_PAR_C(respbuff, avplist) TX(pacs, PMT_PAR, (PFLAG_R | PFLAG_C), avplist, respbuff)

#define TX_PAN_S(respbuff, avplist) TX(pacs, PMT_PAN, PFLAG_S, avplist, respbuff)
#define TX_PAN(respbuff, avplist)   TX(pacs, PMT_PAN, PFLAGS_NONE, avplist, respbuff)
#define TX_PAN_C(respbuff, avplist) TX(pacs, PMT_PAN, PFLAG_C, avplist, respbuff)

#define TX_PNA_A(respbuff, avplist) TX(pacs, PMT_PNA, PFLAG_P | PFLAG_A, avplist, respbuff)
#define TX_PNA_P(respbuff, avplist) TX(pacs, PMT_PNA, PFLAG_P, avplist, respbuff)
#define TX_PNR_P(respbuff, avplist) TX(pacs, PMT_PNA, (PFLAG_R | PFLAG_P), avplist, respbuff)

#define TX_PNR_A(respbuff, avplist) TX(pacs, PMT_PNA, (PFLAG_R | PFLAG_A), avplist, respbuff)

#define TX_PTA(respbuff, avplist)   TX(pacs, PMT_PTA, PFLAGS_NONE, avplist, respbuff)
#define TX_PTR(respbuff, avplist)   TX(pacs, PMT_PTR, PFLAG_R, avplist, respbuff)

#endif /* PAASESSION_H_ */
