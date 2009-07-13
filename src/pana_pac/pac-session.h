/*
 * pac-session.h
 *
 *  Created on: Jul 13, 2009
 *      Author: alex
 */

#ifndef PACSESSION_H_
#define PACSESSION_H_

#include "pana_common/pana_common.h"
#include "eap_peer/eap_md5.h"

#define RX(msgtype, msgflags, pktin) \
    ((pktin)->pp_message_type == (msgtype) && (pktin)->pp_flags == (msgflags))

#define RX_PAR_S(pktin) RX(PMT_PAR, (PFLAG_R | PFLAG_S), pktin)
#define RX_PAR(pktin)   RX(PMT_PAR, (PFLAG_R), pktin)
#define RX_PAR_C(pktin) RX(PMT_PAR, (PFLAG_R | PFLAG_C), pktin)


#define RX_PAN(pktin)   RX(PMT_PAN, (PFLAGS_NONE), pktin)


#define RX_PNR_P(pktin) RX(PMT_PNR, (PFLAG_R | PFLAG_P), pktin)
#define RX_PNA_P(pktin) RX(PMT_PNA, (PFLAG_P), pktin)


#define TX(msgtype, msgflags, pktout, avplist) \
    (pktout) = construct_pana_packet((msgtype), (msgflags), pacs->session_id, pacs->seq_tx++, avplist)

#define TX_PCI(pktout, avplist) TX(PMT_PNA, PFLAGS_NONE, pkt_out, avplist)

#define TX_PAR(pktout, avplist)   TX(PMT_PAR, PFLAG_R, pkt_out, avplist)

#define TX_PAN_S(pktout, avplist) TX(PMT_PAN, PFLAG_S, pkt_out, avplist)
#define TX_PAN(pktout, avplist)   TX(PMT_PAN, PFLAGS_NONE, pkt_out, avplist)

#define TX_PNA_P(pktout, avplist) TX(PMT_PNA, PFLAG_P, pkt_out, avplist)

    


#endif /* PACSESSION_H_ */
