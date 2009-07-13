/*
 * pac-session.h
 *
 *  Created on: Jul 13, 2009
 *      Author: alex
 */

#ifndef PACSESSION_H_
#define PACSESSION_H_

#include "pana_common/pana_common.h"

#define RX(msgtype, msgflags, pktin) \
    ((pktin)->pp_message_type == (msgtype) && (pktin)->pp_flags == (msgflags))

#define RX_PNR_P(pktin) RX(PMT_PNR, (PFLAG_R | PFLAG_P), pktin)
#define RX_PNA_P(pktin) RX(PMT_PNA, PFLAG_P, pktin)


#define TX(msgtype, msgflags, pktout, avplist) \
    (pktout) = construct_pana_packet((msgtype), (msgflags), pacs->session_id, pacs->seq_tx++, avplist)

#define TX_PNA_P(pktout, avplist) TX(PMT_PNA, PFLAG_P, pkt_out, avplist)
    


#endif /* PACSESSION_H_ */
