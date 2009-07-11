/*
 * libpana.h
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#ifndef LIBPANA_H_
#define LIBPANA_H_

typedef struct ip_port_s {
    uint32_t ip;
    uint16_t port;      // UDP Port
} ip_port_t;


struct eap_peer_config {
        u8 *identity;
        size_t identity_len;

        u8 *password;
        size_t password_len;
};


typedef struct pac_config_s {
    struct eap_peer_config * eap_cfg;
    ip_port_t pac;
    ip_port_t paa;    
} pac_config_t;




/*
 * -------------------------------------------------------------------------
 * PaC specific functions
 * -------------------------------------------------------------------------
 */

extern int pac_packet_handler(pana_packet_t * pkt);


/*
 * -------------------------------------------------------------------------
 * PAA specific functions
 * -------------------------------------------------------------------------
 */

extern int paa_packet_handler(pana_packet_t * pkt);




#endif /* LIBPANA_H_ */
