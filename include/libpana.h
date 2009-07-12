/*
 * libpana.h
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#ifndef LIBPANA_H_
#define LIBPANA_H_

/* error codes */
#define ERR_SOCK_ERROR          0x1003
#define ERR_BIND_SOCK           0x1004
#define ERR_CONNECT_SOCK        0x1005


typedef struct ip_port_s {
    uint32_t ip;
    uint16_t port;      // UDP Port
} ip_port_t;


struct eap_peer_config {
        uint8_t *identity;
        size_t identity_len;

        uint8_t *password;
        size_t password_len;
};

/* PaC global config */
typedef struct pac_config_s {
    /* auth config parameters */
    ip_port_t pac;
    ip_port_t paa;
    struct eap_peer_config * eap_cfg;
    
    /* transmission params */
    uint16_t rtx_interval;
    uint8_t  rtx_max_count;
    uint8_t  reauth_interval; /* start reauth at sess_lifetime*(reauth_interval/100) */
    
    
    
} pac_config_t;

/* PAA global config */
typedef struct paa_config_s {
    /* auth config parameters */
    ip_port_t paa;
    ip_port_t ep;                               // Enforcement point
    struct eap_peer_config (*get_eap_cfg)(uint32_t sess_id);
    
    /* transmission params */
    uint16_t rtx_interval;
    uint8_t  rtx_max_count;
    uint8_t  reauth_interval; /* start reauth at sess_lifetime*(reauth_interval/100) */
    
    
    
} paa_config_t;




/*
 * -------------------------------------------------------------------------
 * PaC specific functions
 * -------------------------------------------------------------------------
 */

/*
 * -------------------------------------------------------------------------
 * PAA specific functions
 * -------------------------------------------------------------------------
 */

#endif /* LIBPANA_H_ */
