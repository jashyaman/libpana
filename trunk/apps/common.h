/*
 * common.h
 *
 *  Created on: Jul 12, 2009
 *      Author: alex
 */

#ifndef COMMON_H_
#define COMMON_H_


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libpana.h>

#define DECIMAL_BASE    10
#define MAX_PORTN       0xFFFF

#define PACD_DEF_PORT   5001
#define NAS_DEF_PORT    7001
#define AAA_DEF_PORT    8001
#define EP_DEF_PORT     9001


#define DEBUG(cmd) printf("#DEBUG# - %s [%d]: %s\n", __FILE__, __LINE__, #cmd); \
                   cmd

#define os_free(p) \
    do{if((p) != NULL) {\
        free((p));\
        (p) = NULL;\
        }} while(0)

sockaddr_in4_t * str_to_sockaddr_in4(const char * const in_str);

#endif /* COMMON_H_ */
