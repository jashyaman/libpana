/*
 * common.c
 *
 *  Created on: Jul 12, 2009
 *      Author: alex
 */

#include "common.h"

/*
 * Misc util functions.
 */
ip_port_t * str_to_ip_port(const char * const in_str) {
    unsigned long tmp_val = 0;
    int res = 0; 
    char * cpos = NULL;
    
    ip_port_t * out = malloc(sizeof(ip_port_t));
    if (out == NULL) {
        return NULL;
    }
    
    cpos = strchr(in_str, ':');
    
    if (cpos == NULL) {
        /*
         * Only the ip is specified. The port is implied to be the default one
         */
        out->port = NAS_DEF_PORT;
        if (inet_pton(AF_INET, in_str, &out->ip) <= 0) {
            res = -1;
        }
    } else {
        /*
         * Separate the ip and port sections
         */
        *cpos = '\0';
        cpos++;
        tmp_val = strtoul(cpos, &cpos, DECIMAL_BASE);
        if (cpos != '\0' || tmp_val > MAX_PORTN) {
            res = -1;
        }
        out->port = tmp_val;
        if (inet_pton(AF_INET, in_str, &out->ip) <= 0) {
            res = -1;
        }
    }

    if (res < 0) {
        free(out);
        return NULL;
    }
    
    return out;
}
