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
sockaddr_in4_t * str_to_sockaddr_in4(const char * const in_str) {
    unsigned long tmp_val = 0;
    int res = 0; 
    char * cpos = NULL;
    char * tmpstr = NULL;
    
    sockaddr_in4_t * out = calloc(sizeof(sockaddr_in4_t),1);
    if (out == NULL) {
        return NULL;
    }
    
    tmpstr = strdup(in_str);
    cpos = strchr(tmpstr, ':');
    
    if (cpos == NULL) {
        /*
         * Only the ip is specified. The port is implied to be the default one
         */
        out->sin_port = 0;
        if (inet_pton(AF_INET, tmpstr, &out->sin_addr.s_addr) <= 0) {
            res = -1;
        }
    } else {
        /*
         * Separate the ip and port sections
         */
        *cpos = '\0';
        cpos++;
        tmp_val = strtoul(cpos, &cpos, DECIMAL_BASE);
        if (*cpos != '\0' || tmp_val > MAX_PORTN) {
            res = -1;
        }
        out->sin_port = htons(tmp_val);
        if (inet_pton(AF_INET, tmpstr, &out->sin_addr.s_addr) <= 0) {
            res = -1;
        }
    }
    
    os_free(tmpstr);
    if (res < 0) {
        os_free(out);
        return NULL;
    }
    
    return out;
}
