/*
 * pacd.c
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <libpana.h>

#include <pacd.h>

#define DECIMAL_BASE    10
#define MAX_PORTN       0xFFFF

/*
 * Misc util functions.
 */
int str_to_ip_port(const char * const in_str,
                   uint32_t * out_ip, uint16_t * out_port) {
    unsigned long tmp_val = 0;
    char * cpos = NULL;
    
    cpos = strchr(in_str, ':');
    
    if (cpos == NULL) {
        /*
         * Only the ip is specified. The port is implied to be the default one
         */
        *out_port = NAS_DEF_PORT;
        if (!inet_pton(AF_INET, in_str, out_ip)) {
            return -1;
        }
    } else {
        /*
         * Separate the ip and port sections
         */
        *cpos = '\0';
        cpos++;
        tmp_val = strtoul(cpos, &cpos, DECIMAL_BASE);
        if (cpos != '\0' || tmp_val > MAX_PORTN) {
            return -1;
        }
        *out_port = tmp_val;
        if (!inet_pton(AF_INET, in_str, out_ip)) {
            return -1;
        }
    }
    return 0;
}


/*
 * Variables that will hold the PANA configuration settings.
 */
static char * pacd_config_file = "/etc/pana/pacd.conf";
static char * dhcp_lease_file = "/var/lib/dhcp3/dhclient.leases";
static uint16_t pacd_port = PACD_DEF_PORT;
static uint32_t nas_v4_ip = 0;
static uint16_t nas_port = NAS_DEF_PORT;

#define CMD_FLAG_P      0x0001
#define CMD_FLAG_S      0x0002
#define CMD_FLAG_C      0x0004
#define CMD_FLAG_D      0x0008
#define CMD_FLAG_T      0x0010

#define PACD_USAGE_MSG ""\
"Usage: pacd [-p <client-port>] [-s <nas-ip[:port]>] [-c <config-file>]\n"\
"            [-d <dhcp-lease-file>] [-t <session-timeout-seconds>]\n"\
"       pacd { -h | --help }\n"\
"Warning: command line parameters take precedence over config files.\n"

static int process_args(char * argv[], int argc) {
    short flags = 0x0000; // the p,s,c,d,t;
    int ctoken = 1;       // skip command name
    char * pos = NULL;
    unsigned long tmp_parsing_val = 0;

    while (ctoken < argc) {
        if ((strcmp(argv[ctoken++], "-h") == 0)) {
            puts(PACD_USAGE_MSG);
            return NFO_HELP_REQ;
        }
        else if ((strcmp(argv[ctoken++], "-p") == 0) && !(flags & CMD_FLAG_P)) {
            /*
             * Client port number
             */
            tmp_parsing_val = strtoul(argv[ctoken++], &pos, DECIMAL_BASE);
            if (pos != '\0' || tmp_parsing_val > MAX_PORTN) {
                puts("Incorrect port number: should be in 0-65365\n");
                return ERR_BADARGS;
            }
        }
        else if ((strcmp(argv[ctoken++], "-s") == 0) && !(flags & CMD_FLAG_S)) {
            if (str_to_ip_port(argv[ctoken++], &nas_v4_ip, &nas_port) < 0) {
                puts("Incorrect ip:port address\n");
                return ERR_BADARGS;
            }
        }
        else if ((strcmp(argv[ctoken++], "-c") == 0) && !(flags & CMD_FLAG_C)) {
            pacd_config_file = argv[ctoken++];
        }
        else if ((strcmp(argv[ctoken++], "-d") == 0) && !(flags & CMD_FLAG_D)) {
            dhcp_lease_file = argv[ctoken++];
        }
        else if ((strcmp(argv[ctoken++], "-t") == 0) && !(flags & CMD_FLAG_T)) {
            /*
             * Session timeout in seconds;
             */
            tmp_parsing_val = strtoul(argv[ctoken++], &pos, DECIMAL_BASE);
            if (pos != '\0' || tmp_parsing_val > PANA_SESSION_MAX_TIMEOUT ||
                    tmp_parsing_val < PANA_SESSION_MIN_TIMEOUT) {
                puts("The session timeout must be in "\
                        #PANA_SESSION_MIN_TIMEOUT "-" #PANA_SESSION_MAX_TIMEOUT "\n");
                return ERR_BADARGS;
            }
        }
        else {
            puts("Bad or duplicate arguments.\n");
            puts(PACD_USAGE_MSG);
            return ERR_BADARGS;
        }
    }
    
    return RES_ARGS_OK;

}

int process_config_files() {
    
}


int main(char * argv[], int argc)
{
    int exit_code = 0;
    
    exit_code = process_args(argv, argc);
    if (exit_code > 0x1000) {
        exit(exit_code);
    }

    exit_code = process_config_files();
    if (exit_code > 0x1000) {
        exit(exit_code);
    }
    
    
    
    


}
