/*
 * pacd.c
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#include "common.h"
#include "pacd.h"

/*
 * Variables that will hold the PANA configuration settings.
 */
static char * pacd_config_file = "/etc/pana/pacd.conf";
static char * dhcp_lease_file = "/var/lib/dhcp3/dhclient.leases";

static pac_config_t global_cfg;

#define CMD_FLAG_P      0x0001
#define CMD_FLAG_S      0x0002
#define CMD_FLAG_C      0x0004
#define CMD_FLAG_D      0x0008

#define PACD_USAGE_MSG ""\
"Usage: pacd [-p <client-port>] [-s <nas-ip[:port]>] [-c <config-file>]\n"\
"            [-d <dhcp-lease-file>]\n"\
"       pacd { -h | --help }\n"\
"Warning: command line parameters take precedence over config files.\n"

static int process_args(char * argv[], int argc) {
    short flags = 0x0000; // the p,s,c,d;
    int ctoken = 1;       // skip command name
    char * pos = NULL;
    unsigned long tmp_parsing_val = 0;
    ip_port_t * tmp_ipporv = NULL;

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
            global_cfg.pac.port = tmp_parsing_val;
        }
        else if ((strcmp(argv[ctoken++], "-s") == 0) && !(flags & CMD_FLAG_S)) {
            if (!(tmp_ipporv = str_to_ip_port(argv[ctoken++]))) {
                puts("Incorrect ip:port address\n");
                return ERR_BADARGS;
            }
            global_cfg.paa = *tmp_ipporv;
            free(tmp_ipporv);
        }
        else if ((strcmp(argv[ctoken++], "-c") == 0) && !(flags & CMD_FLAG_C)) {
            pacd_config_file = argv[ctoken++];
        }
        else if ((strcmp(argv[ctoken++], "-d") == 0) && !(flags & CMD_FLAG_D)) {
            dhcp_lease_file = argv[ctoken++];
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
    /*
     * TODO: implement parsing of config and dhcp-lease file
     */
    
    global_cfg.pac = *(str_to_ip_port("192.168.1.102:5000"));
    global_cfg.eap_cfg = malloc(sizeof(pana_eap_peer_config_t));
    global_cfg.eap_cfg->identity = "alex.antone@gmail.com";
    global_cfg.eap_cfg->identity_len = strlen(global_cfg.eap_cfg->identity);
    global_cfg.eap_cfg->password = "CLEARTEXT TEST PASSWORD";
    global_cfg.eap_cfg->password_len = strlen(global_cfg.eap_cfg->password);
               
    
    return RES_CFG_FILES_OK;
}

void cleanup() {
    if (global_cfg.eap_cfg) {
        free(global_cfg.eap_cfg);
    }
}

int main(char * argv[], int argc)
{
    int exit_code = 0;
    
    exit_code = process_args(argv, argc);
    if (exit_code > ERR_CODE) {
        exit(exit_code);
    }

    exit_code = process_config_files();
    if (exit_code > ERR_CODE) {
        exit(exit_code);
    }

    exit_code = pac_main(&global_cfg);

    cleanup();
    
    exit(exit_code);
}
