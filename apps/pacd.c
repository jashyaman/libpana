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
static uint8_t localmac[6] = {0x00, 0x22 , 0x69, 0x7b ,0x83, 0x3c};

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
    /*
     * TODO: Recode to use optargs
     */
    return RES_ARGS_OK;

}

int process_config_files() {
    /*
     * TODO: implement parsing of config and dhcp-lease file
     */
    sockaddr_in4_t * tmp_addr;

    tmp_addr = str_to_sockaddr_in4("192.168.1.102:5000");   // locsl port
    global_cfg.pac_addr = *tmp_addr;
    os_free(tmp_addr);

    tmp_addr = str_to_sockaddr_in4("192.168.1.102:7000");    // server's address
    global_cfg.paa_addr = *tmp_addr;
    os_free(tmp_addr);
    
    global_cfg.eap_cfg = malloc(sizeof(pana_eap_peer_config_t));
    global_cfg.eap_cfg->identity = "alex.antone@gmail.com";
    global_cfg.eap_cfg->identity_len = strlen(global_cfg.eap_cfg->identity);
    global_cfg.eap_cfg->password = "CLEARTEXT TEST PASSWORD";
    global_cfg.eap_cfg->password_len = strlen(global_cfg.eap_cfg->password);
    global_cfg.reauth_interval = 80;
    global_cfg.rtx_interval = 10;
    global_cfg.rtx_max_count = 4;
    global_cfg.failed_sess_timeout = 60;  // 1 min
    memcpy(global_cfg.pac_macaddr, localmac, sizeof(localmac));
    
    return RES_CFG_FILES_OK;
}

void cleanup() {
    os_free(global_cfg.eap_cfg);
}

int main(int argc, char * argv[])
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
