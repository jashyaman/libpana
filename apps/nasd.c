/*
 * nasd.c
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#include "common.h"
#include "nasd.h"

/*
 * Variables that will hold the PANA configuration settings.
 */
static paa_config_t global_cfg;
static char * nasd_config_file = "/etc/pana/nasd.conf";

#define CMD_FLAG_P      0x0001
#define CMD_FLAG_S      0x0002
#define CMD_FLAG_E      0x0004
#define CMD_FLAG_C      0x0008

#define NASD_USAGE_MSG ""\
"Usage: pacd [-p <local-port>] [-s <aaa-server[:port]>] [-e <ep-ip[:port]>]\n"\
"            [-c <config-file>]\n"\
"       pacd { -h | --help }\n"\
"Warning: command line parameters take precedence over config files.\n"

static int process_args(char * argv[], int argc) {
    /*
     * TODO: recode to use optarg
     */
    return RES_ARGS_OK;

}

int process_config_files() {
    /*
     * TODO: implement parsing of config and dhcp-lease file
     */
    sockaddr_in4_t * tmp_addr;

    tmp_addr = str_to_sockaddr_in4("192.168.1.102:8001");// remote ep address
    global_cfg.ep_addr= *tmp_addr;
    os_free(tmp_addr);

    tmp_addr = str_to_sockaddr_in4("192.168.1.102:7000");  // local port fo incomming pana comms
    global_cfg.paa_pana= *tmp_addr;
    os_free(tmp_addr);
    
    tmp_addr = str_to_sockaddr_in4("192.168.1.102:8000"); // local port fo ep comm
    global_cfg.paa_ep= *tmp_addr;
    os_free(tmp_addr);
    
    
    global_cfg.eap_cfg = malloc(sizeof(pana_eap_peer_config_t));
    global_cfg.eap_cfg->identity = "alex.antone@gmail.com";
    global_cfg.eap_cfg->identity_len = strlen(global_cfg.eap_cfg->identity);
    global_cfg.eap_cfg->password = "CLEARTEXT TEST PASSWORD";
    global_cfg.eap_cfg->password_len = strlen(global_cfg.eap_cfg->password);
    global_cfg.rtx_interval = 10;
    global_cfg.rtx_max_count = 4;
    global_cfg.failed_sess_timeout = 60;  
    global_cfg.session_lifetime = 1800;  // 30 min 
    
    return RES_CFG_FILES_OK;
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
    
    exit_code = paa_main(&global_cfg);
    
    exit(exit_code);
    
}
