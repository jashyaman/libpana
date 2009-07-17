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
    short flags = 0x0000; // the p,s,e,c;
    int ctoken = 1;       // skip command name
    char * pos = NULL;
    unsigned long tmp_parsing_val = 0;
    ip_port_t * tmp_ipporv = NULL;

    while (ctoken < argc) {
        if ((strcmp(argv[ctoken++], "-h") == 0)) {
            puts(NASD_USAGE_MSG);
            return NFO_HELP_REQ;
        }
        else if ((strcmp(argv[ctoken++], "-p") == 0) && !(flags & CMD_FLAG_P)) {
            /*
             * Local NAS port number to listen to PaCs
             */
            tmp_parsing_val = strtoul(argv[ctoken++], &pos, DECIMAL_BASE);
            if (pos != '\0' || tmp_parsing_val > MAX_PORTN) {
                puts("Incorrect port number: should be in 0-65365\n");
                return ERR_BADARGS;
            }
            global_cfg.paa_pana.port = tmp_parsing_val;
        }
        else if ((strcmp(argv[ctoken++], "-e") == 0) && !(flags & CMD_FLAG_E)) {
            if (!(tmp_ipporv = str_to_ip_port(argv[ctoken++]))) {
                puts("Incorrect ip:port address\n");
                return ERR_BADARGS;
            }
            global_cfg.ep = *tmp_ipporv;
            os_free(tmp_ipporv);
        }
        else if ((strcmp(argv[ctoken++], "-c") == 0) && !(flags & CMD_FLAG_C)) {
            nasd_config_file = argv[ctoken++];
        }
        else {
            puts("Bad or duplicate arguments.\n");
            puts(NASD_USAGE_MSG);
            return ERR_BADARGS;
        }
    }
    
    return RES_ARGS_OK;

}

int process_config_files() {
    /*
     * TODO: implement parsing of config and dhcp-lease file
     */
    ip_port_t * tmp_iport;

    tmp_iport = str_to_ip_port("192.168.1.102:8001");// remote ep address
    global_cfg.ep= *tmp_iport;
    os_free(tmp_iport);

    tmp_iport = str_to_ip_port("192.168.1.102:7000");  // local port fo incomming pana comms
    global_cfg.paa_pana= *tmp_iport;
    os_free(tmp_iport);
    
    tmp_iport = str_to_ip_port("192.168.1.102:8000"); // local port fo ep comm
    global_cfg.paa_ep= *tmp_iport;
    os_free(tmp_iport);
    
    
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
