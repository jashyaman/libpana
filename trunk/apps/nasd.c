/*
 * nasd.c
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libpana.h>
#include <nasd.h>

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
        if (inet_pton(AF_INET, in_str, out_ip)<=0) {
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
        if (inet_pton(AF_INET, in_str, out_ip)<=0) {
            return -1;
        }
    }
    return 0;
}


/*
 * Variables that will hold the PANA configuration settings.
 */
static char * nasd_config_file = "/etc/pana/nasd.conf";
static uint16_t nas_listenport = NAS_DEF_PORT;
static uint32_t aaa_v4_ip = 0;
static uint16_t aaa_port = AAA_DEF_PORT;
static uint32_t ep_v4_ip = 0;
static uint16_t ep_port = EP_DEF_PORT;

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
        }
        else if ((strcmp(argv[ctoken++], "-e") == 0) && !(flags & CMD_FLAG_E)) {
            if (str_to_ip_port(argv[ctoken++], &ep_v4_ip, &ep_port) < 0) {
                puts("Incorrect EP ip:port address\n");
                return ERR_BADARGS;
            }
        }
        else if ((strcmp(argv[ctoken++], "-c") == 0) && !(flags & CMD_FLAG_C)) {
            nasd_config_file = argv[ctoken++];
        }
        else if ((strcmp(argv[ctoken++], "-d") == 0) && !(flags & CMD_FLAG_D)) {
            dhcp_lease_file = argv[ctoken++];
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
    
    return RES_CFG_FILES_OK;
}

int main(char * argv[], int argc)
{
    struct sockaddr_in nas_sockaddr;
    struct sockaddr_in aaa_sockaddr;
    struct sockaddr_in ep_sockaddr;
    int pana_sockfd;
    int ep_sockfd;
    int aaa_sockfd;
    
    
    int exit_code = 0;
    
    exit_code = process_args(argv, argc);
    if (exit_code > ERR_CODE) {
        exit(exit_code);
    }

    exit_code = process_config_files();
    if (exit_code > ERR_CODE) {
        exit(exit_code);
    }

    memset(&pac_sockaddr, 0, sizeof pac_sockaddr);
    nas_sockaddr.sin_family = AF_INET;
    nas_sockaddr.sin_addr.s_addr = INADDR_ANY; 
    nas_sockaddr.sin_port = htons(pacd_port);
    
    memset(&aaa_sockaddr, 0, sizeof aaa_sockaddr);
    aaa_sockaddr.sin_family = AF_INET;
    aaa_sockaddr.sin_addr.s_addr = aaa_v4_ip;
    aaa_sockaddr.sin_port = htons(aaa_port);

    memset(&ep_sockaddr, 0, sizeof ep_sockaddr);
    ep_sockaddr.sin_family = AF_INET;
    ep_sockaddr.sin_addr.s_addr = ep_v4_ip;
    ep_sockaddr.sin_port = htons(ep_port);
    
    /*
     * Setup the PANA socket
     */
    if ((pana_sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        exit(ERR_SOCK_ERROR);
    }
    

    if ((bind(pana_sockfd, &nas_sockaddr, sizeof nas_sockaddr)) < 0) {
        close(pana_sockfd);
        exit(ERR_BIND_SOCK);
    }
    
    /*
     * Setup the AAA socket
     * TODO:
     */
    
    
    /*
     * Setup the EP socket
     * TODO:
     */
    
  
    /*
     * Start the PANA session
     */
    
    
    
    close(pana_sockfd);
    close(aaa_sockfd);
    close(ep_sockfd);
    
    return exit_code;
    
}
