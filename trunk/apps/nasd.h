/*
 * nasd.h
 *
 *  Created on: Apr 19, 2009
 *      Author: alex
 */

#ifndef NASD_H_
#define NASD_H_

#define NAS_DEF_PORT    7001
#define AAA_DEF_PORT    8001
#define EP_DEF_PORT     9001

#define RES_ARGS_OK             0x0000
#define RES_CFG_FILES_OK        0x0000

#define ERR_CODE                0x1000
#define ERR_BADARGS             0x1001
#define ERR_FILE_ERROR          0x1002
#define ERR_SOCK_ERROR          0x1003
#define ERR_BIND_SOCK           0x1004
#define ERR_CONNECT_SOCK        0x1005

#define NFO_HELP_REQ            0x2001


#define DEBUG(cmd) printf("#DEBUG# - %s [%d]: %s\n", __FILE__, __LINE__, #cmd); \
                   cmd

#endif /* NASD_H_ */
