/*
 * debug.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef DEBUG_H_
#define DEBUG_H_


#define dbg_printf(level,fmt,args...) \
    vprintf("[%s]: " fmt "\n", #level, ##args)


#define dbg_hexdump(level, title, buff, len)\
{\
    printf("[%s] - " title "\n", #level);\
    int _ix;\
    for (_ix=0 ; _ix<len; _ix++ ) {\
        printf("%02X ", (unsigned char) buff[_ix]);\
        if (((_ix + 1) & 0x0f) == 0)\
            puts("|");\
    }\
}


#endif /* DEBUG_H_ */
