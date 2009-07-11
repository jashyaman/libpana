/*
 * debug.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef DEBUG_H_
#define DEBUG_H_


#define dbg_printf(level,fmt, args...) \
    printf("[%s]: " fmt "\n" , #level, ##args)

#define wpa_hexdump(level, title, buff, len)\
{\
    printf("[%s] - " title "\n", #level);\
    int _ix;\
    for (_ix=0 ; _ix<len; _ix++ ) {\
        printf("%02X ", *(((char*) buff) + _ix));\
        if (((_ix + 1) & 0x0f) == 0)\
            puts("|");\
    }\
    puts("");\
}

#define DEBUG(cmd) \
    printf("#DEBUG: %s [%d]: %s\n", __FILE__, __LINE__, #cmd); \
    cmd


#endif /* DEBUG_H_ */
