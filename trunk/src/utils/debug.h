/*
 * debug.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef DEBUG_H_
#define DEBUG_H_


void dbgi_hexdump(const char * const level, const char * const title,
                  const unsigned char * const buff, unsigned int len);

void dbgi_asciihexdump(const char * const level, const char * const title,
                      const unsigned char * const buff, unsigned int len);

#define dbg_printf(level,fmt, args...) \
    printf("[%s]: " fmt "\n" , #level, ##args)

#define dbg_hexdump(level, title, buff, len) dbgi_hexdump(#level, title, buff, len)

#define dbg_asciihexdump(level, title, buff, len) dbgi_asciihexdump(#level, title, buff, len)


#define DEBUG(cmd) do{\
    printf("#DEBUG: %s [%d]: %s\n", __FILE__, __LINE__, #cmd); \
    cmd; } while(0)


#endif /* DEBUG_H_ */
