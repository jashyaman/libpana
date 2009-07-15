/*
 * debug.c
 *
 *  Created on: Jul 12, 2009
 *      Author: alex
 */

#include "includes.h"
#include "debug.h"

void dbgi_hexdump(const char * const level, const char * const title,
                  const unsigned char * const buff, unsigned int len)
{
    int _ix;
    printf("[%s] - %s\n", level, title);
    
    for (_ix=0 ; _ix<len; _ix++ ) {
        printf("%02X ", buff[_ix]);
        if (((_ix + 1) & 0x0f) == 0)
            puts("|");
    }
    puts("");
}


#define DBG_LINEBUFF_LEN 100
void dbgi_asciihexdump(const char * const level, const char * const title,
                      const unsigned char * const buff, unsigned int len)
{
    char linebuff[DBG_LINEBUFF_LEN];
    char * lx;
    unsigned char * px;
    int ix,jx,cx;
    printf("[%s] - %s -%d-\n", level, title, len);
    
    for (ix=0 ; ix<len; ix += 0x10 ) {
        bzero(linebuff, sizeof(linebuff));
        px = buff + ix;
        lx = linebuff;
        cx = (len - ix > 0xf) ? 0x10 : len - ix; 
        for (jx=0; jx < cx; jx++ , lx+=3) {
            sprintf(lx, "%02X ", px[jx]);
        }
        for (jx; jx < 0x10; jx++, lx+=3) {
            sprintf(lx, "   ");
        }
        
        sprintf(lx, "|");
        lx++;
        
        for (jx=0; jx < cx; jx++, lx+=2) {
            sprintf(lx, "%c.", (px[jx] > 0x20) ? px[jx] : '.');
        }
        for (jx; jx < 0x10; jx++, lx+=2) {
            sprintf(lx, "..");
        }
        printf("%s\n",linebuff);
    }
}
