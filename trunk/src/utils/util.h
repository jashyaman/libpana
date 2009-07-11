/*
 * util.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef UTIL_H_
#define UTIL_H_

#ifdef FALSE
#undef FALSE
#endif
#ifdef TRUE
#undef TRUE
#endif
typedef enum { FALSE = 0, TRUE = 1 } Boolean;

#define NULL = 0;

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t

static inline uin16_t bytes_to_be16(uint8_t * buff) {
    return (buff[0] << 8) | buff[1];
}

static inline uin32_t bytes_to_be24(uint8_t* buff) {
    return (buff[0] << 16) | (buff[1] << 8) | buff[2];
}

static inline uin32_t bytes_to_be32(uint8_t * buff) {
    return (buff[0] << 24u) | (buff[1] << 16u) | (buff[2] << 8u) | buff[3];
}


static inline void buff_insert_be16(uint8_t * buff, uint16_t val) {
    buff[0] = (val >> 8) & 0xff;
    buff[1] = (val >> 0) & 0xff;
}

static inline void buff_insert_be24(uint8_t * buff, uint32_t val) {
    buff[0] = (val >> 16) & 0xff;
    buff[1] = (val >> 8) & 0xff;
    buff[2] = (val >> 0) & 0xff;
}

static inline void buff_insert_be32(uint8_t * buff, uint32_t val) {
    buff[0] = (val >> 24) & 0xff;
    buff[1] = (val >> 16) & 0xff;
    buff[2] = (val >> 8) & 0xff;
    buff[3] = (val >> 0) & 0xff;
}



#endif /* UTIL_H_ */
