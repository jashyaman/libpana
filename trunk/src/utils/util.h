/*
 * util.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h>

#ifdef FALSE
#undef FALSE
#endif
#ifdef TRUE
#undef TRUE
#endif

typedef enum { FALSE = 0, TRUE = 1 } Boolean;

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t


#define zalloc(size) calloc((size), 1)

#define smalloc(data_type)  malloc(sizeof(data_type))
#define szalloc(data_type)  zalloc(sizeof(data_type))



#define host_to_be16 htons
#define host_to_be32 htonl

#define be_to_host16 ntohs
#define be_to_host32 ntohl

static inline u16 bytes_to_be16(const uint8_t * buff) {
    return (buff[0] << 8) | buff[1];
}

static inline u32 bytes_to_be24(const uint8_t* buff) {
    return (buff[0] << 16) | (buff[1] << 8) | buff[2];
}

static inline u32 bytes_to_be32(const uint8_t * buff) {
    return (buff[0] << 24u) | (buff[1] << 16u) | (buff[2] << 8u) | buff[3];
}

static inline void buff_insert_u8(uint8_t * buff, uint8_t val) {
    buff[0] = val;
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
