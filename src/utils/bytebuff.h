/*
 * bytebuff.h
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#ifndef BYTEBUFF_H_
#define BYTEBUFF_H_

typedef struct bytebuff {
    /* header */
    size_t size;
    size_t used;
    /* data will follow*/
} bytebuff_t;

uint8_t * bytebuff_data(bytebuff_t * buff);
bytebuff_t * bytebuff_alloc(size_t size);
bytebuff_t * bytebuff_dup(bytebuff_t * src);
bytebuff_t * bytebuff_from_bytes(const uint8_t * src, size_t size);

#define free_bytebuff(b) free((b))

#endif /* BYTEBUFF_H_ */
