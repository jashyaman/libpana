/*
 * bytebuff.c
 *
 *  Created on: Jul 11, 2009
 *      Author: alex
 */

#include "includes.h"
#include "util.h"

#include "bytebuff.h"


uint8_t * bytebuff_data(bytebuff_t * buff) {
    return (uint8_t *)(buff + 1);
}


bytebuff_t * bytebuff_alloc(size_t size) {
    bytebuff_t * out = zalloc(sizeof(bytebuff_t) + size);
    if (out == NULL) {
        return NULL;
    }
    out->size = size;
    out->used = 0;
    return out;
}

bytebuff_t * bytebuff_from_bytes(const uint8_t * src, size_t size) {
    bytebuff_t * out = malloc(sizeof(bytebuff_t) + size);
    if (out == NULL) {
        return NULL;
    }
    
    memcpy(bytebuff_data(out), src, size);
    out->size = size;
    out->used = size;
    
    return out;
}




