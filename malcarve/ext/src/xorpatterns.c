/* 
 * Malcarve - Obfuscated payload extractor for malware samples
 * Copyright (C) 2016 Steve Henderson
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include "xorpatterns.h"

// not type safe
#define min(x, y) (x < y ? x : y)
#define max(x, y) (x > y ? x : y)
// how many chunks need to line up in a row to consider it a repeating pattern
#define CONTIGUOUS_PATTERN_CHECKS 4
// minimum number of bytes that need to match, effectlvely min pattern size
#define MIN_BYTES_MATCH 6

inline bool preserve_nulls(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        uint8_t *out) {
    // overly complicated as tries to handle indefinite keysizes
    // null or key byte and enough bytes for key
    if ((!buf[0] || buf[0] == key[0]) && keysize <= bufsize) {
        // copy nulls or key
        bool nulls = false;
        size_t j = 0;
        for (; j<keysize; j++) {
            if (j > 0 && buf[j] == 0 && !nulls) {
                break;
            }
            if (buf[j] == 0) {
                out[j] = 0;
                nulls = true;
            } else if (!nulls && buf[j] == key[j]) {
                out[j] = key[j];
            } else {
                break;
            }
        }
        // did we get to the end of keysize?
        // otherwise bytes to be overwritten with xor by caller
        if (j == keysize) {
            return true;
        }
    }
    return false;
}


void xor(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        bool null_preserve,
        uint8_t *out) {

    for (size_t i=0; i<bufsize; i+=keysize) {
        if (null_preserve && preserve_nulls(buf+i, bufsize-i, key, keysize, out+i)) {
            continue;
        }
        for (size_t j=0; j<min(keysize, bufsize-i); j++) {
            out[i+j] = buf[i+j] ^ key[j];
        }
    }
}


void xor_countup(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        int32_t step, size_t offset, bool null_preserve,
        uint8_t *out) {

    union {
        uint8_t bytes[8];
        uint64_t number;
    } tempkey;
    // todo: better error handling
    if (keysize > 8) return;

    uint64_t maxkey = 2<<(keysize*8-1);
    tempkey.number = (*((uint64_t*)key)+offset/keysize*step)%maxkey;

    for (size_t i=0; i<bufsize; i+=keysize) {
        if (null_preserve && preserve_nulls(buf+i, bufsize-i, tempkey.bytes, keysize, out+i)) {
            // have moved keysize bytes forward
            tempkey.number = (tempkey.number+step)%maxkey;
            continue;
        }
        // assumes little-endian
        for (size_t j=0; j<min(keysize, bufsize-i); j++) {
            out[i+j] = buf[i+j] ^ tempkey.bytes[j];
        }
        // increment key
        tempkey.number = (tempkey.number+step)%maxkey;
    }
}


void xor_rolling(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        bool decode, uint8_t *out) {

    const uint8_t *temp;
    // key is used for first xor
    temp = key;
    for (size_t i=0; i<bufsize; i+=keysize) {
        for (size_t j=0; j<min(keysize, bufsize-i); j++) {
            out[i+j] = buf[i+j] ^ temp[j];
        }
        // key updated to previous input/output byte depending on direction
        if (decode) {
            temp = buf+i;
        } else {
            temp = out+i;
        }
    }
}

bool keypattern(
        const uint8_t *pattern,
        const uint8_t *original, size_t origoffset, size_t maxkeysize,
        uint8_t *key, size_t *outsize,
        bool *null_preserve, int32_t *step) {

    // should prob check somewhere that pattern length is adequate
    for(size_t keysize=1; keysize<=maxkeysize; keysize++) {
        // mask off x num of bits to match keysize
        uint64_t keymask = (uint64_t)(2 << (keysize*8-1))-1;
        uint64_t pivot = 0;
        size_t off;
        bool stepcheck = false;
        *null_preserve = false;
        *step = 0;

        for(off=0; off<max(MIN_BYTES_MATCH, maxkeysize*CONTIGUOUS_PATTERN_CHECKS); off+=keysize) {
            uint64_t curr = (*(uint64_t*)(pattern+off)&keymask);
            uint64_t orig = (*(uint64_t*)(original+off)&keymask);
            if (!curr && !orig) {
                *null_preserve = true;
                continue;
            }
            if (stepcheck) {
                stepcheck = false;
                if (pivot == curr) {
                    *step = 0;
                // countdown no wrap
                } else if ((pivot <= keymask/2) && (curr < pivot)) {
                    *step = curr - pivot;
                // countdown wrapped
                } else if ((pivot <= keymask/2) && (curr > pivot) && (curr > keymask/2)) {
                    *step = -keymask-1+curr-pivot;
                // countdown no wrap
                } else if ((pivot > keymask/2) && (curr < pivot) && (curr > keymask/2)) {
                    *step = curr - pivot;
                // countup no wrap
                } else if (curr > pivot) {
                    *step = curr - pivot;
                // countup wrapped
                } else if (curr < pivot) {
                    *step = keymask-pivot+curr;
                }
                // unrealistic values?
                if (*step > 127 || *step < -127) {
                    break;
                }
            }
            if (!pivot) {
                pivot = curr;
                stepcheck = true;
            }
            uint64_t expected = (pivot+((*step)*(off/keysize)));
            if (keysize <4) {
                expected %= keymask+1;
            }
            // compare with first value
            if (curr != expected) {
                break;
            }
        }
        // got there... ship it!
        if (off >= CONTIGUOUS_PATTERN_CHECKS*keysize && off >= MIN_BYTES_MATCH) {
            // hope not nulls in first key
            // note: we need to rotate the key if we found it at odd offset
            // note: we also need to increment/decrement key based on step
            uint64_t k = pivot-(((*step)*(origoffset/keysize)));
            if (keysize<4) {
                k %= keymask+1;
            }
            for (size_t i=0; i<keysize; i++) {
                key[(i+origoffset)%keysize] = ((uint8_t *)&k)[i];
            }
            *outsize = keysize;
            return true;
        }
    }
    return false;
}


bool isrolling(
        const uint8_t *buf,
        const uint8_t *pattern,
        const size_t maxkeysize,
        size_t *outsize) {

    for(size_t keysize=1; keysize<=maxkeysize; keysize++) {
        // mask off x num of bits to match keysize
        uint64_t keymask = (uint64_t)(2 << (keysize*8-1))-1;
        size_t off=keysize;
        for(; off<CONTIGUOUS_PATTERN_CHECKS*maxkeysize; off+=keysize) {
            uint64_t plain = (*(uint64_t*)(pattern+off)&keymask);
            uint64_t curr = (*(uint64_t*)(buf+off)&keymask);
            uint64_t prev = (*(uint64_t*)(buf+off-keysize)&keymask);
            if (! ((curr ^ prev) == plain)) {
                break;
            }
        }
        if (off >= CONTIGUOUS_PATTERN_CHECKS*maxkeysize) {
            *outsize = keysize;
            return true;
        }
    }
    return false;
}


bool findxor(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *pattern, size_t patsize, size_t patoffset,
        size_t *offset, uint8_t *key, size_t *keysize,
        bool *null_preserve, int32_t *step, bool *rolling) {

    bool success = false;
    uint8_t *temp;
    // not big enough
    if (bufsize < patsize) {
        return success;
    }
    temp = malloc(patsize);
    if (NULL == temp) {
        return success;
    }
    *rolling = false;
    // step through whole buffer bytewise
    for (*offset = patoffset; (*offset)<bufsize-patsize+1; (*offset)++) {
        // try rolling detection
        success = isrolling(buf+(*offset), pattern,
                            min(8, (patsize/CONTIGUOUS_PATTERN_CHECKS)),
                            keysize);
        // need to determine start key from offset 0
        if (success) {
            *rolling = true;
            // this assumes pat at offset 0 not case for our pe search
            // really need knowledge of what to expect at off 0
            for (size_t k=0; k<*keysize; k++) { 
                    key[k] = buf[max((*offset)-patoffset, 0)] ^ pattern[k];
            }
        }
        // xor with pattern to see if we can detect a key repeating in result
        if (!success) {
            xor(buf+(*offset), patsize, pattern, patsize, 0, temp);
            success = keypattern(temp, pattern, patoffset,
                        min(8, (patsize/CONTIGUOUS_PATTERN_CHECKS)),
                        key, keysize, null_preserve, step);
        }
        if(success) {
            // we're returning the start of the 'thing' being searched
            // not where this particular pattern was found
            (*offset) -= patoffset;
            break;
        }
    }
    free(temp);
    return success;
}
