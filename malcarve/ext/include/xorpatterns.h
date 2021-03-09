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

#ifndef XORPATTERNS_H
#define XORPATTERNS_H

#include <stdint.h>
#include <stdbool.h>

bool preserve_nulls(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        uint8_t *out); 

void xor(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        bool null_preserve,
        uint8_t *out);

void xor_countup(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        int32_t step, size_t offset, bool null_preserve,
        uint8_t *out);

void xor_rolling(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *key, size_t keysize,
        bool decode, uint8_t *out);

bool keypattern(
        const uint8_t *pattern,
        const uint8_t *original, size_t origoffset,
        size_t maxkeysize,
        uint8_t *key, size_t *keysize,
        bool *null_preserve, int32_t *step);

bool isrolling(
        const uint8_t *buf,
        const uint8_t *pattern,
        size_t maxkeysize,
        size_t *keysize);

bool findxor(
        const uint8_t *buf, size_t bufsize,
        const uint8_t *pattern, size_t patsize, size_t patoffset,
        size_t *offset, uint8_t *key, size_t *keysize,
        bool *null_preserve, int32_t *step, bool *rolling);

#endif

