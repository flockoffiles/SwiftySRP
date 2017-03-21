//
//  imath+additions.c
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

#include "imath+additions.h"

/**
 Read an mpz_t value from a (big endian) data buffer of the given length.
 
 @param z The mpz_t pointer which will hold the eventual value.
 @param buf Big ending data buffer from which to read the value.
 @param len Buffer length in bytes.
 @return MP_OK if successful; MP_MEMORY if out of memory.
 */
mp_result mp_int_read_const_unsigned(mp_int z, const unsigned char *buf, int len)
{
    // Ugly hack to cast away the const, but the mp_int_read_unsigned is NOT modifying the buffer.
    return mp_int_read_unsigned(z, (unsigned char *)buf, len);
}

/**
 Initialize an mpz_t value from another similar value.
 
 @param z The value to be initialized.
 @param old The value to initialize from.
 @return MP_OK if successful; MP_MEMORY if out of memory.
 */
mp_result mp_int_init_const_copy(mp_int z, const mpz_t* const old)
{
    // Assume that old won't be modified.
    return mp_int_init_copy(z, (mp_int)old);
}

/**
 Copy one value to another.
 
 @param a Value to copy from
 @param c Value to copy into
 @return MP_OK if successful; MP_MEMORY if out of memory.
 */
mp_result mp_int_const_copy(const mpz_t* a, mp_int c)
{
    // We assume that a won't be modified.
    return mp_int_copy((mp_int)a, c);
}
