//
//  imath+additions.c
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

#include "imath+additions.h"

mp_result mp_int_read_const_unsigned(mp_int z, const unsigned char *buf, int len)
{
    // Ugly hack to cast away the const, but the mp_int_read_unsigned is NOT modifying the buffer.
    return mp_int_read_unsigned(z, (unsigned char *)buf, len);
}

mp_result mp_int_init_const_copy(mp_int z, const mpz_t* const old)
{
    // Assume that old won't be modified.
    return mp_int_init_copy(z, (mp_int)old);
}

mp_result mp_int_const_copy(const mpz_t* a, mp_int c)
{
    // We assume that a won't be modified.
    return mp_int_copy((mp_int)a, c);
}
