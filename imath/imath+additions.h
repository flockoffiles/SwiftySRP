//
//  imath+additions.h
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

#ifndef imath_additions_h
#define imath_additions_h

#include "imath.h"

extern mp_result mp_int_read_const_unsigned(mp_int z, const unsigned char *buf, int len);
extern mp_result mp_int_init_const_copy(mp_int z, const mpz_t* const old);
extern mp_result mp_int_const_copy(const mpz_t* a, mp_int c);           /* c = a     */

#endif /* imath_additions_h */
