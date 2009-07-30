/*
 * func_test.c
 *
 *  Created on: 2009-7-29
 *      Author: xiaoyi
 */

#include "daa.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

int main()
{
    BIGNUM *x, *y, *exp, *m;
    BIGNUM t;
    COMPLEX a, b, r;

    BN_init( &t );
    x = BN_new();
    y = BN_new();
    exp = BN_new();
    m = BN_new();

    if(!BN_set_word(m, 43l))
    	return NULL;
    BN_set_word(x, 11l);
    BN_set_word(y, 3l);
    BN_set_word(exp, 2l);
    BN_copy( &t ,m );

    COMP_set(&a, x, y, m);
    COMP_pow(&r, &a, exp, m);

	return 0;
}
