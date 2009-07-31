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
    COMP_init( &a );
    COMP_init( &b );
    COMP_init( &r );

    if ( Context == NULL )
    	Context = BN_CTX_new();

    if(!BN_set_word(m, 43l))
    	goto err;
    BN_set_word(x, 38l);
    BN_set_word(y, 13l);
    BN_set_word(exp, 168l);
    BN_copy( &t ,m );

    if (!COMP_set(&a, x, y, m))
    	goto err;
    if (!COMP_pow(&r, &a, exp, m))
    	goto err;


    BN_free( &t );
    BN_free( x );
    BN_free( y );
    BN_free( exp );
    BN_free( m );
    COMP_free( &a );
    COMP_free( &b );
    COMP_free( &r );

	return 0;
err:
	BN_free( &t );
	BN_free( x );
	BN_free( y );
	BN_free( exp );
	BN_free( m );
	COMP_free( &a );
	COMP_free( &b );
	COMP_free( &r );

	return 0;
}
