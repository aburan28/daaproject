/*
 * func_test.c
 *
 *  Created on: 2009-7-29
 *      Author: xiaoyi
 */

#include "daa.h"
#include "bi.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#if 0 // test COMPLEX lib
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
#endif
int main()
{
    BIGNUM   *x, *y, *exp, *m, *order, *cof;
    BIGNUM   t, store[30];
    COMPLEX  *a, *b, *r;
    EC_POINT *point, *Q;
    int      i;

    x = BN_new();
    y = BN_new();
    order = BN_new();
    exp = BN_new();
    m = BN_new();

    a = COMP_new();
    b = COMP_new();
    r = COMP_new();
    for( i = 0; i < 30; i++ )
    	BN_init( &(store[i]) );

    if ( Context == NULL )
    	Context = BN_CTX_new();

    bi_init( &malloc );

    group = EC_GROUP_new( EC_GFp_simple_method() );
    if ( group == NULL )
    	goto err;

    if(!BN_set_word(m, 43l))
    	goto err;
    BN_set_word(x, 1l);
    BN_set_word(y, 0l);

    if ( !EC_GROUP_set_curve_GFp( group, m, x, y, Context) )
    	goto err;

    BN_set_word(x, 23l);
    BN_set_word(y, 8l);
    BN_set_word(order, 11l);

    point = EC_POINT_new( group );
    EC_POINT_set_affine_coordinates_GFp( group, point, x, y, Context );

    cof = BN_new();
    BN_set_word( cof, 4 );
    EC_GROUP_set_generator( group, point, order, cof );

    if ( EC_GROUP_check( group, Context ) )
    	printf(" group set is ok \n");

    TSS_DAA_ISSUER_KEY   issuer_key;
    TSS_DAA_ISSUER_PROOF issuer_proof;
    TSS_DAA_JOIN_issuer_setup(&issuer_key, &issuer_proof);


//    printf("\n");
//    BN_set_word(x, 41l);
//    BN_mod_inverse(x, x, m, Context);
//    BN_print_fp(stdout, x);
//
//    printf("\n");
//    BN_set_word(x, 11l);
//    BN_mod_inverse(x, x, m, Context);
//    BN_print_fp(stdout, x);

    char *str = "abcdefghijklmnop";
    Q = map_to_point( str );

    BN_set_word(x, 23l);
    BN_set_word(y, 8l);
    BN_set_word(order, 11l);

    Q = EC_POINT_new( group );
    EC_POINT_set_affine_coordinates_GFp( group, Q, x, y, Context );

    Tate( point, Q, order, 0,  store, a );
    printf("tate pair  t(p, Q) =:\n a.x: ");
    BN_print_fp(stdout, &a->x);
    printf("\na.y: ");
    BN_print_fp(stdout, &a->y);

    EC_POINT_dbl( group, point, point, Context);
    EC_POINT_get_affine_coordinates_GFp( group, point, x, y, Context);
    printf("2A.x =:\n");
    BN_print_fp(stdout, x);
    printf("2P.y= :\n");
    BN_print_fp(stdout, y);

    Tate( point, Q, order, 0,  store, a );
    printf("tate pair  t(2p, Q) =:\n a.x: ");
    BN_print_fp(stdout, &a->x);
    printf("\na.y: ");
    BN_print_fp(stdout, &a->y);

    BN_free( x );
    BN_free( y );
    BN_free( exp );
    BN_free( m );
    BN_free( order );
    BN_free( cof );

    COMP_free( a );
    COMP_free( b );
    COMP_free( r );

	return 0;
err:
	BN_free( &t );
	BN_free( x );
	BN_free( y );
	BN_free( exp );
	BN_free( m );
    BN_free( order );
    BN_free( cof );

	COMP_free( a );
	COMP_free( b );
	COMP_free( r );

	return 0;
}
