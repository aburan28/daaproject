/*
 * complex.h
 *
 *  Created on: 2009-7-26
 *      Author: xiaoyi
 */

#ifndef COMPLEX_H_
#define COMPLEX_H_

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#ifdef  __cplusplus
extern "C" {
#endif
//typedef struct bignum_st BIGNUM; //define in ossl_type.h

BN_CTX *Context;

// complex number a + bi
typedef struct complex_st{

	BIGNUM x;

	BIGNUM y;

}COMPLEX;


// res = x + y
COMPLEX *Add( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUN *m )
{
	BN_mod_add( &r->x, &a->x, &b->x, m, Context );
	BN_mod_add( &r->y, &a->y, &b->y, m, Context );

	return r;

}

int Copy ( COMPLEX *a, COMPLEX *b )
{
	if ( a == b)
		return 0;

	BN_copy( &a->x, &a->x);
	BN_copy( &b->y, &a->y);

	return 0;
}

// res = -x + (-y)i
COMPLEX *Negate( COMPLEX *r, COMPLEX *a, BIGNUM *m )
{
	Copy( r, a );

	BN_set_negative( &r->x, 1);
	BN_set_negative( &r->y, 1);

	return r;

}

// res = x - y
COMPLEX *Sub( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m )
{
	BN_mod_sub( &r->x, &a->x, &b->x, m, Context );
	BN_mod_sub( &r->y, &a->y, &b->y, m, Context );

	return r;
}

// res = (xa + xbi) * (xb + ybi) = xa * xb - ya * yb + ((xa + ya) * (xb + yb) - xa * xb - ya * yb) % m
COMPLEX *Mul( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM * m )
{
	BIGNUM tmp1, tmp2, tmp3;

	BN_mod_mul( &tmp1, &a->x, &b->x, m, Context);
	BN_mod_mul( &tmp2, &a->y, &b->y, m, Context);

	BN_mod_add( &tmp3, &a->x, &a->y, m, Context);
	BN_mod_add( &r->y, &b->x, &b->y, m, Context);
	BN_mod_mul( &r->y, &tmp3, &r->y, m, Context);

	BN_mod_sub( &r->y, &r->y, &tmp1, m ,Context);
	BN_mod_sub( &r->y, &r->y, &tmp2, m, Context);

	BN_mod_sub( &r->x, &temp1, &temp2, m, Context);

    return r;
}

// if x = a + bi
//    res = a - bi
COMPLEX *Conj( BIGNUM *r, COMPLEX *a, BIGNUM * m )
{

	Copy( r, a );
	BN_set_negative( &r->y, 1);

	return r;

}

// r = 1/a = (x - bi)/(a * a + b * b)
COMPLEX *Inver( COMPLEX *r, COMPLEX *a, BIGNUM * m )
{
	BIGNUM sqr1, sqr2;
	int ret = 0;

	// TODO check the return value
	ret = BN_mod_sqr( &sqr1, &a->x, m, Context);
	if ( ret )
		return NULL;

	ret = BN_mod_sqr( &sqr2, &a->x, m, Context);
	if ( ret )
		return NULL;

	ret = BN_mod_add( &sqr1, &sqr2, m, Context);
	if ( ret )
		return NULL;

	ret = BN_mod_inverse( &sqr2, &sqr1, m, Context);
	if ( ret )
		return NULL;

	Conj( r, a, m );

	ret = BN_mod_mul( r->x, &r->x, &sqr2, m, Context );
	if ( ret )
		return NULL;

	ret = BN_mod_mul( r->y, &r->y, &sqr2, m, Context );
	if ( ret )
		return NULL;

	return r;
}

// r = a/b = a * (1/b)
COMPLEX *Div( COMPLEX *r, COMPLEX *a, COMPLEX * b, BIGNUM * m )
{
	COMPLEX ret;
	Inver( &ret, b, m );
	Mul( &ret, &ret, a, m );
	Copy( r, &ret );

	return r;
}

// res = x ^exp % mod
COMPLEX *Pow( COMPLEX *r, COMPLEX *a, COMPLEX * b, BIGNUM * m )
{
	//TODO slid window
}

#ifdef  __cplusplus
}
#endif
#endif /* COMPLEX_H_ */
