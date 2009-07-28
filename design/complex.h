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
#define  WINDOW_SIZE 5

BN_CTX *Context;

// complex number a + bi
typedef struct complex_st{

	BIGNUM x;

	BIGNUM y;

}COMPLEX;

int complex_iszero(COMPLEX *a)
{
    if ( BN_is_zero(&a->x) == 1 && BN_is_zero(&a->y) == 1 )
    	return 1;
    return 0;
}

// res = x + y
COMPLEX *Add( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m )
{
	BN_mod_add( &r->x, &a->x, &b->x, m, Context );
	BN_mod_add( &r->y, &a->y, &b->y, m, Context );

	return r;

}

/* a = b */
int Copy ( COMPLEX *a, COMPLEX *b )
{
	if ( a == b)
		return 0;

	BN_copy( &a->x, &b->x);
	BN_copy( &a->y, &b->y);

	return 0;
}

// res = -x + (-y)i
COMPLEX *Negate( COMPLEX *r, COMPLEX *a, BIGNUM *m )
{
	Copy( r, a );

	/* r->x is neg*/
	if (BN_is_negative(&r-x))
		BN_set_negative( &r->x, 0);
	else
		BN_set_negative( &r->x, 1);

	/* r->y is neg*/
	if (BN_is_negative(&r-y))
		BN_set_negative( &r->y, 0);
	else
		BN_set_negative( &r->y, 0);

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

	BN_mod_sub( &r->x, &tmp1, &tmp2, m, Context);

    return r;
}

// if x = a + bi
//    res = a - bi
COMPLEX *Conj( COMPLEX *r, COMPLEX *a, BIGNUM * m )
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

	ret = BN_mod_add( &sqr1, &sqr1, &sqr2, m, Context);
	if ( ret )
		return NULL;

	if ( !BN_mod_inverse( &sqr2, &sqr1, m, Context) )
		return NULL;

	Conj( r, a, m );

	ret = BN_mod_mul( &r->x, &r->x, &sqr2, m, Context );
	if ( ret )
		return NULL;

	ret = BN_mod_mul( &r->y, &r->y, &sqr2, m, Context );
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

int Window( BIGNUM *a, int i, int *nbs, int *nzs, int window_size)
{
	int j ,r ,w;
	w = window_size;

	*nbs = 1;
	*nzs = 0;

	if (!BN_is_bit_set(a, i))
		return 0;

	if ( (i - w + 1) < 0 )
		w = i + 1;

	r = 1;
	for ( j = i - 1; j > i-w; j-- )
	{
		( *nbs )++;
		r *= 2;

		if ( BN_is_bit_set(a, j) )
			r += 1;

		if ( (r % 4) == 0 )
		{
			r /= 4;
			*nbs -= 2;
			*nzs = 2;
			break;
		}
	}
	if ( (r % 2) == 0 )
	{
		r /= 2;
		*nzs = 1;
		( *nbs )--;
	}
	return r;

}

/*int BN_is_bit_set(const BIGNUM *a, int n);测试是否已经设置，1表示已设置, returns 1 if the bit is set(1), 0 otherwise*/

/* res = x ^exp % mod
 * sliding window for speeding up
 *
 */
COMPLEX *Pow( COMPLEX *r, COMPLEX *a, BIGNUM * b, BIGNUM * m )
{
	/* slid window */
	int i, j, nb, n, nbw, nzs, ret;
	COMPLEX  u, u2, t[16];

	if ( r == NULL )
		return r;

	if (complex_iszero(a))
	{
		BN_set_word( &r->x, (BN_ULONG)0 );
		BN_set_word( &r->y, (BN_ULONG)0 );
		return r;
	}

	if (BN_is_zero( b )) /* a^b = 1 */
	{
		BN_set_word( &r->x, (BN_ULONG)1 );
		BN_set_word( &r->y, (BN_ULONG)0 );
		return r;
	}

	/* r = a */
	ret = Copy( &u, a );
	if (ret != 0)
		return NULL;

	if (BN_is_word( b, 1 ))
	{
		Copy( r, a);
		return r;
	}

	Mul( &u2, &u, &u, m);
	Copy( &t[0], &u );
	for ( i = 1; i < 16; i++)
		Mul( &t[i], &t[i-1], &u2, m);

	nb = BN_num_bits(b);
	if (nb > 1)
	{
		for ( i = nb -2; i >= 0; )
		{
			n = Window( b, i, &nbw, &nzs, WINDOW_SIZE);
			for ( j = 0; j < nbw; j++ )
				Mul( &u, &u, &u , m);

			if ( n > 0 )
				Mul( &u, &u, &t[n/2], m);

			i -= nbw;
			if (nzs)
			{
				for( j = 0; j< nzs; j++)
				   Mul(&u, &u, &u, m);

				i -= nzs;
			}
		}
	}
	ret = Copy(r, &u);
	return r;
}

#ifdef  __cplusplus
}
#endif
#endif /* COMPLEX_H_ */
