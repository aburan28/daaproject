/*
 * complex.c
 *
 *  Created on: 2009-7-30
 *      Author: xiaoyi
 */
#include "complex.h"

void COMP_init( COMPLEX *a )
{
	BN_init( &a->x );
	BN_init( &a->y );
}

COMPLEX *COMP_new( void )
{
	COMPLEX * ret;

	ret = ( COMPLEX * )OPENSSL_malloc( sizeof( COMPLEX ) );
	if ( !ret )
		return NULL;

	COMP_init( ret );

	return ret;
}

void COMP_free( COMPLEX *a )
{
	if ( a == NULL )
		return ;

	BN_free( &a->x );
	BN_free( &a->y );

}

int COMP_is_zero(COMPLEX *a)
{
    if ( BN_is_zero(&a->x) == 1 && BN_is_zero(&a->y) == 1 )
    	return 1;

    return 0;
}

int COMP_set(COMPLEX *a, BIGNUM *x, BIGNUM *y, BIGNUM *m)
{
	BIGNUM r;

	BN_init( &r );

	if ( a == NULL || x == NULL || y == NULL || m == NULL )
	{
		return 0;
	}
	else
	{
		BN_mod( &r, x, m, Context );
		if (!BN_copy( &a->x, &r))
		{
			BN_free( &r );
			return 0;
		}
		BN_mod( &r, y, m, Context );
		if (!BN_copy (&a->y, &r))
		{
			BN_free( &r );
			return 0;
		}

	}

	BN_free( &r );
	return 1;
}

// res = x + y
COMPLEX *COMP_add( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m )
{
	if ( r == NULL || a == NULL || b == NULL || m == NULL)
		return NULL;

	if (!BN_mod_add( &r->x, &a->x, &b->x, m, Context ))
			return NULL;
	if (!BN_mod_add( &r->y, &a->y, &b->y, m, Context ))
		return NULL;

	return r;

}

/* a = b
 * return :success 1, failed 0
 */

int COMP_copy ( COMPLEX *a, COMPLEX *b )
{
	if ( a == b)
		return 1;

	if(!BN_copy( &a->x, &b->x))
		return 0;

	if(!BN_copy( &a->y, &b->y))
		return 0;

	return 1;
}

/* x = a->x, y = a->y */
int COMP_get( COMPLEX *a, BIGNUM *x, BIGNUM *y )
{
	if ( a == NULL )
		return 0;

	if ( x != NULL )
		BN_copy( x, &a->x );

	if ( y != NULL )
		BN_copy( y, &a->y );

	return 1;
}

/* Compare complex number a, b, 0: a == b, 1: a != b*/
int COMP_cmp( COMPLEX *a, COMPLEX *b )
{
	if ( a == NULL || b == NULL )
		return -1;

	if ( BN_cmp( &a->x, &b->x ) || BN_cmp(&a->y, &b->y))
		return 1;

	return 0;
}

// res = -x + (-y)i
COMPLEX *COMP_negate( COMPLEX *r, COMPLEX *a, BIGNUM *m )
{
	if ( r == NULL || a == NULL || m == NULL)
		return NULL ;

	if (! COMP_copy( r, a ))
		return NULL;

	/* r->x is neg*/
	if (BN_is_negative(&r->x))
		BN_set_negative( &r->x, 0);
	else
		BN_set_negative( &r->x, 1);

	/* r->y is neg*/
	if (BN_is_negative(&r->y))
		BN_set_negative( &r->y, 0);
	else
		BN_set_negative( &r->y, 0);

	return r;

}

// res = x - y
COMPLEX *COMP_sub( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m )
{
	if ( r == NULL || a == NULL || b == NULL || m == NULL )
		return NULL;

	if (!BN_mod_sub( &r->x, &a->x, &b->x, m, Context ))
		return NULL;

	if (!BN_mod_sub( &r->y, &a->y, &b->y, m, Context ))
		return NULL;

	return r;
}

// res = (xa + xbi) * (xb + ybi) = xa * xb - ya * yb + ((xa + ya) * (xb + yb) - xa * xb - ya * yb) % m
COMPLEX *COMP_mul( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM * m )
{
	BIGNUM *tmp1, *tmp2, *tmp3;

	if ( r == NULL || a == NULL || b == NULL || m == NULL )
		return NULL;

	tmp1 = BN_new();
	tmp2 = BN_new();
	tmp3 = BN_new();


	if (!BN_mod_mul( tmp1, &a->x, &b->x, m, Context))
		goto err;
	if (!BN_mod_mul( tmp2, &a->y, &b->y, m, Context))
		goto err;

	if (!BN_mod_add( tmp3, &a->x, &a->y, m, Context))
		goto err;
	if (!BN_mod_add( &r->y, &b->x, &b->y, m, Context))
		goto err;
	if (!BN_mod_mul( &r->y, tmp3, &r->y, m, Context))
		goto err;

	if (!BN_mod_sub( &r->y, &r->y, tmp1, m ,Context))
		goto err;
	if (!BN_mod_sub( &r->y, &r->y, tmp2, m, Context))
		goto err;

	if (!BN_mod_sub( &r->x, tmp1, tmp2, m, Context))
		goto err;

    BN_free( tmp1 );
    BN_free( tmp2 );
    BN_free( tmp3 );

    return r;

err:

	BN_free( tmp1 );
    BN_free( tmp2 );
    BN_free( tmp3 );

    return NULL;
}

// if x = a + bi
//    res = a - bi
COMPLEX *COMP_conj( COMPLEX *r, COMPLEX *a, BIGNUM * m )
{
	if ( r == NULL || a == NULL || m == NULL)
		return NULL ;

	if (!COMP_copy( r, a ))
		return NULL;

	BN_set_negative( &r->y, 1);

	return r;

}

// r = 1/a = (x - bi)/(a * a + b * b)
COMPLEX *COMP_inver( COMPLEX *r, COMPLEX *a, BIGNUM * m )
{
	BIGNUM sqr1, sqr2;
	int ret = 0;

	if ( r == NULL || a == NULL || m == NULL)
		return NULL ;

	BN_init( &sqr1 );
	BN_init( &sqr2 );

	// TODO check the return value
	ret = BN_mod_sqr( &sqr1, &a->x, m, Context);
	if ( !ret )
	{
		BN_free( &sqr1 );
		BN_free( &sqr2 );
		return NULL;
	}

	ret = BN_mod_sqr( &sqr2, &a->x, m, Context);
	if ( !ret )
	{
		BN_free( &sqr1 );
		BN_free( &sqr2 );
		return NULL;
	}

	ret = BN_mod_add( &sqr1, &sqr1, &sqr2, m, Context);
	if ( !ret )
	{
		BN_free( &sqr1 );
		BN_free( &sqr2 );
		return NULL;
	}

	if ( !BN_mod_inverse( &sqr2, &sqr1, m, Context) )
	{
		BN_free( &sqr1 );
		BN_free( &sqr2 );
		return NULL;
	}

	COMP_conj( r, a, m );

	ret = BN_mod_mul( &r->x, &r->x, &sqr2, m, Context );
	if ( !ret )
	{
		BN_free( &sqr1 );
		BN_free( &sqr2 );
		return NULL;
	}

	ret = BN_mod_mul( &r->y, &r->y, &sqr2, m, Context );
	if ( !ret )
	{
		BN_free( &sqr1 );
		BN_free( &sqr2 );
		return NULL;
	}

	return r;
}

// r = a/b = a * (1/b)
COMPLEX *COMP_div( COMPLEX *r, COMPLEX *a, COMPLEX * b, BIGNUM * m )
{
	COMPLEX ret;

	if ( r == NULL || a == NULL || b == NULL || m == NULL)
		return NULL ;

	COMP_init( &ret );

	if (!COMP_inver( &ret, b, m ))
		goto err;

	if (!COMP_mul( &ret, &ret, a, m ))
		goto err;

	if ( !COMP_copy( r, &ret ))
		goto err;

	COMP_free( &ret );

	return r;

err:
	COMP_free( &ret );

	return NULL;
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
COMPLEX *COMP_pow( COMPLEX *r, COMPLEX *a, BIGNUM * b, BIGNUM * m )
{
	/* slid window */
	int i, j, nb, n, nbw, nzs, ret;
	COMPLEX  u, u2, t[16];

	if ( r == NULL || a == NULL || b == NULL || m == NULL )
		return NULL;

	COMP_init( &u );
	COMP_init( &u2 );
	for ( i = 0; i < 16; i++)
		COMP_init( &t[i] );

	if ( COMP_is_zero(a) )
	{
		if (!BN_set_word( &r->x, (BN_ULONG)0 ))
			goto err;
		if (!BN_set_word( &r->y, (BN_ULONG)0 ))
			goto err;

		goto out;
	}

	if (BN_is_zero( b )) /* a^b = 1 */
	{
		if (!BN_set_word( &r->x, (BN_ULONG)1 ))
			goto err;
		if (!BN_set_word( &r->y, (BN_ULONG)0 ))
			goto err;
		goto out;
	}

	/* r = a */
	ret = COMP_copy( &u, a );
	if ( !ret )
		goto err;

	if (BN_is_word( b, 1 ))
	{
		COMP_copy( r, a);
		goto out;
	}

	if (!COMP_mul( &u2, &u, &u, m))
		goto err;
	if (!COMP_copy( &t[0], &u ))
		goto err;
	for ( i = 1; i < 16; i++)
	{
		if (!COMP_mul( &t[i], &t[i-1], &u2, m))
			goto err;
	}

	nb = BN_num_bits(b);
	if (nb > 1)
	{
		for ( i = nb -2; i >= 0; )
		{
			n = Window( b, i, &nbw, &nzs, WINDOW_SIZE);
			for ( j = 0; j < nbw; j++ )
			{
				if (!COMP_mul( &u, &u, &u , m))
					goto err;
			}

			if ( n > 0 )
			{
				if (!COMP_mul( &u, &u, &t[n/2], m))
					goto err;
			}

			i -= nbw;
			if (nzs)
			{
				for( j = 0; j< nzs; j++)
				{
					if (!COMP_mul(&u, &u, &u, m))
						goto err;
				}

				i -= nzs;
			}
		}
	}
	ret = COMP_copy(r, &u);
	if( !ret )
		goto err;

out:
	COMP_free( &u );
	COMP_free( &u2 );
	for ( i = 0; i < 16; i++)
		COMP_free( &t[i] );

	return r;
err:
	COMP_free( &u );
	COMP_free( &u2 );
	for ( i = 0; i < 16; i++)
		COMP_free( &t[i] );

	return NULL;
}
