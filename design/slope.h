/*
 * slope.h
 *
 *  Created on: 2009-8-6
 *      Author: ctqmumu
 */

#ifndef SLOPE_H_
#define SLOPE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bi.h"

BIGNUM *EC_POINT_add_slope(EC_GROUP *group, EC_POINT *A, EC_POINT *B, BIGNUM *slope)
{
	if ( !group ) return NULL;
	if ( !A ) return NULL;
	if ( !B ) return NULL;
	if ( !slope ) return NULL;

	bi_ptr ans = NULL, bip = NULL, bimod = NULL, bi_res = NULL;
	BIGNUM *ax = NULL, *ay = NULL, *bx = NULL, *by = NULL;

	ans = bi_new_ptr();
	bip = bi_new_ptr();
	bimod = bi_new_ptr();

	ax = BN_new();
	ay = BN_new();
	bx = BN_new();
	by = BN_new();

	/* set mod*/
	bi_res = bi_set( bimod, &(group->field));
	if (!bi_res) goto err;

	if ( !EC_POINT_get_affine_coordinates_GFp( group, A, ax, ay, Context) )
		goto err;

	if ( !EC_POINT_get_affine_coordinates_GFp( group, A, bx, by, Context) )
		goto err;

	/* if double */
	if (A == B) {
		/* ans=x^2    <result> := <i> * <n>
						bi_ptr bi_mul( bi_ptr result, const bi_ptr i, const bi_ptr n);*/
		bi_res = bi_mul( ans, ax, ax);
		if (!bi_res) goto err;

		bi_res = bi_mod( ans, ans, bimod);
		if (!bi_res) goto err;

		/* ans=3*x^2     <result> := <i> * <n>
							bi_ptr bi_mul_si( bi_ptr result, const bi_ptr i, const long n); * */
		bi_res = bi_mul_si( ans, ans, 3);
		if (!bi_res) goto err;

		/* ans=3*x^2+A   <result> := <i> + <n>
							bi_ptr bi_add( bi_ptr result, const bi_ptr i, const bi_ptr n);*/
		bi_res = bi_add( ans, ans, &group->a);
		if (!bi_res) goto err;

		bi_res = bi_mod( ans, ans, bimod);
		if (!bi_res) goto err;

		/* bip=2y */
		bi_res = bi_mul_si( bip, ay, 2);
		if (!bi_res) goto err;

		/* moddiv ans/bip  <result> := <i> / <n>
							bi_ptr bi_div( bi_ptr result, const bi_ptr i, const bi_ptr n);*/
		if ( !bi_invert_mod(bip, bip, bimod ) )
			goto err;
		bi_res = bi_mul( ans, ans, bip);
		if (!bi_res) goto err;

		bi_res = bi_mod( ans, ans, bimod);
		if (!bi_res) goto err;

		/* OUT */

		bi_res = bi_set( slope, ans);
		if (!bi_res) goto err;
	}
	else{
		/*ans = y2-y1  <result> := <i> - <n>
						bi_ptr bi_sub( bi_ptr result, const bi_ptr i, const bi_ptr n);*/
		bi_res = bi_sub( ans, by, ay);
		if (!bi_res) goto err;

		bi_res = bi_mod( ans, ans, bimod);	/* if here is negative ? so i use mod */
		if (!bi_res) goto err;

		/*bip = x2-x1*/
		bi_res = bi_sub( bip, bx, ax);
		if (!bi_res) goto err;

		bi_res = bi_mod( ans, ans, bimod);
		if (!bi_res) goto err;

		/*moddiv ans/bip*/
		bi_res = bi_div( ans, ans, bip);
		if (!bi_res) goto err;

		/* OUT */
		bi_res = bi_set( slope, ans);
		if (!bi_res) goto err;
	}

	bi_free(ans);
	bi_free(bip);
	bi_free(bimod);

	BN_free( ax );
	BN_free( ay );
	BN_free( bx );
	BN_free( by );

	return slope;

err:
	bi_free(ans);
	bi_free(bip);
	bi_free(bimod);

	BN_free( ax );
	BN_free( ay );
	BN_free( bx );
	BN_free( by );

	return  NULL;
}

#endif /* SLOPE_H_ */
