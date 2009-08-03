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

//TODO init the Context;
BN_CTX *Context;

// complex number a + bi
typedef struct complex_st{

	BIGNUM x;

	BIGNUM y;

}COMPLEX;

void COMP_init( COMPLEX *a );
void COMP_free( COMPLEX *a );
int COMP_is_zero(COMPLEX *a);
int COMP_set(COMPLEX *a, BIGNUM *x, BIGNUM *y, BIGNUM *m);
COMPLEX *COMP_add( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m );
int COMP_copy ( COMPLEX *a, COMPLEX *b );
COMPLEX *COMP_negate( COMPLEX *r, COMPLEX *a, BIGNUM *m );
COMPLEX *COMP_sub( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m );
COMPLEX *COMP_mul( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM * m );
COMPLEX *COMP_conj( COMPLEX *r, COMPLEX *a, BIGNUM * m );
COMPLEX *COMP_inver( COMPLEX *r, COMPLEX *a, BIGNUM * m );
COMPLEX *COMP_div( COMPLEX *r, COMPLEX *a, COMPLEX * b, BIGNUM * m );
int Window( BIGNUM *a, int i, int *nbs, int *nzs, int window_size);
COMPLEX *COMP_pow( COMPLEX *r, COMPLEX *a, BIGNUM * b, BIGNUM * m );

#ifdef  __cplusplus
}
#endif

#endif /* COMPLEX_H_ */
