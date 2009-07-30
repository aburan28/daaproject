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

int complex_iszero(COMPLEX *a);
COMPLEX *Add( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m );
int Copy ( COMPLEX *a, COMPLEX *b );
COMPLEX *Negate( COMPLEX *r, COMPLEX *a, BIGNUM *m );
COMPLEX *Sub( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM *m );
COMPLEX *Mul( COMPLEX *r, COMPLEX *a, COMPLEX *b, BIGNUM * m );
COMPLEX *Conj( COMPLEX *r, COMPLEX *a, BIGNUM * m );
COMPLEX *Inver( COMPLEX *r, COMPLEX *a, BIGNUM * m );
COMPLEX *Div( COMPLEX *r, COMPLEX *a, COMPLEX * b, BIGNUM * m );
int Window( BIGNUM *a, int i, int *nbs, int *nzs, int window_size);
COMPLEX *Pow( COMPLEX *r, COMPLEX *a, BIGNUM * b, BIGNUM * m );
int Set(BIGNUM *x, BIGNUM *y);


#ifdef  __cplusplus
}
#endif

#endif /* COMPLEX_H_ */
