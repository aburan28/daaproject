/*
 * transform.h
 *
 *  Created on: 2009-7-27
 *      Author: ctqmumu
 */

#ifndef TRANSFORM_H_
#define TRANSFORM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bi.h"
#include "daa.h"
#include <openssl/bn.h>
#include <openssl/engine.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT32
#define UINT32 unsigned long
#endif

/* return a bi_ptr from UNIT32,BYTE*  */
bi_ptr bin_2_bip( const BYTE *buffer, const UINT32 length)
{
	bi_ptr ret_bi = bi_new_ptr();

	if ( ret_bi == NULL)
		    return NULL;

	if ( BN_bin2bn( buffer, length, ret_bi) == NULL)
	{
			bi_free( ret_bi);
			return NULL;
	}
	return ret_bi;
}

/* return a BYTE* and UINT32 from bi_ptr*/
BYTE *bip_2_bin( UINT32 *length, const bi_ptr bp)
{
	BYTE *ret ;
	*length = BN_num_bytes( bp);
	ret = (BYTE *)bi_alloc( *length * 2);
	if( ret == NULL) {
		return NULL; }

	BN_bn2bin( bp, ret);
	return  ret;
}

/* change ECC_POINT's X,Y to hexadecimal string, and we follow length */
int ecp_2_hex(ECC_POINT *EccPoint, BYTE **X, BYTE **Y, UINT32 *XLength, UINT32 *YLength)
{

	*X = (BYTE *)bi_2_hex_char(&(EccPoint->X));
	if (*X==NULL) return 0;

	*Y = (BYTE *)bi_2_hex_char(&(EccPoint->Y));
	if (*Y==NULL) return 0;

	if ((!XLength)&&(!YLength)) return 0;
		*XLength = strlen(*X);
		*YLength = strlen(*Y);

	return 1;
}

/* change hexadecimal string X , Y to ECC_POINT's X and Y */
int hex_2_ecp(BYTE *X, BYTE *Y, ECC_POINT **EccPoint, EC_GROUP *group)
{
	if (group==NULL) group = EC_GROUP_new(EC_GFp_mont_method());
	if (group==NULL) return 0;

	if ((X== NULL)||(Y== NULL)) return 0;

	*EccPoint = EC_POINT_new(group);


	bi_ptr bip = bi_new_ptr();
	BN_hex2bn( &bip, X);
	(*EccPoint)->X = *bip;

	bip = bi_new_ptr();
	BN_hex2bn( &bip, Y);
	(*EccPoint)->Y = *bip;

    return 1;
}

#ifdef  __cplusplus
}
#endif
#endif /* TRANSFORM_H_ */
