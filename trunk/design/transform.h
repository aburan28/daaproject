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
bi_ptr bin_2_bip( const BYTE length, const UINT32 *buffer)
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
	BYTE * ret;
	*length = BN_num_bytes( bp );
	ret = (BYTE *)bi_alloc( *length * 2);
	if( ret == NULL) return NULL;
	BN_bn2bin( bp, ret);
	return  ret;
}


#ifdef  __cplusplus
}
#endif
#endif /* TRANSFORM_H_ */
