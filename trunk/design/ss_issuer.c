/*
 * ss_issuer.c
 *
 *  Created on: 2009-7-28
 *      Author: ctqmumu
 *
 *      about err
 *      	EVP_DigestInit_ex(), EVP_DigestUpdate() and EVP_DigestFinal_ex() return 1 for success and 0 for failure.
 *      	RSA_public_encrypt() ,On error, -1 is returned;
 *      	BN_bn2bin() returns the length of the big-endian number placed at to. BN_bin2bn() returns the BIGNUM , NULL on error.
 *      	EVP_get_digestbyname() return either an EVP_MD structure or NULL if an error occurs.
 *      	EC_POINT_add() return 0 fail
 *          for ALL BN function : 1 is returned for success, 0 on error
 *
 */


#include "daa.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <string.h>

int TSS_DAA_JOIN_issuer_setup(
                              TSS_DAA_ISSUER_KEY *   IssuerKey,
                              TSS_DAA_ISSUER_PROOF * IssuerProof)
{
	bi_ptr x = NULL , y = NULL , order = NULL , bi_res = NULL;
	EC_POINT *P1 = NULL , *P2 = NULL , *point = NULL, /*test*/*gen;
	int ret;

	if ( !(IssuerKey->IssuerPK.CapitalX) ||
		 !(IssuerKey->IssuerPK.CapitalY) ||
	     !(IssuerKey->IssuerPK.Eccparmeter.CapitalP1) ||
	     !(IssuerKey->IssuerPK.Eccparmeter.CapitalP2) ||
	     !(IssuerProof->CapitalXPrime) ||
	     !(IssuerProof->CapitalYPrime) ||
	     !(IssuerKey->IssuerSK.x) ||
	     !(IssuerKey->IssuerSK.y) ) return 0;

	x = bi_new_ptr();	if (!x) goto err;
	y = bi_new_ptr();	if (!x) goto err;

	order = bi_new_ptr();	if (!order) goto err;

	P1 = EC_POINT_new(group);	if (!P1) goto err;
	P2 = EC_POINT_new(group);	if (!P2) goto err;
	point = EC_POINT_new(group);	if (!point) goto err;

	/*  GET group->order = order */
	EC_GROUP_get_order(group , order , Context);

	/*  random x,y */
	bi_urandom( x, NONCE_LENGTH );
	bi_urandom( y, NONCE_LENGTH );

	bi_res = bi_mod(x , x, order );
	if ( !bi_res ) goto err;
	bi_res = bi_mod(y , y, order );
	if ( !bi_res ) goto err;

	/* set in the key */
	bi_set( IssuerKey->IssuerSK.x, x);
	bi_set( IssuerKey->IssuerSK.y, y);

	/*TODO [set  P2]  need get the G from group to P1  and bulit a P2 */
	gen = EC_GROUP_get0_generator(group);
	ret = EC_POINT_copy( P1 , EC_GROUP_get0_generator(group));
	if (!ret) goto err;

	/* X=x*P2 Y=y*P2 */
	ret = EC_POINT_mul(group, point, NULL, P2 , x, Context);	// mul the x*P2 = X
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerKey->IssuerPK.CapitalX , point);
	if (!ret) goto err;

	ret = EC_POINT_mul(group, point, NULL, P2 , y, Context);	// mul the y*P2 = Y
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerKey->IssuerPK.CapitalY , point);
	if (!ret) goto err;

	/* XP=x*P1 YP=y*P1 */
	ret = EC_POINT_mul(group, point, NULL, P1 , x, Context);	// mul the x*P1 = XP
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerProof->CapitalXPrime , point);
	if (!ret) goto err;

	ret = EC_POINT_mul(group, point, NULL, P1 , y, Context);	// mul the y*P1 = YP
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerProof->CapitalYPrime , point);
	if (!ret) goto err;

	/* Here is the list maybe make in future developing
	*  Kk	is common var and defined in daa.h */

	ret = EC_POINT_copy( IssuerKey->IssuerPK.Eccparmeter.CapitalP1 , P1);
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerKey->IssuerPK.Eccparmeter.CapitalP2 , P2);
	if (!ret) goto err;

	bi_free(x);
	bi_free(y);
	EC_POINT_free(point);
	EC_POINT_free(P1);
	EC_POINT_free(P2);

	return 1;
err:
	if (x) bi_free(x);
	if (y) bi_free(y);
	if (order) bi_free(order);
	if (point) EC_POINT_free(point);
	if (P1) EC_POINT_free(P1);
	if (P2) EC_POINT_free(P2);

	return 0;
}
int TSS_DAA_JOIN_issuer_init(
							BYTE * 					  	  PlatformEndorsementPubKey,
                            UINT32 					  	  PlatformEndorsementPubkeyLength,
                            TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                            BYTE   ** 	   				  EncryptedNonceOfIssuer,
                            UINT32 *					  EncryptedNonceOfIssuerLength)
{
	unsigned char exp[] = { 0x01, 0x00, 0x01 };
	int rv, e_size = 3, nbin_ni_len;
	RSA *rsa = NULL;
	bi_ptr ni = NULL;
	BYTE  *nbin_ni = NULL , *eni_st = NULL;

	if ( !(IssuerJoinSession->IssuerNone) )  return 0;

	/* 1.	{0,1}t -> nI */
	ni = bi_new_ptr();
	if (!ni)
		return 0;

	bi_urandom(ni , NONCE_LENGTH );
	bi_set( IssuerJoinSession->IssuerNone, ni);

	/* built the final commreq */
	eni_st = OPENSSL_malloc(( RSA_MODULE_LENGTH / 8 + 1) );
	if (!eni_st) goto err;

	/* change ni to nbin_ni */
	nbin_ni = bi_2_nbin(&nbin_ni_len, ni);
	if (!nbin_ni) goto err;

	rsa = RSA_new();
	if (!rsa) goto err;
	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsementPubKey , PlatformEndorsementPubkeyLength , rsa->n);    // setup rsa
    if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
    	goto err;

    /* nI -> commreq */
	rv = RSA_public_encrypt( nbin_ni_len, nbin_ni , eni_st , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;

	/* send out */
	*EncryptedNonceOfIssuer = eni_st;
	*EncryptedNonceOfIssuerLength = rv;
	//eni_st = NULL;

	bi_free(ni);
	RSA_free(rsa);
	if (nbin_ni) OPENSSL_free(nbin_ni);

	return 1;

err:
	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (eni_st) OPENSSL_free(eni_st);
	if (nbin_ni) OPENSSL_free(nbin_ni);

	return 0;
}

int TSS_DAA_JOIN_issuer_credentia(BYTE *				PlatformEndorsementPubKey,
								  UINT32				PlatformEndorsementPubkeyLength,
								  TSS_DAA_ISSUER_KEY *	IssuerKey,
								  TSS_DAA_ISSUER_JOIN_SESSION *	IssuerJoinSession,
                                  TSS_DAA_CREDENTIAL2 *			Credential,
                                  BYTE ** 						EncyptedCred,
                                  UINT32 *						EncyptedCredLength)
{

	point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
	EC_POINT *Ctemp = NULL ,*point1 = NULL , *point2 = NULL ,  *UPrime = NULL;;
	bi_ptr   r = NULL , xy = NULL ,  order = NULL , bi_res = NULL ;
	RSA      *rsa = NULL;
	int      i , ret , oct_len , e_size = 3 , buffer_len = 1024;
	unsigned char exp[] = { 0x01, 0x00, 0x01 }, *buffer = NULL, *encrypted_oct = NULL;

	if (!group) return 0;

	rsa = RSA_new();		if (!rsa) return 0;

	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsementPubKey , PlatformEndorsementPubkeyLength , rsa->n);
	if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
		goto err;

	xy	  = bi_new_ptr();	if (!xy)    goto err;
	order = bi_new_ptr();	if (!order) goto err;

	point1 = EC_POINT_new(group);
	if (!point1) goto err;
	point2  = EC_POINT_new(group);
	if (!point2) goto err;

	UPrime = EC_POINT_new(group);
	if (!UPrime) goto err;
	Ctemp = EC_POINT_new(group);
	if (!Ctemp) goto err;

	/* s*P1 – c*F -> U’ */

	/* mul the s*P1 = point1 */
	ret = EC_POINT_mul(group, point1, NULL, IssuerKey->IssuerPK.Eccparmeter.CapitalP1 , IssuerJoinSession->s, Context);
	if ( !ret ) goto err;

	/* mul the c*F  = point2 */
	ret = EC_POINT_mul(group, point2 , NULL, &(IssuerJoinSession->CapitalF) , IssuerJoinSession->ch, Context);
	if ( !ret ) goto err;

	/* use  EC_POINT_invert to updown point2 so can add it */
	ret = EC_POINT_invert(group, point2, Context);
	if ( !ret ) goto err;

	/* S*P1 + CF = point3( U’) */
	ret = EC_POINT_add(group, UPrime, point1, point2 , Context);
	if ( !ret ) goto err;

	//TODO	check rogue list

	//	Zq -> r ->mod -> finish
	r = bi_new_ptr();
	if (!r) goto err;
	bi_urandom( r, NONCE_LENGTH );

	/*  GET group->order = order */
	EC_GROUP_get_order(group , order , Context);
	if (!order) goto err;

	/*  r mod order */
	bi_res = bi_mod(r , r, order );
	if ( !bi_res ) goto err;

	/*	r *P1 -> A   y*A -> B */

	/* 1 mul the r*P1 = point1 - > A */
	ret = EC_POINT_mul(group, point1 , NULL, IssuerKey->IssuerPK.Eccparmeter.CapitalP1 , r , Context);
	if ( !ret ) goto err;

	ret = EC_POINT_copy( &(Credential->CapitalA) , point1 );
	if ( !ret ) goto err;
	/* 1 end */

	/* 2 mul the y*A  = point1 - > B */
	ret = EC_POINT_mul(group, point1, NULL, &(Credential->CapitalA) , IssuerKey->IssuerSK.y , Context);
	if ( !ret ) goto err;

	ret = EC_POINT_copy( &(Credential->CapitalB) , point1);
	if ( !ret ) goto err;
	/* 2 end */

	/* 3  (x*A + rxy*F)- C */
	/* mul the x*A = point1 */
	ret = EC_POINT_mul(group, point1, NULL, &(Credential->CapitalA) , IssuerKey->IssuerSK.x , Context);
	if ( !ret ) goto err;

	/* mul the x*y = xy */
	ret = BN_mul(xy , IssuerKey->IssuerSK.x , IssuerKey->IssuerSK.y  , Context);
	if ( !ret ) goto err;

	/* mul the r*xy = r'*/
	ret = BN_mul(r , r , xy  , Context);
	if ( !ret ) goto err;

	/* mul the r'*F = point2 */
	ret = EC_POINT_mul(group, point1, NULL, &(IssuerJoinSession->CapitalF) , r , Context);
	if ( !ret ) goto err;

	/* point2 + point1 -> C*/
	ret = EC_POINT_add(group, Ctemp, point2, point1, Context);
	if ( !ret ) goto err;

	ret = EC_POINT_copy( &(Credential->CapitalC) , Ctemp);
	if ( !ret ) goto err;
	/* 3 end */

	/*	Eek(cre)[A.B.C] -> buffer -> encrypted_oct -> EncyptedCred - >TPM */

	/* malloc the buffer , encrypted_oct and (*EncyptedCred) */

	buffer = OPENSSL_malloc(buffer_len * sizeof(BYTE));
	encrypted_oct = OPENSSL_malloc(( RSA_MODULE_LENGTH/8 + 1) );
	(*EncyptedCred) = OPENSSL_malloc(( RSA_MODULE_LENGTH/8 * 3 +1) );

	/* malloc end*/

	/*1  cre.A -> buffer */
	oct_len = EC_POINT_point2oct(group, &(Credential->CapitalA), form, buffer, buffer_len,  Context);
	if ( !oct_len ) goto err;
	/*1  buffer -> encrypted_oct*/
	ret = RSA_public_encrypt( oct_len, buffer , encrypted_oct , rsa , RSA_NO_PADDING);
		if (ret == -1)
			goto err;
	/*1  encrypted_oct - > EncyptedCred*/
	for (i=0;i<RSA_MODULE_LENGTH/8;i++)
		{
			if ( ( i+ret ) >= (RSA_MODULE_LENGTH/8 - 1)  ) *EncyptedCred[i] = encrypted_oct[ ( i+ret ) - (RSA_MODULE_LENGTH/8 - 1) ];
			else
				*EncyptedCred[i] = 0;
		}

	/*2  cre.B -> buffer */
	oct_len = EC_POINT_point2oct(group, &(Credential->CapitalB), form, buffer, buffer_len,  Context);
	if ( !oct_len ) goto err;
	/*2  buffer -> encrypted_oct*/
	ret = RSA_public_encrypt( oct_len, buffer , encrypted_oct , rsa , RSA_NO_PADDING);
		if (ret == -1)
			goto err;
	/*2  encrypted_oct - > EncyptedCred*/
	for (i=RSA_MODULE_LENGTH/8;i<RSA_MODULE_LENGTH/4;i++)
		{
			if ( ( i+ret ) >= (RSA_MODULE_LENGTH/4 - 1)  ) *EncyptedCred[i] = encrypted_oct[ ( i+ret ) - (RSA_MODULE_LENGTH/4 - 1) ];
			else
				*EncyptedCred[i] = 0;
		}
	/*3  cre.C -> buffer */
	oct_len = EC_POINT_point2oct(group, &(Credential->CapitalC), form, buffer, buffer_len,  Context);
	if ( !oct_len ) goto err;
	/*3  buffer -> encrypted_oct*/
	ret = RSA_public_encrypt( oct_len, buffer , encrypted_oct , rsa , RSA_NO_PADDING);
		if (ret == -1)
			goto err;
	/*3  encrypted_oct - > EncyptedCred*/
	for (i=RSA_MODULE_LENGTH/8;i<RSA_MODULE_LENGTH/8*3;i++)
		{
			if ( ( i+ret ) >= (RSA_MODULE_LENGTH/8*3 - 1)  ) *EncyptedCred[i] = encrypted_oct[ ( i+ret ) - (RSA_MODULE_LENGTH/8*3 - 1) ];
			else
				*EncyptedCred[i] = 0;
		}


	*EncyptedCredLength = RSA_MODULE_LENGTH/8 * 3;


	RSA_free(rsa);

	bi_free(r);
	bi_free(xy);
	bi_free(order);

	EC_POINT_free(point1);
	EC_POINT_free(point2);
	EC_POINT_free(UPrime);
	EC_POINT_free(Ctemp);

	OPENSSL_free(buffer);
	OPENSSL_free(encrypted_oct);
	OPENSSL_free((*EncyptedCred));


	return 1;
err:
	RSA_free(rsa);

	if (r)  bi_free(r);
	if (xy) bi_free(xy);
	if (order) bi_free(order);

	if (point1) EC_POINT_free(point1);
	if (point2) EC_POINT_free(point2);
	if (UPrime) EC_POINT_free(UPrime);
	if (Ctemp)  EC_POINT_free(Ctemp);

	if ( buffer ) OPENSSL_free(buffer);
	if ( encrypted_oct ) OPENSSL_free(encrypted_oct);
	if ( (*EncyptedCred) ) OPENSSL_free((*EncyptedCred));

	return 0;
}
