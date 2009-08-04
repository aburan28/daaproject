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

int TSS_DAA_JOIN_issuer_setup(
                              TSS_DAA_ISSUER_KEY *   IssuerKey,
                              TSS_DAA_ISSUER_PROOF * IssuerProof)
{
	bi_ptr x = NULL , y = NULL;
	EC_POINT *P1 = NULL , *P2 = NULL , X = NULL , Y = NULL , XP = NULL , YP = NULL;
	int ret;

	x = bi_new_ptr();
	y = bi_new_ptr();

	if (!group)
		group = EC_GROUP_new(EC_GFp_simple_method());       //  default setting for simple method

	if ( !(IssuerKey->IssuerPK.CapitalX) ) IssuerKey->IssuerPK.CapitalX = EC_POINT_new(group);	// if the key-world nothing we built it
	if ( !(IssuerKey->IssuerPK.CapitalY) ) IssuerKey->IssuerPK.CapitalY = EC_POINT_new(group);
	if ( !(IssuerKey->IssuerPK.Eccparmeter.CapitalP1) ) IssuerKey->IssuerPK.Eccparmeter.CapitalP1 = EC_POINT_new(group);
	if ( !(IssuerKey->IssuerPK.Eccparmeter.CapitalP2) ) IssuerKey->IssuerPK.Eccparmeter.CapitalP2 = EC_POINT_new(group);
	if ( !(IssuerProof->CapitalXPrime) ) IssuerProof->CapitalXPrime = EC_POINT_new(group);
	if ( !(IssuerProof->CapitalYPrime) ) IssuerProof->CapitalYPrime = EC_POINT_new(group);

	P1 = EC_POINT_new(group);
	P2 = EC_POINT_new(group);
	XP = EC_POINT_new(group);
	YP = EC_POINT_new(group);
	X = EC_POINT_new(group);
	Y = EC_POINT_new(group);

	if ( !(IssuerKey->IssuerSK.x) ) IssuerKey->IssuerSK.x = bi_new_ptr();
	if ( !(IssuerKey->IssuerSK.y) ) IssuerKey->IssuerSK.y = bi_new_ptr();

	/*  random x,y  */
	bi_urandom( x, NONCE_LENGTH );
	bi_urandom( y, NONCE_LENGTH );

	/*TODO set P1 P2  need get the G from group to P1  and bulit a P2 */

	/* X=x*P2 Y=y*P2 */
	ret = EC_POINT_mul(group, X, NULL, P2 , x, Context);	// mul the x*P2 = X
	if (!ret) goto err;
	ret = EC_POINT_mul(group, Y, NULL, P2 , y, Context);	// mul the y*P2 = Y
	if (!ret) goto err;

	/* XP=x*P1 YP=y*P1 */
	ret = EC_POINT_mul(group, XP, NULL, P1 , x, Context);	// mul the x*P1 = XP
	if (!ret) goto err;
	ret = EC_POINT_mul(group, YP, NULL, P1 , y, Context);	// mul the y*P1 = YP
	if (!ret) goto err;

	/* Here is the list maybe make in future developing
		 IPK Kk	*/

	/* set in the key */
	 bi_set( IssuerKey->IssuerSK.x, x);
	 bi_set( IssuerKey->IssuerSK.y, y);

	ret = EC_POINT_copy( IssuerKey->IssuerPK.CapitalX , X);
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerKey->IssuerPK.CapitalY , Y);
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerKey->IssuerPK.Eccparmeter.CapitalP1 , P1);
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerKey->IssuerPK.Eccparmeter.CapitalP2 , P2);
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerProof->CapitalXPrime , XP);
	if (!ret) goto err;
	ret = EC_POINT_copy( IssuerProof->CapitalYPrime , YP);
	if (!ret) goto err;

	if ( x ) bi_free(x);
	if ( y ) bi_free(y);
	EC_POINT_free(X);
	EC_POINT_free(Y);
	EC_POINT_free(P1);
	EC_POINT_free(P2);
	EC_POINT_free(XP);
	EC_POINT_free(YP);

	return 1;
err:
	bi_free(x);
	bi_free(y);
	EC_POINT_free(X);
	EC_POINT_free(Y);
	EC_POINT_free(P1);
	EC_POINT_free(P2);
	EC_POINT_free(XP);
	EC_POINT_free(YP);

	bi_free(IssuerKey->IssuerSK.x);
	bi_free(IssuerKey->IssuerSK.y);
	EC_POINT_free(IssuerKey->IssuerPK.CapitalX);
	EC_POINT_free(IssuerKey->IssuerPK.CapitalY);
	EC_POINT_free(IssuerKey->IssuerPK.Eccparmeter.CapitalP1);
	EC_POINT_free(IssuerKey->IssuerPK.Eccparmeter.CapitalP2);
	EC_POINT_free(IssuerProof->CapitalXPrime);
	EC_POINT_free(IssuerProof->CapitalYPrime);

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
	int rv, e_size = 3;
	RSA *rsa = NULL;
	bi_ptr ni = NULL;
	BYTE  *hex_ni = NULL , *eni_st = NULL;
	UINT32 hex_ni_len;
	/* 1.	{0,1}t -> nI */
	ni = bi_new_ptr();
	if ( !(IssuerJoinSession.IssuerNone) ) IssuerJoinSession.IssuerNone = bi_new_ptr();

	bi_urandom(ni , NONCE_LENGTH );
	bi_set( IssuerJoinSession.IssuerNone, ni); //TODO find out and err it
	/* built the final commreq */
	eni_st = OPENSSL_malloc(( RSA_MODLE_LENGTH / 8 + 1) );

	/* change ni to hex_ni */
	hex_ni = bi_2_hex_char( ni );
	hex_ni_len = strlen( hex_ni );

	rsa = RSA_new();
	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsementPubKey , PlatformEndorsementPubkeyLength , rsa->n);    // setup rsa
    if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
    	goto err;
    /* nI -> commreq */
	rv = RSA_public_encrypt( hex_ni_len, hex_ni , eni_st , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;
	/* send out */
	*EncryptedNonceOfIssuer = eni_st;
	*EncryptedNonceOfIssuerLength = rv;
	eni_st = NULL;

	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (eni_st) OPENSSL_free(eni_st);
	if (hex_ni) OPENSSL_free(hex_ni);

	return 1;

err:
	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (eni_st) OPENSSL_free(eni_st);
	if (hex_ni) OPENSSL_free(hex_ni);

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
	//s*P1 – c*F - U’
	point_conversion_form_t form;
	BYTE * cre;
	BN_CTX *ctx = NULL;
	EC_POINT *SP1 = NULL , *CF = NULL , *UP = NULL , *A = NULL , *B = NULL , *C = NULL , *XA = NULL , *RXYF = NULL;
	bi_ptr r = NULL , xy = NULL , rxy = NULL;
	char *ahex = NULL, *bhex = NULL, *chex = NULL , *aenc = NULL , *benc = NULL , *cenc = NULL;
	int i , ret , HEX_LENGTH , e_size = 3 , RSA_BYTES_LEN = RSA_MODLE_LENGTH / 8;
	RSA *rsa = NULL;
	unsigned char exp[] = { 0x01, 0x00, 0x01 };

	rsa = RSA_new();
	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsementPubKey , PlatformEndorsementPubkeyLength , rsa->n);
	if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
		goto err;

	if (!group)
		group = EC_GROUP_new(EC_GFp_simple_method());       //  default setting for simple method
	ctx = BN_CTX_new();

	aenc = OPENSSL_malloc(( RSA_BYTES_LEN + 1) );
	benc = OPENSSL_malloc(( RSA_BYTES_LEN + 1) );
	cenc = OPENSSL_malloc(( RSA_BYTES_LEN + 1) );
	(*EncyptedCred) = OPENSSL_malloc(( RSA_BYTES_LEN * 3 +1) );

	r = bi_new_ptr();
	xy = bi_new_ptr();
	rxy = bi_new_ptr();
	bi_urandom( r, NONCE_LENGTH );

	SP1 = EC_POINT_new(group);
	CF  = EC_POINT_new(group);
	UP  = EC_POINT_new(group);
	A = EC_POINT_new(group);
	B = EC_POINT_new(group);
	C = EC_POINT_new(group);
	XA = EC_POINT_new(group);
	RXYF = EC_POINT_new(group);

	// EC_POINT_mul  return 0 err
	ret = EC_POINT_mul(group, SP1, NULL, IssuerKey->IssuerPK.Eccparmeter.CapitalP1 , IssuerJoinSession->s, ctx);	// mul the s*P1 = SP1
	if ( !ret ) goto err;
	ret = EC_POINT_mul(group, CF , NULL, &(IssuerJoinSession->CapitalF) , IssuerJoinSession->ch, ctx);				// mul the c*F  = CF
	if ( !ret ) goto err;

	ret = EC_POINT_invert(group, CF, ctx);					// use  EC_POINT_invert to updown CF so can add it
	if ( !ret ) goto err;
	ret = EC_POINT_add(group, UP, SP1, CF , ctx);					// SP1+CF = UP( U’)
	if ( !ret ) goto err;

	//TODO	check rogue list

	//	Zq - r ->finish

	//	r *P1 - A   y*A - B
	ret = EC_POINT_mul(group, A, NULL, IssuerKey->IssuerPK.Eccparmeter.CapitalP1 , r , ctx);	// mul the r*P1 = A
	if ( !ret ) goto err;
	ret = EC_POINT_mul(group, B, NULL, A , IssuerKey->IssuerSK.y , ctx);						// mul the y*A = B
	if ( !ret ) goto err;
	//	(x*A + rxy*F)- C
	ret = EC_POINT_mul(group, XA, NULL, A , IssuerKey->IssuerSK.x , ctx);						// mul the x*A = XA
	if ( !ret ) goto err;
	ret = BN_mul(xy , IssuerKey->IssuerSK.x , IssuerKey->IssuerSK.y  , ctx);					// mul the x*y = xy
	if ( !ret ) goto err;
	ret = BN_mul(rxy , r , xy  , ctx);															// mul the r*xy = rxy
	if ( !ret ) goto err;
	ret = EC_POINT_mul(group, RXYF, NULL, &(IssuerJoinSession->CapitalF) , rxy , ctx);			// mul the rxy*F = RXYF
	if ( !ret ) goto err;
	ret = EC_POINT_add(group, C, XA, RXYF, ctx);
	if ( !ret ) goto err;
	//	(A，B，C) - cre   ://
	ret = EC_POINT_copy( &(Credential->CapitalA) , A);
	if ( !ret ) goto err;
	ret = EC_POINT_copy( &(Credential->CapitalB) , B);
	if ( !ret ) goto err;
	ret = EC_POINT_copy( &(Credential->CapitalC) , C);
	if ( !ret ) goto err;

	A = NULL;
	B = NULL;
	C = NULL;
	//	Eek(cre) - ε
	//	ε - TPM
	ahex = EC_POINT_point2hex(group , &(Credential->CapitalA) , from , ctx);
	if ( !ahex ) goto err;
	bhex = EC_POINT_point2hex(group , &(Credential->CapitalB) , from , ctx);
	if ( !bhex ) goto err;
	chex = EC_POINT_point2hex(group , &(Credential->CapitalC) , from , ctx);
	if ( !chex ) goto err;
																	//  here len(ahex)==len(abex)==len(chenx)?
	HEX_LENGTH = strlen(ahex);

	*EncyptedCred[0] = 0x00;
	// encrypt ahex in aenc and put in EncyptedCred
	rv = RSA_public_encrypt( HEX_LENGTH, ahex , aenc , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;
	for (i=1;i<=RSA_BYTES_LEN;i++)
	{
		if ( ( i+rv ) > RSA_BYTES_LEN ) *EncyptedCred[i] = aenc[ ( i+rv ) - RSA_BYTES_LEN ];
		else
			*EncyptedCred[i] = 0;
	}
	// encrypt bhex in benc and put in EncyptedCred
	rv = RSA_public_encrypt( HEX_LENGTH, bhex , benc , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;
	for (i=1;i<=RSA_BYTES_LEN;i++)
	{
		if ( ( i+rv ) > RSA_BYTES_LEN ) *EncyptedCred[i + RSA_BYTES_LEN] = aenc[ ( i+rv ) - RSA_BYTES_LEN ];
		else
			*EncyptedCred[i + RSA_BYTES_LEN] = 0;
	}
	// encrypt chex in cenc and put in EncyptedCred
	rv = RSA_public_encrypt( HEX_LENGTH, bhex , cenc , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;
	for (i=1;i<=RSA_BYTES_LEN;i++)
	{
		if ( ( i+rv ) > RSA_BYTES_LEN ) *EncyptedCred[i + RSA_BYTES_LEN*2 ] = aenc[ ( i+rv ) - RSA_BYTES_LEN ];
		else
			*EncyptedCred[i + RSA_BYTES_LEN*2 ] = 0;
	}

	*EncyptedCredLength = RSA_BYTES_LEN * 3;

	BN_CTX_free(ctx);
	bi_free(r);
	bi_free(xy);
	bi_free(rxy);
	EC_POINT_free(SP1);
	EC_POINT_free(CF);
	EC_POINT_free(UP);
	if ( A ) EC_POINT_free(A);
	if ( B ) EC_POINT_free(B);
	if ( C ) EC_POINT_free(C);
	EC_POINT_free(XA);
	EC_POINT_free(RXYF);

	if ( ahex ) OPENSSL_free(ahex);
	if ( bhex ) OPENSSL_free(bhex);
	if ( chex ) OPENSSL_free(chex);
	if ( aenc ) OPENSSL_free(aenc);
	if ( benc ) OPENSSL_free(benc);
	if ( cenc ) OPENSSL_free(cenc);

	if (rsa) RSA_free(rsa);

	return 1;
err:
	BN_CTX_free(ctx);
	bi_free(r);
	bi_free(xy);
	bi_free(rxy);
	EC_POINT_free(SP1);
	EC_POINT_free(CF);
	EC_POINT_free(UP);
	if ( A ) EC_POINT_free(A);
	if ( B ) EC_POINT_free(B);
	if ( C ) EC_POINT_free(C);
	EC_POINT_free(XA);
	EC_POINT_free(RXYF);

	if (rsa) RSA_free(rsa);

	if ( ahex ) OPENSSL_free(ahex);
	if ( bhex ) OPENSSL_free(bhex);
	if ( chex ) OPENSSL_free(chex);
	if ( aenc ) OPENSSL_free(aenc);
	if ( benc ) OPENSSL_free(benc);
	if ( cenc ) OPENSSL_free(cenc);
	if ( (*EncyptedCred) ) OPENSSL_free((*EncyptedCred));


	return 0;
}
