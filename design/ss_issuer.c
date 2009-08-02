/*
 * ss_issuer.c
 *
 *  Created on: 2009-7-28
 *      Author: ctqmumu
 *
 *      About Err
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
                              TSS_DAA_ISSUER_PROOF * IssuerProof);
//TODO setup function

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
												//		1.	{0,1}t -> nI
	ni = bi_new_ptr();
	bi_urandom( ni, NONCE_LENGTH );

	IssuerJoinSession.IssuerNone = ni;

	rsa = RSA_new();

	eni_st = malloc(( RSA_MODLE_LENGTH / 8 + 1) * sizeof(BYTE));					   //built the final commreq {RSA_MODLE_LENGTH=2048}

	hex_ni = bi_2_hex_char( ni );
	hex_ni_len = strlen( hex_ni );             //   	change ni to hex_ni

	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsemenPubKey , PlatformEndorsemenPubkeyLength , rsa->n);    // setup rsa
    if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
    	goto err;
												//					2.	nI -> commreq
	rv = RSA_public_encrypt( hex_ni_len, hex_ni , eni_st , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;

	*EncryptedNonceOfIssuer = eni_st;          // send out
	*EncryptedNonceOfIssuerLength = rv;

	ni = NULL;      // here we make NULL so not free it

	if (eni_st) free(eni_st);
	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (hex_ni) OPENSSL_free(hex_ni);

	return 1;

err:
	if (eni_st) free(eni_st);
	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (hex_ni) OPENSSL_free(hex_ni);

	return 0;
}

int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_KEY * IssuerKey,
								  TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                                  TSS_DAA_CREDENTIAL2 * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength)
{
//	s*P1 – c*F - U’   :

	point_conversion_form_t form;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	EC_POINT *SP1 = NULL , *CF = NULL , *UP = NULL , *A = NULL , *B = NULL , *C = NULL , *XA = NULL , *RXYF = NULL;
	bi_ptr r = NULL , xy = NULL , rxy = NULL;
	char *ahex = NULL, *bhex = NULL, *chex = NULL;
	int ret , HEX_LENGTH;

	group = EC_GROUP_new(EC_GFp_simple_method());       //  default setting for simple method
	ctx = BN_CTX_new();

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
//	(x*A + rxy*F)- C   : //
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
	ret = EC_POINT_copy( *(Credential->CapitalA) , A);
	if ( !ret ) goto err;
	ret = EC_POINT_copy( *(Credential->CapitalB) , B);
	if ( !ret ) goto err;
	ret = EC_POINT_copy( *(Credential->CapitalC) , C);
	if ( !ret ) goto err;

	A = NULL;
	B = NULL;
	C = NULL;
//	Eek(cre) - ε
//	ε - TPM   :/
	ahex = EC_POINT_point2hex(group , *(Credential->CapitalA) , from , ctx);
	if ( !ahex ) goto err;
	bhex = EC_POINT_point2hex(group , *(Credential->CapitalB) , from , ctx);
	if ( !bhex ) goto err;
	chex = EC_POINT_point2hex(group , *(Credential->CapitalC) , from , ctx);
	if ( !chex ) goto err;
																	//  here len(ahex)==len(abex)==len(chenx)?
	HEX_LENGTH = strlen(ahex);
	*EncyptedCred = OPENSSL_malloc(sizeof(BYTE) * HEX_LENGTH * 3 );
	if ( !(*EncyptedCred) ) goto err;

	*EncyptedCred[0] = '\0';
	*EncyptedCred = strncat(*EncyptedCred , ahex , HEX_LENGTH);
	*EncyptedCred = strncat(*EncyptedCred , bhex , HEX_LENGTH);
	*EncyptedCred = strncat(*EncyptedCred , chex , HEX_LENGTH);
	*EncyptedCredLength = HEX_LENGTH * 3;

	EC_GROUP_free(group);
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
	if ( (*EncyptedCred) ) OPENSSL_free((*EncyptedCred));

	return 1;
err:
	EC_GROUP_free(group);
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

	return 0;
}
