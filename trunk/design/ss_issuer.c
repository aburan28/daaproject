/*
 * ss_issuer.c
 *
 *  Created on: 2009-7-28
 *      Author: ctqmumu
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
							BYTE * 					  	  PlatformEndorsemenPubKey,
                            UINT32 					  	  PlatformEndorsemenPubkeyLength,
                            TSS_DAA_ISSUER_PK * 		  IssuerPK,
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
												//		1.	{0,1}t -> nI  // bi_random
	ni = bi_new_ptr();
	bi_urandom( nI, NONCE_LENGTH );

	eni_st = malloc(2048);					   // 		built the final commreq

	hex_ni = bi_2_hex_char( ni );
	hex_ni_len = strlen( hex_ni );             //   	change ni to hex_ni

	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsemenPubKey , PlatformEndorsemenPubkeyLength , rsa->n);    // setup rsa
    if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
    {
    	free(eni_st);
    	return 0;
    }
												//					2.	nI -> commreq
	rv = RSA_public_encrypt( hex_ni_len, hex_ni , eni_st , rsa , RSA_NO_PADDING);
	if (rv == -1)
	{
	    	free(eni_st);
	    	return 0;
	}

	EncryptedNonceOfIssuer = &eni_st;          // send out
	EncryptedNonceOfIssuerLength = rv;

	free(eni_st);                              // here we have ni and hex_ni not free !
	return 1;
}

int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_JOIN_SESSION * TpmJoinSession,
		                          TSS_DAA_CREDENTIAL2 * Credential,
		                          TSS_DAA_ISSUER_PK * 		  IssuerPK,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength)
{
	int rv, e_size = 1;
	unsigned char exp[] = { 0x01 };
	BYTE *temp = NULL , *str = NULL , *f = NULL , *c = NULL;
	UINT32 templength;
	bi_ptr u = NULL , fn = NULL , cn = NULL ,s = NULL , temp = NULL;

	 u = bi_new_ptr();

	 EVP_MD *digest = NULL;
	 EVP_MD_CTX mdctx;

	 digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	 rv = EVP_DigestInit( &mdctx , digest ); 								 //  initialization the ||

														 // 1: 1||X||Y||nI -> str

	 rv = EVP_DigestUpdate(&mdctx,  exp , e_size );			//  1

	 temp = BN_bn2hex ( IssuerPK->CapitalX.X);
	 templength = strlen( temp );
	 rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  x.x
	 OPENSSL_free( temp );

	 temp = BN_bn2hex ( IssuerPK->CapitalX.Y );
	 templength = strlen( temp );
	 rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  x.y
	 OPENSSL_free( temp );

	 temp = BN_bn2hex ( IssuerPK->CapitalY.X );
	 templength = strlen( temp );
	 rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  y.x
	 OPENSSL_free( temp );

	 temp = BN_bn2hex ( IssuerPK->CapitalY.Y );
	 templength = strlen( temp );
	 rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  y.y
	 OPENSSL_free( temp );

	 temp = BN_bn2hex ( *TpmJoinSession->IssuerNone );
	 templength = strlen( temp );
	 rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//	nI
	 OPENSSL_free( temp );


	 str = malloc(EVP_DigestFinal_OUT_SIZE);
	 rv = EVP_DigestFinal(&mdctx, str, NULL);            	// put Final to str

															// 2:  H1(0||DaaSeed||Kk) -> f
	   exp[0] =  0x00 ;
	   rv = EVP_DigestUpdate(&mdctx,  exp , e_size );

	   temp = bi_2_hex_char ( DaaSeed );                    //TODO DaaSeed and Kk need to define
	   templength = strlen( temp );
	   rv = EVP_DigestUpdate(&mdctx,  temp , templength );
	   OPENSSL_free( temp );

	   temp = bi_2_hex_char ( Kk );
	   templength = strlen( temp );
	   rv = EVP_DigestUpdate(&mdctx,  temp , templength );
	   OPENSSL_free( temp );

	   f = malloc(EVP_DigestFinal_OUT_SIZE);
	   rv = EVP_DigestFinal(&mdctx, f, NULL);				// put Final to f

														    // 3:  u*P1 -> U   f*P1 -> F

		fn = BN_bin2bn(f, EVP_DigestFinal_OUT_SIZE, NULL);	// change BYTE* f to bi_ptr fn

	    bi_urandom( u, NONCE_LENGTH );  		            //Zq -> u

		EC_GROUP *group;
		EC_POINT *U, *F;
		BN_CTX *ctx = NULL;

	 	group = EC_GROUP_new(EC_GFp_simple_method());       //  default setting for simple method

	 	ctx = BN_CTX_new();

	 	U = EC_POINT_new(group);
	 	F = EC_POINT_new(group);

	 	EC_POINT_mul(group, U, NULL, IssuerPK->Eccparmeter.CapitalP1 , u, ctx);	// mul the F
	 	EC_POINT_mul(group, F, NULL, IssuerPK->Eccparmeter.CapitalP1 , f, ctx); // mul the U

	// 4: TODO H1(str||F||U) -> c   :// EVP_Digst_Final
	 	rv = EVP_DigestUpdate(&mdctx,  str , EVP_DigestFinal_OUT_SIZE );     // str

		temp = BN_bn2hex ( F.X);
		templength = strlen( temp );
		rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  F.x
		OPENSSL_free( temp );

		temp = BN_bn2hex ( F.Y );
		templength = strlen( temp );
		rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  F.y
		OPENSSL_free( temp );

		temp = BN_bn2hex ( U.X );
		templength = strlen( temp );
		rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  U.x
		OPENSSL_free( temp );

		temp = BN_bn2hex ( U.Y );
		templength = strlen( temp );
		rv = EVP_DigestUpdate(&mdctx,  temp , templength );	//  U.y
		OPENSSL_free( temp );

		c = malloc(EVP_DigestFinal_OUT_SIZE);
		rv = EVP_DigestFinal(&mdctx, c, NULL);	 			// out final to c

		cn = BN_bin2bn(c, EVP_DigestFinal_OUT_SIZE, NULL);	// change BYTE* c to bi_ptr cn

	// 5: u+c*f (mod q) -> s
		bi_ptr s   = bi_new_ptr();
		bi_ptr temp = bi_new_ptr();

		bi_mul(temp, c, f);
		bi_add(s, u, temp);
		bi_mod(s, s, q);

	// 6:  (F，c，s) -> comm.
		rv = EC_POINT_copy(TpmJoinSession.CapitalF , F);
		TpmJoinSession.ch = cn;
		TpmJoinSession.s  = s ;
}
