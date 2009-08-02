/*
 * ss_tpm.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_tpm.h"

int TSS_DAA_JOIN_credential_request(BYTE * EncryptedNonceOfIssuer,
                                    UINT32 EncryptedNonceOfIssuerLength,
                                    TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                    TSS_DAA_ISSUER_PK        * IssuerPK,
                                    TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                                    ) //TODO change to BYTE *
{
	int rv, e_size = 1;
	unsigned char exp[] = { 0x01 };
	BYTE *temp = NULL , *str = NULL , *f = NULL , *c = NULL;
	UINT32 DaaSeed ;
	int strlen , flen;

	bi_ptr u = NULL , fn = NULL , cn = NULL ,s = NULL , TEMP = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *U = NULL, *F = NULL;
	BN_CTX *ctx = NULL;

	u = bi_new_ptr();
	fn = bi_new_ptr();
	cn = bi_new_ptr();
	s =  bi_new_ptr();
	TEMP = bi_new_ptr();

	group = EC_GROUP_new(EC_GFp_simple_method());       //  default setting for simple method

	U = EC_POINT_new(group);
	F = EC_POINT_new(group);

	ctx = BN_CTX_new();

	bi_urandom( u, NONCE_LENGTH );  		            //Zq -> u

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	EVP_MD_CTX_init(&mdctx);

	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if (!digest)
		goto err;			//return either an EVP_MD structure or NULL if an error occurs.

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;
			// 1: 1||X||Y||nI -> str

	rv = EVP_DigestUpdate(&mdctx,  exp , e_size );			//  1
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalX.X));
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) ); 	//  x.x
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalX.Y) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  x.y
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalY.X) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  y.x
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalY.Y) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  y.y
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate(&mdctx,  EncryptedNonceOfIssuer , EncryptedNonceOfIssuerLength );	//	nI
	OPENSSL_free( temp );									// I make a mistake here now is fixed
	if (!rv)												// here ni come from issuer
		goto err;


	str = OPENSSL_malloc(EVP_DigestFinal_OUT_SIZE);
	rv = EVP_DigestFinal_ex(&mdctx, str, &strlen );            	// put Final to str
	if (!rv)
		goto err;

															// 2:  H1(0||DaaSeed||Kk) -> f
	exp[0] =  0x00 ;
	rv = EVP_DigestUpdate(&mdctx,  exp , e_size );
	if (!rv)
		goto err;

	DaaSeed = DAASEED;
	temp = (BYTE *) &DaaSeed;							// DaaSeed and kk
	rv = EVP_DigestUpdate(&mdctx, temp, sizeof( DaaSeed ) );
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate(&mdctx,  Kk , strlen( Kk ) );
	if (!rv)
		goto err;

	f = OPENSSL_malloc(EVP_DigestFinal_OUT_SIZE);
	rv = EVP_DigestFinal_ex(&mdctx, f, &flen );				// put Final to f
	if (!rv)
		goto err;
														    // 3:  u*P1 -> U   f*P1 -> F

	fn = BN_bin2bn(f, flen, NULL);	// change BYTE* f to bi_ptr fn

	EC_POINT_mul(group, U, NULL, IssuerPK->Eccparmeter.CapitalP1 , u, ctx);	// mul the F
	EC_POINT_mul(group, F, NULL, IssuerPK->Eccparmeter.CapitalP1 , fn, ctx); // mul the U

																			// 4:  H1(str||F||U) -> c   :// EVP_Digst_Final
	rv = EVP_DigestUpdate(&mdctx,  str , strlen );     // str release
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(F.X) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  F.x
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(F.Y) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  F.y
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(U.X) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  U.x
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(U.Y) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  U.y
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	c = OPENSSL_malloc(EVP_DigestFinal_OUT_SIZE);
	rv = EVP_DigestFinal_ex(&mdctx, c, NULL);	 			// out final to c

	cn = BN_bin2bn(c, EVP_DigestFinal_OUT_SIZE, NULL);	// change BYTE* c to bi_ptr cn

		// 5: u+c*f (mod q) -> s

	bi_mul(TEMP, c, f);
	bi_add(s, u, TEMP);
	bi_mod(s, s, q); 				// u+c*f (mod q) == (u+c*f) (mod q)
									// or            == ( c*f(mod q)+u ) (mod q)?

		// 6:  (F，c，s) -> comm.
	rv = EC_POINT_copy(IssuerJoinSession.CapitalF , F);
	IssuerJoinSession.ch = cn;
	IssuerJoinSession.s  = s ;

	//

	bi_free(u);
	bi_free(fn);
	bi_free(cn);
	bi_free(s);
	bi_free(TEMP);
	EC_GROUP_free(group);
	EC_POINT_free(U);
	EC_POINT_free(F);
	BN_CTX_free(ctx);
	EVP_MD_CTX_cleanup(&mdctx);
	if (!str) OPENSSL_free(str);
	if (!f) OPENSSL_free(f);
	if (!c) OPENSSL_free(c);
	if (!fn) BN_free(fn);
	if (!cn) BN_free(cn);

	return 1;

err:
	bi_free(u);
	bi_free(fn);
	bi_free(cn);
	bi_free(s);
	bi_free(TEMP);
	EC_GROUP_free(group);
	EC_POINT_free(U);
	EC_POINT_free(F);
	BN_CTX_free(ctx);
	EVP_MD_CTX_cleanup(&mdctx);

	if (!str) OPENSSL_free(str);
	if (!f) OPENSSL_free(f);
	if (!c) OPENSSL_free(c);

	if (!fn) BN_free(fn);
	if (!cn) BN_free(cn);

	return 0;
}
int TSS_DAA_JOIN_tpm_credential(BYTE * EncryptedCred,
                                UINT32 EncryptedCredLength,
                                BYTE **  Credential,
                                UINT32 * CredentialLength,
                                BYTE **  CapitalE,
                                UINT32 * CapitalELength)
{
	// TODO 1. Eek-1 (ε) -> cre   :// ASA_Decypt
	// TODO 2. f*B -> E   :// ?

}


int TSS_DAA_SIGN_tpm_init(TSS_DAA_CREDENTIAL2 * Credential,
                          BYTE * VerifierBaseName,
                          UINT32 VerifierBaseNameLength,
                          BYTE **  RPrime,
                          UINT32 * RPrimeLength,
                          BYTE **  DPrime,
                          UINT32 * DPrimeLength)
{
	//TODO 1. If bsn == ⊥

	//TODO 2. Zq -> r'   :// bi_random，bi_mod

	//TODO 3. else
	       //H2(f||bsn) -> r'   :// EVP_Digest_Final //  私有 f

	//TODO 4. Zq -> v   (vr')*B -> D'   :// bi_random，bi_mod，?  //私有 r' D'

	//TODO 5. r'，D' -> HOST   :// ?

}

int TSS_DAA_SIGN_tpm_sing(BYTE *  ChPrime,
                          UINT32  ChPrimelength,
                          BYTE **  Noncetpm,
                          UINT32 * Noncetpmlength,
                          BYTE **  Ch,
                          UINT32 * Chlength,
                          BYTE **  S,
						  UINT32 * SLength)
{
	// TODO 1. {0，1}t -> nT   :// bi_random

	// TODO 2. H4(c’||nT||msg) -> c   :// EVP_Digest_Final

	// TODO 3. v+c*f(mod q) -> s   ://bi_mul，bi_add，bi_mod

	// TODO 4. (c，s，nT) -> HOST   :// ?


}
