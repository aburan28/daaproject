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
	bi_ptr   u = NULL , fn = NULL , cn = NULL ,s = NULL , TEMP = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *U = NULL, *F = NULL;
	BYTE     exp[] = { 0x01 };
	BYTE     *temp = NULL , *str = NULL , *f = NULL , *c = NULL;
	UINT32   DaaSeed ;
	int      strlen , flen, rv, e_size = 1;

	u  = bi_new_ptr();
	fn = bi_new_ptr();
	cn = bi_new_ptr();
	s  =  bi_new_ptr();
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

	/* 1: 1||X||Y||nI -> str */

	rv = EVP_DigestUpdate(&mdctx,  exp , e_size );			//  1
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalX->X) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) ); 	//  x.x
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalX->Y) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  x.y
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalY->X) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  y.x
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	temp = BN_bn2hex ( &(IssuerPK->CapitalY->Y) );
	rv = EVP_DigestUpdate(&mdctx,  temp , strlen( temp ) );	//  y.y
	OPENSSL_free( temp );
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate(&mdctx,  EncryptedNonceOfIssuer , EncryptedNonceOfIssuerLength );	//	nI
	OPENSSL_free( temp );									// I make a mistake here now is fixed
	if (!rv)												// here ni come from issuer
		goto err;


	str = OPENSSL_malloc( DAA_HASH_SHA1_LENGTH );
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

	f = OPENSSL_malloc( DAA_HASH_SHA1_LENGTH );
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

	c = OPENSSL_malloc( DAA_HASH_SHA1_LENGTH );
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

	EC_POINT_free(U);
	EC_POINT_free(F);
	//BN_CTX_free(ctx);
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

	EC_POINT_free(U);
	EC_POINT_free(F);
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
                                TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                BYTE **  Credential,
                                UINT32 * CredentialLength,
                                BYTE **  CapitalE,
                                UINT32 * CapitalELength)
{
	EC_GROUP *group = NULL;
	EC_POINT *A, *B, *C, *E;
	RSA      *rsa = NULL;
	BYTE     *PlatformEndorsementPubKey = NULL;
	UINT32   field_len, PlatformEndorsementPubkeyLength;
	int      i, j, ret;

	if ( EncryptedCred == NULL || EncryptedCredLength == 0 )
		return 0;

	/* Check the gloable group */
	if( group == NULL )
		return 0;

	/* Init points */
	A = EC_POINT_new( group );
	B = EC_POINT_new( group );
	C = EC_POINT_new( group );
	E = EC_POINT_new( group );
	if ( A == NULL || B == NULL || C == NULL || E == NULL)
		goto err;

	/* Init rsa key */
	rsa = RSA_new();
	if ( rsa == NULL )
		goto err;

	/* 1. Eek-1 (ε) -> cre   : */
	// TODO secret key of Ek
	rsa->n = BN_bin2bn( PlatformEndorsementPubKey , PlatformEndorsementPubkeyLength , rsa->n);
	rsa->d = BN_bin2bn( PlatformEndorsementSKey, PlatformEndorsementSkeyLength, rsa->d);
    if ( ( rsa->d == NULL ) || ( rsa->n == NULL ) )
    	goto err;

    *Credential = ( BYTE * )malloc( sizeof(BYTE) * (RSA_MODULE_LENGTH / 8) );
    if ( *Credential == NULL )
    	goto err;

	ret = RSA_private_decrypt(EncryptedCredLength, EncryptedCred,
									*Credential, rsa, RSA_NO_PADDING);
	if ( !ret )
		goto err;

	field_len = (EC_GROUP_get_degree(group) + 7) / 8;
	*CredentialLength = 6 * field_len;

	EC_POINT_hex2point( group, *Credential, A, Context);
	EC_POINT_hex2point( group, ( *Credential + field ), B, Context);
	EC_POINT_hex2point( group, ( *Credential + field * 2 ), C, Context);

	// 2. f*B -> E   :// ?
	/* f * B */
	EC_POINT_mul(group, E, NULL, B , TpmJoinSession->f, Context );	// mul the F
	*CapitalE =  EC_POINT_point2hex( group, E, POINT_CONVERSION_UNCOMPRESSED, Context);
	if ( !*Capital )
		goto err;

	*CaptialELength = strlen( *CapitalE );

	TpmJoinSession->B = EC_POINT_new( group );
	if ( TpmJoinSession->B == NULL )
		goto err;
	if (!EC_POINT_copy( TpmJoinSession->B, B ))
	{
		EC_POINT_free( TpmJoinSession->B );
		goto err;
	}

	EC_POINT_free( A );
	EC_POINT_free( B );
	EC_POINT_free( C );
	EC_POINT_free( E );
	RSA_free( rsa );

	return 1;
err:
	if ( A )
		EC_POINT_free( A );
	if ( B )
		EC_POINT_free( B );
	if ( C )
		EC_POINT_free( C );
	if ( E )
		EC_POINT_free( E );

	if ( rsa )
		RSA_free( rsa );

	return 0;
}


int TSS_DAA_SIGN_tpm_init(TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                          BYTE * VerifierBaseName,
                          UINT32 VerifierBaseNameLength,
                          BYTE **  RPrime,
                          UINT32 * RPrimeLength,
                          BYTE **  DPrime,
                          UINT32 * DPrimeLength)
{
	bi_ptr module = NULL , r_prime = NULL , v = NULL , mul = NULL;
	BYTE * buf = NULL , hash[DAA_HASH_SHA1_LENGTH +1];
	UINT32 hash_len, buf_len;
	int field_len, rev;
	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module p */
	module = bi_new_ptr();
	ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context );

	/* return either an EVP_MD structure or NULL if an error occurs. */
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if ( !digest )
		return 0;

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;

	/* 1. If bsn == ⊥ */
	if ( VerifierBaseName == NULL )
	{
		/* Zq -> r'  */
		r_prime = bi_new_ptr();

		// int     BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
		// int     BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
		// int	BN_rand_range(BIGNUM *rnd, BIGNUM *range);
		// int	BN_pseudo_rand_range(BIGNUM *rnd, BIGNUM *range);
		bi_urandom( r_prime, EC_GROUP_get_degree(group) );
		bi_mod( r_prime, r_prime, module);
	}
	else
	{
		/* 3. H2(f||bsn) -> r'   : */
		buf = BN_bn2hex( TpmJoinSession->f );
		buf_len = strlen( buf );
		rv = EVP_DigestUpdate_ex( &mdctx, buf, buf_len );
		OPENSSL_free( buf );
		if ( !rv )
		{
			goto err;
		}

		rv = EVP_DigestUpdate( &mdctx, VerifierBaseName, VerifierBaseNameLength );
		if ( !rv )
			goto err;

		rv = EVP_DigestFinal_ex(&mdctx, hash, &hash_len);
		if ( hash_len != DAA_HASH_SHA1_LENGTH )
			goto err;

		r_prime = bi_set_as_nbin( &hash_len, hash );
		if ( !r_prime )
			goto err;
	}

	/* 4. Zq -> v   (vr')*B -> D'   : */
	v = bi_new_ptr();
	bi_urandom( v, EC_GROUP_get_degree(group) );
	bi_mod( v, v, module);

	//TODO 5. r'，D' -> HOST   :// ?
	mul = bi_new_ptr();
	bi_mul( mul, v, r_prime );

	*DPrime = bi_2_nbin( DPrimeLength, mul);
	if ( *DPrimeLength <= 0 )
		goto err;

	*RPrime = bi_2_nbin( RPrimeLength, r_prime );
	if ( *RPrimeLength <= 0 )
		goto err;

	bi_free_ptr( module );
	bi_free_ptr( r_prime );
	bi_free_ptr( v );
	bi_free_ptr( mul );

	EVP_MD_CTX_cleanup(&mdctx);

	return 1;
err:
    if ( module )
    	bi_free_ptr( module );

    if ( r_prime )
    	bi_free_ptr( r_prime );
	if ( v )
		bi_free_ptr( v );
	if ( mul )
		bi_free_ptr( mul );

	EVP_MD_CTX_cleanup(&mdctx);

	return 0;
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
