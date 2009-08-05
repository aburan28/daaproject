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
                                    TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession
                                    ) //TODO change to BYTE *
{
	bi_ptr   u = NULL , f = NULL , c = NULL ,s = NULL , module = NULL, temp = NULL;
	EC_POINT *U = NULL, *F = NULL;
	RSA      *rsa = NULL;

	BYTE     *buf = NULL , str[DAA_HASH_SHA1_LENGTH] , hash[DAA_HASH_SHA1_LENGTH];
	BYTE     exp[] = { 0x01 };
	UINT32   DaaSeed, buf_len, str_len, hash_len;
	int      rv, e_size = 1;

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module p */
	module = bi_new_ptr();
	if ( module == NULL )
		return 0;
	rv = ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context ); //return 1 if success
	if ( !rv )
		goto err;

	/* 1. Zq -> u */
	u  = bi_new_ptr();
	if ( u == NULL )
		goto err;
	bi_urandom( u, NONCE_LENGTH );
	bi_mod( u, u, module );


	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if ( !digest )
		goto err;
	/* Return either an EVP_MD structure or NULL if an error occurs. */
	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;

	/* 1: 1||X||Y||nI -> str */
	rv = EVP_DigestUpdate(&mdctx,  exp , e_size );			//  1
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalX->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  x.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalX->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//  x.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalY->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//  y.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalY->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//  y.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	/* DECRYPT NI */
	rsa = RSA_new();
	if ( rsa == NULL )
		goto err;
	// TODO secret key of Ek and Publick key of EK
	rsa->n = bi_set_as_nbin(  PlatformEndorsementPubkeyLength, PlatformEndorsementPubKey );
	rsa->d = bi_set_as_nbin( PlatformEndorsementSkeyLength, PlatformEndorsementSKey );
    if ( ( rsa->d == NULL ) || ( rsa->n == NULL ) )
    	goto err;

    buf = ( BYTE * )malloc( sizeof(BYTE) * (RSA_MODULE_LENGTH / 8) );
    if ( buf == NULL )
    	goto err;

	buf_len = RSA_private_decrypt(EncryptedNonceOfIssuerLength, EncryptedNonceOfIssuer,
									buf, rsa, RSA_NO_PADDING);
	if ( !ret )
	{
		OPENSSL_free( buf );

		goto err;
	}

	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//	nI
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, str, &str_len );
	if (!rv)
		goto err;

	/* 2:  H1(0||DaaSeed||Kk) -> f */
	exp[0] =  0x00 ;
	rv = EVP_DigestUpdate(&mdctx,  exp , e_size );
	if (!rv)
		goto err;

	DaaSeed = DAASEED;
	buf = (BYTE *) &DaaSeed;							// DaaSeed and Kk
	rv = EVP_DigestUpdate(&mdctx, buf, sizeof( DaaSeed ) );
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate(&mdctx,  Kk , strlen( Kk ) );
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, hash, &hash_len );				// put Final to f
	if (!rv)
		goto err;

	f = bi_set_as_nbin( &hash_len, hash );
	if ( f == NULL )
		goto err;

	/* 3:  u*P1 -> U   f*P1 -> F */

	/* u mul P1 and assign to  U */
	U = EC_POINT_new( group );
	F = EC_POINT_new( group );
	if ( U == NULL || F == NULL)
		goto err;

	EC_POINT_mul(group, U, NULL, IssuerPK->Eccparmeter.CapitalP1 , u, Context);
	/* f mul P1 and assign to  F */
	EC_POINT_mul(group, F, NULL, IssuerPK->Eccparmeter.CapitalP1 , fn, Context);

																			// 4:  H1(str||F||U) -> c   :// EVP_Digst_Final
	rv = EVP_DigestUpdate(&mdctx,  str , str_len );     // str release
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &( F->X ) );
	rv = EVP_DigestUpdate(&mdctx,  buf, buf_len );	//  F.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(F->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//  F.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(U->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//  U.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(U->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf, buf_len );	//  U.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, hash, &hash_len);
	if ( !rv )
		goto err;

	/* change BYTE* c to bi_ptr cn */
	c = bi_set_as_nbin( hash_len, hash );
	if ( c == NULL )
		goto err;

	/* 5: u+c*f (mod q) -> s */

	temp = bi_new_ptr();
	if ( temp == NULL )
		goto err;

	s  =  bi_new_ptr();
	if ( s == NULL )
		goto err;

	bi_mul( temp, c, f );
	bi_add( s, u, temp );
	bi_mod( s, s, module );

	/* 6:  (F，c，s) -> comm. */
	rv = EC_POINT_copy(IssuerJoinSession->CapitalF , F);
	if ( !rv )
		goto err;

	if ( IssuerJoinSession->ch == NULL )
	{
		IssuerJoinSession->ch = bi_new_ptr();
		if ( IssuerJoinSession->ch == NULL )
			goto err;
	}
	bi_set( IssuerJoinSession->ch ,c );


	if ( IssuerJoinSession->s == NULL )
	{
		IssuerJoinSession->s = bi_new_ptr();
		if ( IssuerJoinSession->s == NULL )
		{
			bi_free_ptr( IssuerJoinSession->ch );
			goto err;
		}
	}
	bi_set( IssuerJoinSession->s, s);

	bi_free_ptr( module );
	bi_free_ptr( u );
	bi_free_ptr( f );
	bi_free_ptr( c );
	bi_free_ptr( s );
	bi_free_ptr( temp );

	EC_POINT_free(U);
	EC_POINT_free(F);

	EVP_MD_CTX_cleanup(&mdctx);

	return 1;

err:
	if ( module )
		bi_free_ptr( module );
	if ( u )
		bi_free_ptr( u );
	if ( f )
		bi_free_ptr( f );
	if ( c )
		bi_free_ptr( c );
	if ( s )
		bi_free_ptr( s );
	if ( temp )
		bi_free_ptr( temp );

	if ( U )
		EC_POINT_free(U);
	if ( F )
		EC_POINT_free(F);

	EVP_MD_CTX_cleanup(&mdctx);

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
	rsa->n = bi_set_as_nbin(  PlatformEndorsementPubkeyLength, PlatformEndorsementPubKey );
	rsa->d = bi_set_as_nbin( PlatformEndorsementSkeyLength, PlatformEndorsementSKey );
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

	/* TpmJoinSession->B = B */
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
	int field_len, ret;
	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module p */
	module = bi_new_ptr();
	if ( module == NULL )
		return 0;
	ret = ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context );
	if ( !ret )
		goto err;

	/* return either an EVP_MD structure or NULL if an error occurs. */
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if ( !digest )
		goto err;

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;

	/* 1. If bsn == ⊥ */
	if ( VerifierBaseName == NULL )
	{
		/* Zq -> r'  */
		r_prime = bi_new_ptr();
		if ( r_prime == NULL )
			goto err;
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
		buf = bi_2_nbin( &buf_len, TpmJoinSession->f );
		rv = EVP_DigestUpdate_ex( &mdctx, buf, buf_len );
		OPENSSL_free( buf );
		if ( !rv )
			goto err;

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
	if ( v == NULL )
		goto err;
	bi_urandom( v, EC_GROUP_get_degree(group) );
	bi_mod( v, v, module);

	// 5. r'，D' -> HOST   :// ?
	mul = bi_new_ptr();
	if ( mul == NULL )
		goto err;

	bi_mul( mul, v, r_prime );

	*DPrime = bi_2_nbin( DPrimeLength, mul);
	if ( *DPrimeLength <= 0 )
		goto err;

	*RPrime = bi_2_nbin( RPrimeLength, r_prime );
	if ( *RPrimeLength <= 0 )
		goto err;

	if ( TpmJoinSession == NULL )
		TpmJoinSession->v = bi_new_ptr();

	if ( !bi_set( TpmJoinSession->v, v))
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

int TSS_DAA_SIGN_tpm_sign(
		                  TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
						  BYTE *  Msg,
						  BYTE *  MsgLength,
		                  BYTE *  ChPrime,
                          UINT32  ChPrimeLength,
                          BYTE **  Noncetpm,
                          UINT32 * NoncetpmLength,
                          BYTE **  Ch,
                          UINT32 * ChLength,
                          BYTE **  S,
						  UINT32 * SLength)
{
	bi_ptr nt = NULL, c = NULL, mul = NULL, module = NULL;
	BYTE   hash[DAA_HASH_SHA1_LENGTH + 1];
	UINT32 hash_len;
	int    rv;

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module p */
	module = bi_new_ptr();
	if ( module == NULL )
		return 0;
	ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context );

	/* 1. {0，1}t -> nT   : */
	nt = bi_new_ptr();
	if ( nt == NULL )
		goto err;
	bi_urandom( nt, NONCE_LENGTH);

	*Noncetpm = bi_2_nbin( NoncetpmLength , nt);
	if ( *NoncetpmLength <= 0 )
		goto err;

	/* 2. H4(c’||nT||msg) -> c   : */
	/* return either an EVP_MD structure or NULL if an error occurs. */
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if ( !digest )
		return 0;

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate( &mdctx, ChPrime, ChPrimeLength );
	if ( !rv )
		goto err;

	rv = EVP_DigestUpdate( &mdctx, *Noncetpm, *NoncetpmLength );
	if ( !rv )
		goto err;

	rv = EVP_DigestUpdate( &mdctx, Msg, MsgLength );
	if ( !rv )
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, hash, &hash_len);
	if ( hash_len != DAA_HASH_SHA1_LENGTH )
		goto err;

	ChLength = sizeof( BYTE ) * DAA_HASH_SHA1_LENGTH;
	*Ch = ( BYTE * )malloc( ChLength );
	if ( Ch = NULL )
		goto err;

	for ( i = 0; i< DAA_HASH_SHA1_LENGTH; i++ )
		*( Ch + i) = hash[i];

	// 3. v+c*f(mod q) -> s   ://bi_mul，bi_add，bi_mod
	c = bi_set_as_nbin( ChLength, *Ch);
	mul = bi_new_ptr();
	if ( mul == NULL || c == NULL )
		goto err;

	bi_mul( mul, c, TpmJoinSession->f);
	bi_add( mul, mul, TpmJoinSession->v );
	bi_mod( mul, mul, module);

	*S = bi_2_nbin( SLength, mul );
	if ( *SLength <= 0 )
		goto err;

	bi_free_ptr( module );
	bi_free_ptr( nt );
	bi_free_ptr( c );
	bi_free_ptr( mul );

	EVP_MD_CTX_cleanup(&mdctx);

	return 1;

err:
	if( module )
		bi_free_ptr( module );
	if ( nt )
		bi_free_ptr( nt );
	if ( c )
		bi_free_ptr( c );
	if ( mul )
		bi_free_ptr( mul );

	EVP_MD_CTX_cleanup(&mdctx);

	return 0;

	// TODO 4. (c，s，nT) -> HOST   :// ?
}
