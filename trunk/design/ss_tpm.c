/*
 * ss_tpm.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_tpm.h"
#include <string.h>

/* rsa_bi_load usage:
 *   ------------- put key int which (rsa_n, rsa_n, rsa_d) not NULL one
 *	 ------------- example rsa_bi_load(rsa->n, NULL, NULL) it put rsa-n key into rsa->n
 * 	 is not full code
 *	 and return 0 mean error
 *	 README: rsa_new didn't new rsa->n and so on , we need do rsa->n = bi_new_ptr();
 * */
int rsa_bi_load(bi_ptr rsa_n, bi_ptr rsa_e, bi_ptr rsa_d)
{
	bi_ptr n = NULL, e = NULL, d = NULL;
	FILE *fp;
	fp = fopen("key","r+");
	if (!fp) return 0;
		/*_we have to malloc the space_*/
	if (!rsa_n) n = bi_new_ptr();
	if (!rsa_e) e = bi_new_ptr();
	if (!rsa_d) d = bi_new_ptr();

	if (rsa_n)
		bi_load( rsa_n, fp);
	else
		bi_load( n, fp);

	if (rsa_e)
		bi_load( rsa_e, fp);
	else
		bi_load( e, fp);

	if (rsa_d)
		bi_load( rsa_d, fp);
	else
		bi_load( d, fp);

	fclose(fp);

	if (n) bi_free_ptr( n );
	if (e) bi_free_ptr( e );
	if (d) bi_free_ptr( d );

	return 1;
err:
	if (n) bi_free_ptr( n );
	if (e) bi_free_ptr( e );
	if (d) bi_free_ptr( d );
	return 0;
}

int TSS_DAA_JOIN_credential_request(BYTE * EncryptedNonceOfIssuer,
                                    UINT32 EncryptedNonceOfIssuerLength,
                                    TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                    TSS_DAA_ISSUER_PK        * IssuerPK,
                                    TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession
                                    ) //TODO change to BYTE *
{
	bi_ptr   u = NULL , f = NULL , c = NULL ,s = NULL , order = NULL, temp = NULL;
	EC_POINT *U = NULL, *F = NULL;
	RSA      *rsa = NULL;

	BYTE     *buf = NULL , str[DAA_HASH_SHA1_LENGTH] , hash[DAA_HASH_SHA1_LENGTH];
	BYTE     exp[] = { 0x01 };
	UINT32   DaaSeed;
	int      buf_len, rv, e_size = 1;
	unsigned int hash_len, str_len;

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module p */
	order = bi_new_ptr();
	if ( order == NULL )
		return 0;
	/* order = group->order */
	rv = EC_GROUP_get_order( group, order, Context );
	if ( !rv )
		goto err;

	/* 1. Zq -> u */
	u  = bi_new_ptr();
	if ( u == NULL )
		goto err;
	/* u = radom % order */
	bi_urandom( u, NONCE_LENGTH );
	bi_mod( u, u, order );

	/* init Digest */
	OpenSSL_add_all_digests();
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
	/*  secret key of Ek and Publick key of EK*/
	/*  here try to read from file key  */
//	FILE *fp;
//	fp = fopen("key","r+");
//	if (!fp) goto err;
//	/*_we have to malloc the space_*/
//	rsa->n = bi_new_ptr();
//	rsa->e = bi_new_ptr();
//	rsa->d = bi_new_ptr();
//
//	bi_load( rsa->n, fp); if (!rsa->n) goto err;
//	bi_load( rsa->e, fp); if (!rsa->e) goto err;
//	bi_load( rsa->d, fp); if (!rsa->d) goto err;
//
//	fclose(fp);
	rsa->n = bi_new_ptr();
	rsa->e = bi_new_ptr();
	rsa->d = bi_new_ptr();
	rv = rsa_bi_load(rsa->n, rsa->e, rsa->d);
	if (!rv)
		goto err;
	/*-- end --*/
    if ( ( rsa->d == NULL ) || ( rsa->n == NULL ) )
    	goto err;

    buf = ( BYTE * )malloc( sizeof(BYTE) * (RSA_MODULE_LENGTH / 8) );
    if ( buf == NULL )
    	goto err;

	buf_len = RSA_private_decrypt(EncryptedNonceOfIssuerLength, EncryptedNonceOfIssuer,buf, rsa, RSA_PKCS1_PADDING);
	if ( buf_len <= 0 )
	{
		OPENSSL_free( buf );
		goto err;
	}
#ifdef DEBUG
	int ii;
	for (ii=0;ii<buf_len;ii++)
	{
		printf("%02x",buf[ii]);
	}
#endif

	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len );	//	nI
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, str, &str_len );
	if (!rv)
		goto err;
#ifdef DEBUG


	printf(" str in %s: %d \n", __FILE__, __LINE__ );
	for (ii=0;ii<str_len;ii++)
		printf("%02x",str[ii]);
	printf("\n");
#endif

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

	f = bi_set_as_nbin( hash_len, hash );
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
	EC_POINT_mul(group, F, NULL, IssuerPK->Eccparmeter.CapitalP1 , f, Context);

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

#ifdef DEBUG


	printf(" hash(C) in %s: %d\n", __FILE__, __LINE__ );
	for (ii=0;ii<hash_len;ii++)
		printf("%02x",hash[ii]);
	printf("\n");
#endif

	/* 5: u+c*f (mod q) -> s */

	temp = bi_new_ptr();
	if ( temp == NULL )
		goto err;

	s  =  bi_new_ptr();
	if ( s == NULL )
		goto err;

	/* temp = c *f */
	bi_mul( temp, c, f );
	/* s = u + temp */
	bi_add( s, u, temp );
	bi_mod( s, s, order );

	/* 6:  (F，c，s) -> comm. */
	IssuerJoinSession->CapitalF = EC_POINT_new(group);
	if ( IssuerJoinSession->CapitalF == NULL )
		goto err;
	rv = EC_POINT_copy( IssuerJoinSession->CapitalF, F);
	if ( !rv )
		goto err;

	IssuerJoinSession->ch = bi_new_ptr();
	if ( IssuerJoinSession->ch == NULL )
		goto err;

	bi_set( IssuerJoinSession->ch ,c );

	IssuerJoinSession->s = bi_new_ptr();
	if ( IssuerJoinSession->s == NULL )
	{
		bi_free_ptr( IssuerJoinSession->ch );
		goto err;
	}

	bi_set( IssuerJoinSession->s, s);

	TpmJoinSession->f = bi_new_ptr();
	if ( TpmJoinSession->f == NULL )
		goto err;

	bi_set( TpmJoinSession->f , f );

	bi_free_ptr( order );
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
	if ( order )
		bi_free_ptr( order );
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

int TSS_DAA_JOIN_tpm_credential(BYTE *   EncryptedCred,
                                UINT32   EncryptedCredLength,
                                TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                BYTE **  Credential,
                                UINT32 * CredentialLength,
                                BYTE **  CapitalE,
                                UINT32 * CapitalELength)
{
	EC_POINT *A, *B, *C, *E;
	RSA      *rsa = NULL;
	BYTE     *PlatformEndorsementPubKey = NULL;
	UINT32   field_len, PlatformEndorsementPubkeyLength;
	int      ret;

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
#if 0
	rsa->d = bi_set_as_nbin( PlatformEndorsementSkeyLength, PlatformEndorsementSKey );
#endif
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

	EC_POINT_oct2point( group, A, *Credential, field_len * 2, Context);
	EC_POINT_oct2point( group, B, ( *Credential + field_len * 2), field_len * 2, Context);
	EC_POINT_oct2point( group, C, ( *Credential + field_len * 4 ), field_len * 2, Context);

	// 2. f*B -> E   :// ?
	/* f * B */
	*CapitalELength = sizeof( BYTE ) * field_len ;
	*CapitalE = ( BYTE * )malloc(sizeof( BYTE ) * field_len );

	EC_POINT_mul(group, E, NULL, B , TpmJoinSession->f, Context );	// mul the F

	EC_POINT_point2oct( group, E, POINT_CONVERSION_UNCOMPRESSED, *CapitalE, *CapitalELength, Context);
	if ( !*CapitalE )
		goto err;

	*CapitalELength = strlen( *CapitalE );

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
	bi_ptr order = NULL , r_prime = NULL , v = NULL , mul = NULL;
	BYTE * buf = NULL , hash[DAA_HASH_SHA1_LENGTH +1];
	int hash_len, buf_len;
	EC_POINT *D_prime;
	int field_len, ret, rv;

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module p */
	order = bi_new_ptr();
	if ( order == NULL )
		return 0;
	/* order = group->order */
	rv = EC_GROUP_get_order( group, order, Context );
	if ( !rv )
		goto err;

	/* return either an EVP_MD structure or NULL if an error occurs. */
	OpenSSL_add_all_digests();
	EVP_MD_CTX_init( &mdctx );
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

		bi_urandom( r_prime, EC_GROUP_get_degree(group) );
		bi_mod( r_prime, r_prime, order);
	}
	else
	{
		/* 3. H2(f||bsn) -> r'   : */
		buf = bi_2_nbin( &buf_len, TpmJoinSession->f );
		rv = EVP_DigestUpdate( &mdctx, buf, buf_len );
		OPENSSL_free( buf );
		if ( !rv )
			goto err;

		rv = EVP_DigestUpdate( &mdctx, VerifierBaseName, VerifierBaseNameLength );
		if ( !rv )
			goto err;

		rv = EVP_DigestFinal_ex(&mdctx, hash, &hash_len);
		if ( hash_len != DAA_HASH_SHA1_LENGTH )
			goto err;

		r_prime = bi_set_as_nbin( hash_len, hash );
		if ( !r_prime )
			goto err;
	}

	/* 4. Zq -> v   (vr')*B -> D'   : */
	v = bi_new_ptr();
	if ( v == NULL )
		goto err;
	bi_urandom( v, EC_GROUP_get_degree(group) );
	bi_mod( v, v, order);

	// 5. r'，D' -> HOST   :// ?
	mul = bi_new_ptr();
	if ( mul == NULL )
		goto err;

	bi_mul( mul, v, r_prime );

	/* DPrime = mul * B */
	D_prime = EC_POINT_new( group );
	if ( D_prime == NULL )
		goto err;

	/* D' = mul * B */
	ret = EC_POINT_mul(group, D_prime, NULL, TpmJoinSession->B, mul, Context);
	if ( !ret ) goto err;

	/* EC_POINT D' to bytes */
	*DPrimeLength = sizeof( BYTE ) * EC_GROUP_get_degree(group) * 2;
	*DPrime = ( BYTE * )malloc( *DPrimeLength + 1 );
	if ( *RPrime == NULL )
		goto err;

	ret = EC_POINT_point2oct(group, D_prime, POINT_CONVERSION_UNCOMPRESSED, *DPrime, *DPrimeLength + 1,  Context);
	if ( ret <= 0 )
		goto err;

	/* r_prime to bytes */
	*RPrime = bi_2_nbin( RPrimeLength, r_prime );
	if ( *RPrimeLength <= 0 )
		goto err;

	/* TpmJoinSession->v = v */
	TpmJoinSession->v = bi_new_ptr();
	if ( !bi_set( TpmJoinSession->v, v))
		goto err;

	bi_free_ptr( order );
	bi_free_ptr( r_prime );
	bi_free_ptr( v );
	bi_free_ptr( mul );
	EC_POINT_free ( D_prime );

	EVP_MD_CTX_cleanup(&mdctx);

	return 1;
err:
    if ( order )
    	bi_free_ptr( order );

    if ( r_prime )
    	bi_free_ptr( r_prime );
	if ( v )
		bi_free_ptr( v );
	if ( mul )
		bi_free_ptr( mul );
	if ( D_prime )
		EC_POINT_free( D_prime );

	EVP_MD_CTX_cleanup(&mdctx);

	return 0;
}

int TSS_DAA_SIGN_tpm_sign(
		                  TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
						  BYTE *  Msg,
						  UINT32  MsgLength,
		                  BYTE *  ChPrime,
                          UINT32  ChPrimeLength,
                          BYTE **  Noncetpm,
                          UINT32 * NoncetpmLength,
                          BYTE **  Ch,
                          UINT32 * ChLength,
                          BYTE **  S,
						  UINT32 * SLength)
{
	bi_ptr nt = NULL, c = NULL, mul = NULL, order = NULL;
	BYTE   hash[DAA_HASH_SHA1_LENGTH + 1];
	int    hash_len;
	int    rv, i;

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	/* Get group module order */
	order = bi_new_ptr();
	if ( order == NULL )
		return 0;
	/* order = group->order */
	rv = EC_GROUP_get_order( group, order, Context );
	if ( !rv )
		goto err;

	/* 1. {0，1}t -> nT   : */
	nt = bi_new_ptr();
	if ( nt == NULL )
		goto err;
	bi_urandom( nt, NONCE_LENGTH);

	*Noncetpm = bi_2_nbin( (int *)NoncetpmLength , nt);
	if ( *NoncetpmLength <= 0 )
		goto err;

	/* 2. H4(c’||nT||msg) -> c   : */
	/* return either an EVP_MD structure or NULL if an error occurs. */
	OpenSSL_add_all_digests();
	EVP_MD_CTX_init( &mdctx );
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

	*ChLength = sizeof( BYTE ) * DAA_HASH_SHA1_LENGTH;
	*Ch = ( BYTE * )malloc( *ChLength );
	if ( *Ch == NULL )
		goto err;

	for ( i = 0; i< DAA_HASH_SHA1_LENGTH; i++ )
		*( *Ch + i) = hash[i];

	// 3. v+c*f(mod q) -> s   ://bi_mul，bi_add，bi_mod
	c = bi_set_as_nbin( *ChLength, *Ch);
	mul = bi_new_ptr();
	if ( mul == NULL || c == NULL )
		goto err;

	bi_mul( mul, c, TpmJoinSession->f);
	bi_add( mul, mul, TpmJoinSession->v );
	bi_mod( mul, mul, order);

	*S = bi_2_nbin( SLength, mul );
	if ( *SLength <= 0 )
		goto err;

	bi_free_ptr( order );
	bi_free_ptr( nt );
	bi_free_ptr( c );
	bi_free_ptr( mul );

	EVP_MD_CTX_cleanup(&mdctx);

	return 1;

err:
	if( order )
		bi_free_ptr( order );
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
