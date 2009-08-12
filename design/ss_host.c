/*
 * ss_host.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_host.h"

//int TSS_DAA_JOIN_host_init();

//int TSS_DAA_JOIN_host_credential_request();

int TSS_DAA_JOIN_host_credential_store(BYTE * CapitalE,                             // in
                                       UINT32 CapitalElength,                       // in
                                       BYTE * CredentialBytes,                      // in
                                       UINT32 CredentialBytesLength,                // in
                                       TSS_DAA_ISSUER_PK  * IssuerPK,               // in
                                       TSS_DAA_CREDENTIAL2 *DaaCredential,          // out
                                       TSS_DAA_HOST_JOIN_SESSION * HostJoinSession) // out
{
	EC_POINT *point = NULL;
	COMPLEX  *complex1 = NULL, *complex2 = NULL;
	bi_ptr   order = NULL;
	UINT32   field_len, len;
	int      ret, precomp;

	/* Get group base point order */
	order = bi_new_ptr();
	if ( order == NULL )
		return 0;
	/* order = group->order */
	ret = EC_GROUP_get_order( group, order, Context );
	if ( !ret )
		goto err;

	field_len = (EC_GROUP_get_degree(group) + 7) / 8;
	if ( field_len <= 0 )
		goto err;
	len = 3 * field_len;

	// TODO if DEBUG the DaaCredential->CapitalA
	point = EC_POINT_new( group );
	if ( point == NULL )
		goto err;
	DaaCredential->CapitalA = EC_POINT_new( group );
	DaaCredential->CapitalB = EC_POINT_new( group );
	DaaCredential->CapitalC = EC_POINT_new( group );
	if( DaaCredential->CapitalA == NULL || DaaCredential->CapitalB == NULL || DaaCredential->CapitalC == NULL )
		goto err;

	ret = EC_POINT_oct2point( group, point, CredentialBytes, len, Context);
	if (!EC_POINT_copy( DaaCredential->CapitalA, point ))
		goto err;

	ret = EC_POINT_oct2point( group, point, (CredentialBytes + field_len * 4 ) , len , Context);
	if (!EC_POINT_copy( DaaCredential->CapitalB, point ))
		goto err;

	ret = EC_POINT_oct2point( group, point, ( CredentialBytes + field_len * 8 ), len , Context);
	if (!EC_POINT_copy( DaaCredential->CapitalC, point ))
		goto err;

	// 1. t(A，X) ->ρa   :// ?Tate(Ppub,Qid,q,precomp,store,gid);

	HostJoinSession->Roa = COMP_new();
	HostJoinSession->Rob = COMP_new();
	HostJoinSession->Roc = COMP_new();
	if ( HostJoinSession->Roa == NULL || HostJoinSession->Rob == NULL || HostJoinSession->Roc == NULL)
		goto err;

	precomp = 0;
	complex1 = COMP_new();

	ret = Tate( DaaCredential->CapitalA, IssuerPK->CapitalX, order, precomp, store, complex1);
	if ( !ret )
		goto err;

	ret = COMP_copy( HostJoinSession->Roa, complex1 );
	if ( !ret )
		goto err;

	// 2. t(B，X) -> ρb   :// ?
	ret = Tate( DaaCredential->CapitalB, IssuerPK->CapitalX, order, precomp, store, complex1);
	if ( !ret )
		goto err;

	ret = COMP_copy( HostJoinSession->Rob, complex1 );
	if ( !ret )
		goto err;

	// 3. t(C，P2) -> ρc   :// ?
	if ( IssuerPK->Eccparmeter.CapitalP2 == NULL )
		goto err;
	ret = Tate( DaaCredential->CapitalC, IssuerPK->Eccparmeter.CapitalP2, order, precomp, store, complex1);
	if ( !ret )
		goto err;

	ret = COMP_copy( HostJoinSession->Roc, complex1 );
	if ( !ret )
		goto err;

	// 4. check t(A，Y) == t(B，P2) || t(A+E，X) ==ρc   :// ?
	ret = Tate( DaaCredential->CapitalA, IssuerPK->CapitalY, order, precomp, store, complex1);
	if ( !ret )
		goto err;

	complex2 = COMP_new();

	ret = Tate( DaaCredential->CapitalB, IssuerPK->Eccparmeter.CapitalP2, order, precomp, store, complex2);
	if ( !ret )
		goto err;

	if ( COMP_cmp( complex1, complex2 ) )
	{
		printf(" t(A, Y) != t(B, P2) \n ");
		goto err;
	}

	ret = EC_POINT_oct2point( group, point, CapitalE , len, Context);
	if ( !ret )
		goto err;

	ret = EC_POINT_add( group, point, DaaCredential->CapitalA, point, Context);
	if ( !ret )
		goto err;

	ret = Tate( point, IssuerPK->CapitalX, order, precomp, store, complex1);
	if ( !ret )
		goto err;

	if ( COMP_cmp( HostJoinSession->Roc, complex1) )
	{
		printf(" t(A + E, X) = Roc \n ");
		goto err;
	}

	bi_free_ptr( order );
	EC_POINT_free( point );
	COMP_free( complex1 );
	COMP_free( complex2 );

	return 1;

err:

	bi_free_ptr( order );

	if ( point )
		EC_POINT_free( point );

	if ( complex1 )
		COMP_free( complex1 );

	if (complex2 )
		COMP_free( complex2 );

	return 0;
}

int TSS_DAA_SIGN_host_sign(BYTE * RPrime,                               // in
                           UINT32 RPrimeLength,                         // in
                           BYTE * DPrime,                               // in
                           UINT32 DPrimeLength,                         // in
                           BYTE * NonceVerifier,                        // in
                           UINT32 NonceVerifierLength,                  // in
                           TSS_DAA_CREDENTIAL2 *DaaCredential,          // in
                           TSS_DAA_ISSUER_PK  * IssuerPK,               // in
                           TSS_DAA_HOST_JOIN_SESSION *HostJoinSession,  // in
                           TSS_DAA_SIGNNATURE *   DaaSignature          // out
                           )
{
	bi_ptr   module = NULL, nv = NULL, rprime = NULL, order = NULL;
	EC_POINT *point = NULL;
	COMPLEX  comp, *complex = &comp, Roaprime, Robprime, Rocprime;
	BYTE     hash[DAA_HASH_SHA1_LENGTH];
	UINT32   hash_len;
	BIGNUM   store[500];
	int      ret, precomp = 0;

	/* Get group module p */
	module = bi_new_ptr();
	if ( module == NULL )
		return 0;
	ret = ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context );
	if ( !ret )
		goto err;

	/* Get group order */
	order = bi_new_ptr();
	if ( order == NULL )
		return 0;
	/* order = group->order */
	ret = EC_GROUP_get_order( group, order, Context );
	if ( !ret )
		goto err;

	/* 1. {0，1}t -> nv or get nv from verifier   : */

	/* NonceVerfier is NULL, nv is random  */
	if ( NonceVerifier == NULL || NonceVerifierLength == 0)
	{
		/* Zq -> nv  */
		nv  = bi_new_ptr();
		if ( nv == NULL )
			goto err;

		bi_urandom( nv, EC_GROUP_get_degree(group) );
		bi_mod( nv, nv, module);
	}
	else
	{
		/* Get nv from verifier */
		nv = bi_set_as_nbin( NonceVerifierLength, NonceVerifier);
		if ( nv == NULL )
			goto err;
	}

	if ( RPrime == NULL || RPrimeLength == 0 )
		goto err;

	rprime = bi_set_as_nbin( RPrimeLength, RPrime );
	if ( rprime == NULL )
		goto err;

	/* 2. r'*A -> A'   r'*C -> C'  r'*C -> B'   r'*E -> E'   : */

	/* Init point */
	point = EC_POINT_new( group );
	if ( point == NULL )
		goto err;

	/* point = r' * A */
	ret = EC_POINT_mul( group, point, NULL, DaaCredential->CapitalA, rprime, Context );
	if ( !ret )
		goto err;

	ret = EC_POINT_copy( DaaSignature->CapitalAPrime, point );
	if ( !ret )
		goto err;

	/* C' = r' * C */
	ret = EC_POINT_mul( group, point, NULL, DaaCredential->CapitalC, rprime, Context );
	if ( !ret )
		goto err;

	ret = EC_POINT_copy( DaaSignature->CapitalCPrime, point );
	if ( !ret )
		goto err;

	/* B' = r'*B   */
	ret = EC_POINT_mul( group, point, NULL, DaaCredential->CapitalB, rprime, Context );
	if ( !ret )
		goto err;

	ret = EC_POINT_copy( DaaSignature->CapitalBPrime, point );
	if ( !ret )
		goto err;

	/* E' = r'*E   */
	ret = EC_POINT_mul( group, point, NULL, HostJoinSession->CapitalE, rprime, Context );
	if ( !ret )
		goto err;

	ret = EC_POINT_copy( DaaSignature->CapitalEPrime, point );
	if ( !ret )
		goto err;

	/* 3. ρar' -> ρa'   ρbr' -> ρb'   ρcr' ->ρc'   : */
	// 	TODO change EC_POINT Roa to COMPLEX;
	COMP_init( complex );
	COMP_init( &Roaprime );
	COMP_init( &Robprime );
	COMP_init( &Rocprime );

	/* ρa^r' -> ρa' */
	if ( !COMP_pow( complex, HostJoinSession->Roa, rprime, module ) )
		goto err;

	if ( !COMP_copy( &Roaprime, complex ) )
		goto err;

	/* ρb^r' -> ρb' */
	if ( !COMP_pow( complex, HostJoinSession->Rob, rprime, module ) )
		goto err;

	if ( !COMP_copy( &Robprime, complex ) )
		goto err;

	/* ρc^r' -> ρc' */
	if ( !COMP_pow( complex, HostJoinSession->Roc, rprime, module ) )
		goto err;

	if ( !COMP_copy( &Rocprime, complex ) )
		goto err;

	// 5. t(D'，X) -> т :// ?
	ret = EC_POINT_oct2point( group, point, DPrime , DPrimeLength, Context);
	if ( !ret )
		goto err;

	ret = Tate( point, IssuerPK->CapitalX, order, precomp, store, complex);
	if ( !ret )
		goto err;

	// 6. H3 (ipk||bsn||A'||B'||C'||D'||E'||ρa'||ρb'||ρc'||т||nv) -> c'   :// EVP_Digest_Final
	compute_sign_challenge(hash,
			            &hash_len,
						IssuerPK,
						BSN,
						strlen( BSN ),
						DaaSignature->CapitalAPrime,
						DaaSignature->CapitalBPrime,
						DaaSignature->CapitalCPrime,
						point,
						DaaSignature->CapitalEPrime,
						&Roaprime,
						&Robprime,
						&Rocprime,
						complex,
						nv
						);

	bi_free_ptr( module );
	bi_free_ptr( nv );
	bi_free_ptr( rprime );
	bi_free_ptr( order );

	EC_POINT_free( point );

	COMP_free( complex );
	COMP_free( &Roaprime );
	COMP_free( &Robprime );
	COMP_free( &Rocprime );

	return 1;

err:

	if ( module )
		bi_free_ptr( module );
	if ( nv )
		bi_free_ptr( nv );
	if (rprime )
		bi_free_ptr( rprime );
	if ( order )
		bi_free_ptr( order );

	if ( point )
		EC_POINT_free( point );

	COMP_free( complex );
	COMP_free( &Roaprime );
	COMP_free( &Robprime );
	COMP_free( &Rocprime );

	return 0;
	//7. c' -> TPM   :// ?

}
