/*
 * ss_verifier.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_verifier.h"
#include "tate_pairing.h"

int HASH (	BYTE * res ,
			UINT32 * reslen ,
			TSS_DAA_ISSUER_PK  * IssuerPK ,
		    BYTE *  VerifierBasename,
			UINT32  VerifierBasenameLength,,
			ECC_POINT *  CapitalA,
			ECC_POINT *  CapitalB ,
			ECC_POINT *  CapitalC ,
			ECC_POINT *  CapitalD ,
			ECC_POINT *  CapitalE ,
			COMPLEX * pa ,
			COMPLEX * pb ,
			COMPLEX * pc ,
			COMPLEX * r ,
			bi_ptr nv)
{
	EVP_MD * digest = NULL;
	EVP_MD_CTX mdctx;
	UINT32 buf_len;
	BYTE * buf = NULL;

	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalX->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK x.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalX->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK x.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalY->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK y.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalY->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK y.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate(&mdctx,  VerifierBasename , VerifierBasenameLength ); 	//  bsn
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalA->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalA.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalA->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalA.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalB->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalB.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalB->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalB.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalC->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalC.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalC->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalC.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalD->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalD.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalD->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalD.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalE->X) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalE.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalE->Y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalE.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pa->x) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pa.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pa->y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pa.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pb->x) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pb.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pb->y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pb.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pc->x) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pc.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pc->y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pc.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(r->x) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  r.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(r->y) );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  r.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, nv );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  r.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, res, reslen );
	if (!rv)
		goto err;

}

int TSS_DAA_JOIN_verifier_init(BYTE **  VerifierBasename,
                               UINT32 * VerifierBasenameLength,
                               bi_ptr   NonceVerifier)
{
	bi_ptr NV;

	NV = bi_new_ptr();
	bi_urandom( NV , NONCE_LENGTH );
	/* built up the Vbasename */
	if (!(*VerifierBasename))
		{
			*VerifierBasename = OPENSSL_malloc( strlen(BASENAME)+1 );
		}
	if (!VerifierBasenameLength)
		{
			VerifierBasenameLength = OPENSSL_malloc( sizeof(UINT32) / 8 );
		}
	strcpy(*VerifierBasename,BASENAME);
	*VerifierBasenameLength = strlen(BASENAME);
	/*built the Nonceverifier*/
	NonceVerifier = NV;
	NV = NULL;
}

int TSS_DAA_JOIN_verifier_verify(TSS_DAA_SIGNNATURE *   DaaSignature,
							     TSS_DAA_ISSUER_PK  *   IssuerPK,
							     BYTE **  VerifierBasename,
							     UINT32 * VerifierBasenameLength,
							     BYTE   * Msg,
							     UINT32   MsgLength,
                                 UINT32 * IsCorrect)
{
	/*TODO 1. Check rogue list fi*B'   */

	/* 2. Check A' and B' t(A'，Y) == t(B’，P2) */
	bi_ptr module = NULL , store =NULL ;
	COMPLEX *res1 = NULL , *res2 = NULL , *res3 = NULL , pta = NULL , ptb = NULL , ptc = NULL , rt = NULL;
	BN_CTX *ctx = NULL;
	ECC_POINT * SB = NULL , CE = NULL , DT = NULL;
	BYTE  hash[DAA_HASH_SHA1_LENGTH] , final_hash[DAA_HASH_SHA1_LENGTH];
	UINT32 hashlen , final_hashlen;

	ctx = BN_CTX_new();

	int precomp = 0 , ok;

	COMP_init(res1);
	COMP_init(res2);
	COMP_init(res3);
	COMP_init(pta);
	COMP_init(ptb);
	COMP_init(ptc);

	SB = EC_POINT_new(group);
	CE = EC_POINT_new(group);
	DT = EC_POINT_new(group);

	module = bi_new_ptr();
	store = bi_new_ptr();
	sb = bi_new_ptr();
	ce = bi_new_ptr();
	dt = bi_new_ptr();

	/* Get group module p */
	ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context );

	/*TODO change the DaaSignature->CapitalAprime ? */
	Ok=ecap( &(DaaSignature->CapitalAprime) , IssuerPK->CapitalY , module , precomp , store , res1);

	Ok=ecap( &(DaaSignature->CapitalBPrime) , IssuerPK->Eccparmeter.CapitalP2 , module , precomp , store , res2);

	if ( !COMP_cmp( res1 , res2 ) ) goto err;

	COMP_is_zero( res1 );
	COMP_is_zero( res2 );

	/* 3. t(A'，X) -> ρ†a   t(B’，X) -> ρ†b   t(C'，P2) -> ρ†c   */

	Ok=ecap( &(DaaSignature->CapitalAprime) , IssuerPK->CapitalX , module , precomp , store , pta);

	Ok=ecap( &(DaaSignature->CapitalBPrime) , IssuerPK->CapitalX , module , precomp , store , ptb);

	Ok=ecap( &(DaaSignature->CapitalCPrime) , IssuerPK->Eccparmeter.CapitalP2 , module , precomp , store , ptc);

	/* 4. (ρ†b)s *(ρ†c/ρ†a)-c * -> T†   */

	res1 = COMP_pow(res1 , ptb , DaaSignature->s , module);

	res2 = COMP_div(res2 , pta , ptc , module);

	res3 = COMP_pow(res3 , res2 , DaaSignature->ch , module);

	COMP_is_zero( res2 );

	res2 = COMP_mul(res2 , res1 , res3 , module );

	rt = res2;

	/*5. S*B' – c E' -> D†
	 * int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);*/
	ret = EC_POINT_mul(group, SB , NULL, &(DaaSignature->CapitalBPrime) , DaaSignature->s, ctx);

	ret = EC_POINT_mul(group, CE , NULL, &(DaaSignature->CapitalEPrimeCapitalBprime) , DaaSignature->ch, ctx);

	ret = EC_POINT_invert(group, CE, ctx);					/* use  EC_POINT_invert to updown CF so can add it */

	ret = EC_POINT_add(group, DT, SB, CE , ctx);			/* SP1+CF = UP( U’) */

	/* 6. H(ipk||bsn||A'||B'||C'||D'||E'||ρ†a||ρ†b||ρ†c|| T†||nv) -> c†    */

	HASH (	hash ,
			&hashlen ,
			IssuerPK ,
			*VerifierBasename ,
			*VerifierBasenameLength ,
			&(DaaSignature->CapitalAprime) ,
			&(DaaSignature->CapitalBPrime) ,
			&(DaaSignature->CapitalCPrime) ,
			DT ,
			&(DaaSignature->CapitalEPrime) ,
			pta ,
			ptb ,
			ptc ,
			rt ,
			DaaSignature->nv);

	/* 7.1 Make H4(c†|nT||msg) = final_hash    */

	EVP_MD * digest = NULL;
	EVP_MD_CTX mdctx;
	UINT32 buf_len;
	BYTE * buf = NULL;

	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );

	rv = EVP_DigestUpdate(&mdctx,  hash , hashlen ); 	//  ct
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, DaaSignature->nt );
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  nt
	OPENSSL_free( buf );
	if (!rv)
		goto err;
														//TODO haven't define msg
	rv = EVP_DigestUpdate(&mdctx,  MSG , MSG_LEN ); 	//  nt
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, final_hash, &final_hashlen );
	if (!rv)
		goto err;

	/*TODO 7. check final_hash == c   */
}
