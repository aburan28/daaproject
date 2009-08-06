/*
 * ss_verifier.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_verifier.h"
#include "tate_pairing.h"
#include <string.h>

int compute_sign_challenge (BYTE *res ,
		UINT32 * reslen ,
		TSS_DAA_ISSUER_PK  * IssuerPK ,
		BYTE *  VerifierBasename,
		UINT32  VerifierBasenameLength,
		ECC_POINT *  CapitalA,
		ECC_POINT *  CapitalB ,
		ECC_POINT *  CapitalC ,
		ECC_POINT *  CapitalD ,
		ECC_POINT *  CapitalE ,
		COMPLEX * pa ,
		COMPLEX * pb ,
		COMPLEX * pc ,
		COMPLEX * t ,
		bi_ptr nv)
{
	EVP_MD     *digest = NULL;
	EVP_MD_CTX mdctx;
	int        buf_len;
	char       *buf = NULL;
	int        rv;

	if (  !res || !VerifierBasename || VerifierBasenameLength  <= 0 ) return 0;

	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );

	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalX->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK x.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalX->Y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK x.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalY->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK y.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(IssuerPK->CapitalY->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  IssuerPK y.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestUpdate(&mdctx,  VerifierBasename , VerifierBasenameLength ); 	//  bsn
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalA->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalA.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalA->Y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalA.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalB->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalB.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalB->Y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalB.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalC->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalC.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalC->Y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalC.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalD->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalD.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalD->Y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalD.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalE->X) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalE.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(CapitalE->Y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  CapitalE.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pa->x) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pa.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pa->y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pa.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pb->x) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pb.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pb->y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pb.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pc->x) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pc.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(pc->y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  pc.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(t->x) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  t.x
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, &(t->y) );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  t.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	buf = bi_2_nbin ( &buf_len, nv );
	if (!buf) goto err;
	rv = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  r.y
	OPENSSL_free( buf );
	if (!rv)
		goto err;

	rv = EVP_DigestFinal_ex(&mdctx, res, reslen );
	if (!rv)
		goto err;

	EVP_MD_CTX_cleanup(&mdctx);
	return 1;

err:
	EVP_MD_CTX_cleanup(&mdctx);
	return 0;
}

int TSS_DAA_JOIN_verifier_init(BYTE **  VerifierBasename,
                               UINT32 * VerifierBasenameLength,
                               bi_ptr   NonceVerifier)
{
	bi_ptr NV;

	NV = bi_new_ptr(); // CHECK
	bi_urandom( NV , NONCE_LENGTH );

	/* built up the Vbasename */

	*VerifierBasename = OPENSSL_malloc( strlen(BASENAME)+1 );

	strcpy( *VerifierBasename, BASENAME );
	*VerifierBasenameLength = strlen( BASENAME );
	/*built the Nonceverifier*/
	NonceVerifier = NV;
//	NV = NULL;

	return 1;
}

int TSS_DAA_JOIN_verifier_verify(TSS_DAA_SIGNNATURE *   DaaSignature,
							     TSS_DAA_ISSUER_PK  *   IssuerPK,
							     BYTE *  VerifierBasename,
							     UINT32  VerifierBasenameLength,
							     BYTE   * Msg,
							     UINT32   MsgLength,
                                 UINT32 * IsCorrect )
{
	COMPLEX *res1 = NULL , *res2 = NULL , *res3 = NULL , *pta = NULL , *ptb = NULL , *ptc = NULL , *rt = NULL;
	bi_ptr module = NULL ;
	ECC_POINT *SB = NULL , *CE = NULL , *DT = NULL;
	BYTE  hash[DAA_HASH_SHA1_LENGTH] , final_hash[DAA_HASH_SHA1_LENGTH] , * buf = NULL;
	UINT32 hashlen , final_hashlen ,  buf_len;
	BIGNUM store[500];
	int ret, i;

	EVP_MD * digest = NULL;
	EVP_MD_CTX mdctx;

	int precomp = 0 , ok;

	res1 = COMP_new();
	res2 = COMP_new();
	res3 = COMP_new();
	pta = COMP_new();
	ptb = COMP_new();
	ptc = COMP_new();

	module = bi_new_ptr();

	/* 1. Check rogue list fi*B'   */

	/* 2. Check A' and B' t(A'，Y) == t(B’，P2) */

	/* Get group module p */
	ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context );

	for (i = 0; i < 500; i++)
	{
		BN_init(&store[i]);
	}

	ret = Tate( &(DaaSignature->CapitalAPrime) , IssuerPK->CapitalY , module , precomp , store , res1);
	if (!ret) goto err;

	ret = Tate( &(DaaSignature->CapitalBPrime) , IssuerPK->Eccparmeter.CapitalP2 , module , precomp , store , res2);
	if (!ret) goto err;

	if ( !COMP_cmp( res1 , res2 ) ) goto err;

	/* 3. t(A'，X) -> ρ†a   t(B’，X) -> ρ†b   t(C'，P2) -> ρ†c   */

	ret = Tate( &(DaaSignature->CapitalAPrime) , IssuerPK->CapitalX , module , precomp , store , pta);
	if (!ret) goto err;

	ret = Tate( &(DaaSignature->CapitalBPrime) , IssuerPK->CapitalX , module , precomp , store , ptb);
	if (!ret) goto err;

	ret = Tate( &(DaaSignature->CapitalCPrime) , IssuerPK->Eccparmeter.CapitalP2 , module , precomp , store , ptc);
	if (!ret) goto err;

	/* 4. (ρ†b)s *(ρ†c/ρ†a)-c * -> T†   */

	res1 = COMP_pow(res1 , ptb , DaaSignature->s , module);
	if (!res1) goto err;

	res2 = COMP_div(res2 , pta , ptc , module);
	if (!res2) goto err;

	res3 = COMP_pow(res3 , res2 , DaaSignature->ch , module);
	if (!res3) goto err;

	res2 = COMP_mul(res2 , res1 , res3 , module );
	if (!res2) goto err;

	rt = res2;

	/*5. S*B' – c E' -> D† */

	SB = EC_POINT_new(group);
	CE = EC_POINT_new(group);
	DT = EC_POINT_new(group);

	ret = EC_POINT_mul(group, SB , NULL, &(DaaSignature->CapitalBPrime) , DaaSignature->s, Context);
	if (!ret) goto err;

	ret = EC_POINT_mul(group, CE , NULL, &(DaaSignature->CapitalEPrime) , DaaSignature->ch, Context);
	if (!ret) goto err;

	ret = EC_POINT_invert(group, CE, Context);					/* use  EC_POINT_invert to updown CF so can add it */
	if (!ret) goto err;

	ret = EC_POINT_add(group, DT, SB, CE , Context);			/* SP1+CF = UP( U’) */
	if (!ret) goto err;

	/* 6. H(ipk||bsn||A'||B'||C'||D'||E'||ρ†a||ρ†b||ρ†c|| T†||nv) -> c†    */

	ret = compute_sign_challenge (
			hash ,
			&hashlen ,
			IssuerPK ,
			VerifierBasename ,
			VerifierBasenameLength ,
			&(DaaSignature->CapitalAPrime) ,
			&(DaaSignature->CapitalBPrime) ,
			&(DaaSignature->CapitalCPrime) ,
			DT ,
			&(DaaSignature->CapitalEPrime) ,
			pta ,
			ptb ,
			ptc ,
			rt ,
			DaaSignature->nv);
	if (!ret || hashlen <= 0 ) goto err;

	/* 7.1 Make H4(c†|nT||msg) = final_hash    */

	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );

	ret = EVP_DigestInit_ex( &mdctx , digest , NULL );

	ret = EVP_DigestUpdate(&mdctx,  hash , hashlen ); 	//  ct
	if (!ret)
		goto err;

	buf = bi_2_nbin ( &buf_len, DaaSignature->nt );
	if (!buf) goto err;
	ret = EVP_DigestUpdate(&mdctx,  buf , buf_len ); 	//  nt
	OPENSSL_free( buf );
	if (!ret)
		goto err;

	ret = EVP_DigestUpdate(&mdctx,  DAA_SIGN_MESSAGE , strlen(DAA_SIGN_MESSAGE) ); 	//  nt
	if (!ret)
		goto err;

	ret = EVP_DigestFinal_ex(&mdctx, final_hash, &final_hashlen );
	if (!ret)
		goto err;

	buf = bi_2_nbin(&buf_len, DaaSignature->ch);
	if (!buf) goto err;

	if ( (buf_len != final_hashlen ) || strncmp(buf, final_hash , buf_len) )
		goto err;

	COMP_free(res1);
	COMP_free(res2);
	COMP_free(res3);
	COMP_free(pta);
	COMP_free(ptb);
	COMP_free(ptc);
	EVP_MD_CTX_cleanup(&mdctx);

	bi_free_ptr( module );
	if (SB) EC_POINT_free(SB);
	if (CE) EC_POINT_free(CE);
	if (DT) EC_POINT_free(DT);

	return 1;

err:
	COMP_free(res1);
	COMP_free(res2);
	COMP_free(res3);
	COMP_free(pta);
	COMP_free(ptb);
	COMP_free(ptc);
	EVP_MD_CTX_cleanup(&mdctx);

	if (module) bi_free_ptr( module );
	if (SB) EC_POINT_free(SB);
	if (CE) EC_POINT_free(CE);
	if (DT) EC_POINT_free(DT);

	return 0;
}
