/*
 * ss_verifier.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_verifier.h"
#include "tate_pairing.h"

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
	*VerifierBasename = BASENAME;  /*TODO error?*/
	*VerifierBasenameLength = strlen(BASENAME);
	/*built the Nonceverifier*/
	NonceVerifier = NV;
	NV = NULL;
}

int TSS_DAA_JOIN_verifier_verify(TSS_DAA_SIGNNATURE *   DaaSignature,
							     TSS_DAA_ISSUER_PK  *   IssuerPK,
							     BYTE   * Msg,
							     UINT32   MsgLength,
                                 UINT32 * IsCorrect)
{
	/*TODO 1. Check rogue list fi*B'   */

	/* 2. Check A' and B' t(A'，Y) == t(B’，P2) */
	bi_ptr module = NULL , store =NULL , sb = NULL , ce = NULL , dt = NULL;
	COMPLEX *res1 = NULL , *res2 = NULL , *res3 = NULL , pta = NULL , ptb = NULL , ptc = NULL , nt = NULL;
	BN_CTX *ctx = NULL;

	ctx = BN_CTX_new();

	int precomp = 0 , ok;

	COMP_init(res1);
	COMP_init(res2);
	COMP_init(res3);
	COMP_init(pta);
	COMP_init(ptb);
	COMP_init(ptc);

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

	nt = res2;

	/*5. S*B' – c E' -> D†
	 * int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);*/
	ret = EC_POINT_mul(group, sb , NULL, &(DaaSignature->CapitalBPrime) , DaaSignature->s, ctx);

	ret = EC_POINT_mul(group, ce , NULL, &(DaaSignature->CapitalEPrime) , DaaSignature->ch, ctx);

	ret = EC_POINT_invert(group, ce, ctx);					// use  EC_POINT_invert to updown CF so can add it

	ret = EC_POINT_add(group, dt, sb, ce , ctx);					// SP1+CF = UP( U’)


	//TODO 6. H(ipk||bsn||A'||B'||C'||D'||E'||ρ†a||ρ†b||ρ†c|| T†||nv) -> c†    :// EVP_Digest_Final

	//TODO 7. Check H4(c†|nT||msg) == c   ://
}
