/*
 * ss_verifier.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_verifier.h"

int TSS_DAA_JOIN_verifier_init(BYTE **  VerifierBasename,
                               UINT32 * VerifierBasenameLength,
                               BYTE **  NonceVerifier,
                               UINT32 * NonceVerifierLength)
{
   // bi_urandom();

}

int TSS_DAA_JOIN_verifier_verify(TSS_DAA_SIGNNATURE *   DaaSignature,
							     TSS_DAA_ISSUER_PK  *   IssuerPK,
							     BYTE   * Msg,
							     UINT32   MsgLength,
                                 UINT32 * IsCorrect)
{
	//TODO 1. Check rogue list fi*B'   ://

	//TODO 2. Check A' and B' t(A'，Y) == t(B’，P2)   ://

	//TODO 3. t(A'，X) -> ρ†a   t(B’，X) -> ρ†b   t(C'，P2) -> ρ†c   :// ?

	//TODO 4. (ρ†b)s *(ρ†c/ρ†a)-c * -> T†   :// ?

	//TODO 5. S*B' – c E' -> D†   :// ?

	//TODO 6. H(ipk||bsn||A'||B'||C'||D'||E'||ρ†a||ρ†b||ρ†c|| T†||nv) -> c†    :// EVP_Digest_Final

	//TODO 7. Check H4(c†|nT||msg) == c   ://
}
