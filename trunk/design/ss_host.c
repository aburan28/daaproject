/*
 * ss_host.c
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#include "ss_host.h"

//int TSS_DAA_JOIN_host_init();

//int TSS_DAA_JOIN_host_credential_request();

int TSS_DAA_JOIN_host_credential_store(BYTE * CapitalE,
                                       UINT32 CapitalElength,
                                       BYTE * CredentialBytes,
                                       UINT32 CredentialBytesLength,
                                       TSS_DAA_HOST_JOIN_SESSION * HostJoinSession)
{
	//TODO 1. t(A，X) ->ρa   :// ?

	//TODO 2. t(B，X) -> ρb   :// ?

	//TODO 3. t(C，P2) -> ρc   :// ?

	//TODO 4. check t(A，Y) == t(B，P2) || t(A+E，X) ==ρc   :// ?



}

int TSS_DAA_SIGN_host_sign(BYTE * RPrime,
                           UINT32 RPrimeLength,
                           BYTE * DPrime,
                           UINT32 DPrimeLEgnth,
                           BYTE * NonceVerifier,
                           UINT32 NonceVerifierLength,
                           TSS_DAA_SIGNNATURE *   DaaSignature)
{
	//TODO 1. {0，1}t -> nv or get nv from verifier   :// bi_radom or socket

	//TODO 2. r'*A k-> A'   r'*C -> C'   :// ?

	//TODO 3. r'*B -> B'   :// ?

	//TODO 4. ρar' -> ρa'   ρbr' -> ρb'   ρcr' ->ρc'   :// bi_mod_exp

	//TODO 5. t(D'，X) -> т   r'*E -> E'   :// ?

	//TODO 6. H3 (ipk||bsn||A'||B'||C'||D'||E'||ρa'||ρb'||ρc'||т||nv) -> c'   :// EVP_Digest_Final

	//TODO 7. c' -> TPM   :// ?

}
