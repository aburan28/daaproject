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
                                    TSS_DAA_ISSUER_PK        * IssuerPK
                                    //     TSS_DAA_ISSUER_JOIN_SESSION * TpmJoinSession
                                    ) //TODO change to BYTE *
{
	//TODO 1. 1||X||Y||nI -> str   :// EVP_Digest_Update

	//TODO 2. H1(0||DaaSeed||Kk) -> f   :// EVP_Digest_Final

	//TODO 2. Zq -> u   ://bi_random，bi_mod   // f,u私有

	//TODO 3. u*P1 -> U   f*P1 -> F   :// ?

	//TODO 4. H1(str||F||U) -> c   :// EVP_Digst_Final

	//TODO 5. u+c*f (mod q) -> s   :// bi_mul，bi_add,

	//TODO 6. (F，c，s) -> comm.   :// ?

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
