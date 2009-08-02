/*
 *
 *   ss_tpm.h
 *
 */
#ifndef SS_TPM_H
#define SS_TPM_H
#include "daa.h"

#ifndef DAA_PARAM_MESSAGE_DIGEST_ALGORITHM
#define DAA_PARAM_MESSAGE_DIGEST_ALGORITHM "SHA1"
#endif

#ifndef EVP_DigestFinal_OUT_SIZE
#define EVP_DigestFinal_OUT_SIZE   		   20
#endif

int TSS_DAA_JOIN_credential_request(BYTE * EncryptedNonceOfIssuer,
                                    UINT32 EncryptedNonceOfIssuerLength,
                                    TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                    TSS_DAA_ISSUER_PK        * IssuerPK,
                                    TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                                    ); //TODO change to BYTE *

int TSS_DAA_JOIN_tpm_credential(BYTE * EncryptedCred,
                                UINT32 EncryptedCredLength,
                                BYTE **  Credential,
                                UINT32 * CredentialLength,
                                BYTE **  CapitalE,
                                UINT32 * CapitalELength);

int TSS_DAA_SIGN_tpm_init(TSS_DAA_CREDENTIAL2 * Credential,
                          BYTE * VerifierBaseName,
                          UINT32 VerifierBaseNameLength,
                          BYTE **  RPrime,
                          UINT32 * RPrimeLength,
                          BYTE **  DPrime,
                          UINT32 * DPrimeLength);

int TSS_DAA_SIGN_tpm_sing(BYTE *  ChPrime,
                          UINT32  ChPrimelength,
                          BYTE **  Noncetpm,
                          UINT32 * Noncetpmlength,
                          BYTE **  Ch,
                          UINT32 * Chlength,
                          BYTE **  S,
						  UINT32 * SLength);
#endif
