/*
 *
 *   ss_tpm.h
 *
 */
#ifndef SS_TPM_H
#define SS_TPM_H
#include "daa.h"

int TSS_DAA_JOIN_credential_request(BYTE * EncryptedNonceOfIssuer,
                                    UINT32 EncryptedNonceOfIssuerLength,
                           TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession);

int TSS_DAA_JOIN_tpm_credential(BYTE * EncryptedCred,
                                 UINT32 EncryptedCredLength,
                                 BYTE * EncryptedBytes,
                                 UINT32 EncryptedBytesLength);

int TSS_DAA_SIGN_tpm_init(TSS_DAA_CREDENTIAL * Credential,
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
                          UINT32 * Chlength);
#endif
