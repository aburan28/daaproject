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
                                    TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                    TSS_DAA_ISSUER_PK        * IssuerPK,
                                    TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession
                                    );
//TODO change to BYTE *

int TSS_DAA_JOIN_tpm_credential(BYTE * EncryptedCred,
                                UINT32 EncryptedCredLength,
                                TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                BYTE **  Credential,
                                UINT32 * CredentialLength,
                                BYTE **  CapitalE,
                                UINT32 * CapitalELength);

int TSS_DAA_SIGN_tpm_init(TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                          BYTE * VerifierBaseName,
                          UINT32 VerifierBaseNameLength,
                          BYTE **  RPrime,
                          UINT32 * RPrimeLength,
                          BYTE **  DPrime,
                          UINT32 * DPrimeLength);

int TSS_DAA_SIGN_tpm_sign(
		                  TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
						  BYTE *  Msg,
						  BYTE *  MsgLength,
		                  BYTE *  ChPrime,
                          UINT32  ChPrimeLength,
                          BYTE **  Noncetpm,
                          UINT32 * NoncetpmLength,
                          BYTE **  Ch,
                          UINT32 * ChLength,
                          BYTE **  S,
						  UINT32 * SLength);
#endif
