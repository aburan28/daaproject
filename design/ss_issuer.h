/*
 *
 *  Issuer.h
 *
 */
#ifndef SS_ISSUER_H
#define SS_ISSUER_H
#include "daa.h"

int TSS_DAA_JOIN_issuer_setup(UINT32 SecureLength,
                              TSS_DAA_ISSUER_KEY * IssuerKey,
                              TSS_DAA_ISSUER_PROOF IssuerProof);

//TODO check
int TSS_DAA_JOIN_issuer_int(BYTE * PlatformEndorsemenPubKey,
                            UINT32 PlatformEndorsemenPubkeyLength,
                            TSS_DAA_ISSUER_PK * IssuerPK,
                            TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                            BYTE **  EncryptedNonceOfIssuer,
                            UINT32 * EncryptedNonceOfIssuerLength);

int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_TPM_JOIN_SESSION * TpmJoinSession,
                                  TSS_DAA_CREDENTIAL * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength);

#endif
