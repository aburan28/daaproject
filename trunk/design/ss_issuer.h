/*
 *
 *  Issuer.h
 *
 */
#ifndef SS_ISSUER_H
#define SS_ISSUER_H
#include "daa.h"

// Built issuer parameters
int TSS_DAA_JOIN_issuer_setup(
                              TSS_DAA_ISSUER_KEY *   IssuerKey,
                              TSS_DAA_ISSUER_PROOF * IssuerProof);


int TSS_DAA_JOIN_issuer_init(
							BYTE * 					  	  PlatformEndorsemenPubKey,
                            UINT32 					  	  PlatformEndorsemenPubkeyLength,
                            bi_ptr 						  EncryptedNonceOfIssuer,
                            TSS_DAA_ISSUER_PK * 		  IssuerPK,
                            TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession);


int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_JOIN_SESSION * TpmJoinSession,
                                  TSS_DAA_CREDENTIAL * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength);

#endif
