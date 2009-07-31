/*
 *
 *  Issuer.h
 *
 */
#ifndef SS_ISSUER_H
#define SS_ISSUER_H
#include "daa.h"

#ifndef RSA_NO_PADDING
#define RSA_NO_PADDING		3
#endif

#ifndef EVP_DigestFinal_OUT_SIZE
#define EVP_DigestFinal_OUT_SIZE   		   20
#endif

#ifndef DAA_PARAM_MESSAGE_DIGEST_ALGORITHM
#define DAA_PARAM_MESSAGE_DIGEST_ALGORITHM "SHA1"
#endif

#ifndef RSA_MODLE_LENGTH
#define RSA_MODLE_LENGTH 2048
#endif

#ifndef Kk
#define Kk "islab"
#endif

// Built issuer parameters
int TSS_DAA_JOIN_issuer_setup(
                              TSS_DAA_ISSUER_KEY *   IssuerKey,
                              TSS_DAA_ISSUER_PROOF * IssuerProof);


int TSS_DAA_JOIN_issuer_init(
							BYTE * 					  	  PlatformEndorsemenPubKey,
                            UINT32 					  	  PlatformEndorsemenPubkeyLength,
                  //          TSS_DAA_ISSUER_PK * 		  IssuerPK,    Not use
                            TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                            BYTE   ** 	   				  EncryptedNonceOfIssuer,
                            UINT32 *					  EncryptedNonceOfIssuerLength);


int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                                  TSS_DAA_CREDENTIAL          * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength);
#endif
