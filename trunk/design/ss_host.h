/*
 *   ss_host.h
 *
 * */
#ifndef SS_HOST_H
#define SS_HOST_H
#include "daa.h"

//int TSS_DAA_JOIN_host_init();

//int TSS_DAA_JOIN_host_credential_request();

int TSS_DAA_JOIN_host_credential_store(BYTE * CapitalE,
                                       UINT32 CapitalElength,
                                       BYTE * CredentialBytes,
                                       UINT32 CredentialBytesLength,
                                       TSS_DAA_ISSUER_PK  * IssuerPK,
                                       TSS_DAA_CREDENTIAL2 *DaaCredential,
                                       TSS_DAA_HOST_JOIN_SESSION * HostJoinSession);

int TSS_DAA_SIGN_host_sign(BYTE * RPrime,                               // in
                           UINT32 RPrimeLength,                         // in
                           BYTE * DPrime,                               // in
                           UINT32 DPrimeLength,                         // in
                           BYTE * NonceVerifier,                        // in
                           UINT32 NonceVerifierLength,                  // in
                           TSS_DAA_CREDENTIAL2 *DaaCredential,          // in
                           TSS_DAA_ISSUER_PK  * IssuerPK,               // in
                           TSS_DAA_HOST_JOIN_SESSION *HostJoinSession,  // in
                           TSS_DAA_SIGNNATURE *   DaaSignature          // out
                           );
#endif
