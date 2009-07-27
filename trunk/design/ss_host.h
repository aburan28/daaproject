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
                                       TSS_DAA_HOST_JOIN_SESSION * HostJoinSession);

int TSS_DAA_SIGN_host_sign(BYTE * RPrime,
                           UINT32 RPrimeLength,
                           BYTE * DPrime,
                           UINT32 DPrimeLEgnth,
                           BYTE * NonceVerifier,
                           UINT32 NonceVerifierLength,
                           TSS_DAA_SIGNNATURE *   DaaSignature);
#endif
