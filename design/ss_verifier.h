/*
 *
 *    ss_verifier.h
 *
 */
#ifndef SS_VERIFIER_H
#define SS_VERIFIER_H
#include "daa.h"

int TSS_DAA_JOIN_verifier_init(BYTE **  VerifierBasename,
                               UINT32 * VerifierBasenameLength,
                               BYTE **  NonceVerifier,
                               UINT32 * NonceVerifierLength);

int TSS_DAA_JOIN_verifier_verify(BYTE *   DaaSignature,
                                 UINT32   DaaSignatureLength,
                                 UINT32 * IsCorrect);

#endif
