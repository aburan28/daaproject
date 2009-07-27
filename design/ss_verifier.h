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

int TSS_DAA_JOIN_verifier_verify(TSS_DAA_SIGNNATURE *   DaaSignature,
							     TSS_DAA_ISSUER_PK  *   IssuerPK,
							     BYTE   * Msg,
							     UINT32   MsgLength,
                                 UINT32 * IsCorrect);

#endif
