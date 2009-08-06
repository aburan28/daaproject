/*
 *
 *    ss_verifier.h
 *
 */
#ifndef SS_VERIFIER_H
#define SS_VERIFIER_H
#include "daa.h"

#define BASENAME "ISLAB"

int TSS_DAA_JOIN_verifier_init(BYTE **  VerifierBasename,
                               UINT32 * VerifierBasenameLength,
                               bi_ptr   NonceVerifier);

int TSS_DAA_JOIN_verifier_verify(TSS_DAA_SIGNNATURE *   DaaSignature,
							     TSS_DAA_ISSUER_PK  *   IssuerPK,
							     BYTE *  VerifierBasename,
							     UINT32  VerifierBasenameLength,
							     BYTE   * Msg,
							     UINT32   MsgLength,
                                 UINT32 * IsCorrect );

#endif
