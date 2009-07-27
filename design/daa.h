/*
 *  daa.h
 *
 */

// Issuer 公钥
#ifndef DAA_H
#define DAA_H

#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT32
#define UINT32 unsigned long
#endif

#include <openssl/ec.h>
//#include <openssl/ec_lcl.h>
#include "ec_lcl.h"
#include "complex.h"

typedef EC_POINT ECC_POINT;

//TODO  defien length
#define NONCE_LENGTH 20
// define length end

typedef struct tdECCParmeter
{

    ECC_POINT * CapitalP1;          //G1
    ECC_POINT * CapitalP2;          //G2

  //  follows maybe in EC_GROUP
  //  BYTE * r;                       // n
  //  UINT32 rLength;
  //  BYTE * module;                  // q
  //  UINT32 moduleLength;
  //  BYTE * Seed;                    // h?
  //  UINT32 SeedLength;
  //  BYTE * c;                        //  Like a or b in Ecc
  //  UINT32 cLength;
  //  BYTE * b;                        //  ups
  //  UINT32 bLength;

}ECC_PARAMETER;

typedef struct tdIssuerPk
{
    ECC_PARAMETER  Eccparmeter;

    ECC_POINT  CapitalX;

    ECC_POINT  CapitalY;

}TSS_DAA_ISSUER_PK;

// issuer 私钥

typedef struct tdIssuerSk
{
    bi_ptr x;

    bi_ptr y;

}TSS_DAA_ISSUER_SK;

//issuer密钥

typedef struct tdIssuerKey
{
    TSS_DAA_ISSUER_PK IssuerPK;

    TSS_DAA_ISSUER_SK IssuerSK;

}TSS_DAA_ISSUER_KEY;

// issuer proof 验证 issuer 公钥的正确性

typedef struct tdIssuerProof
{
	ECC_POINT CapitalXPrime;

    ECC_POINT CapitalYPrime;

}TSS_DAA_ISSUER_PROOF;

// issuer session 存储会话临时值


typedef struct tdIssuerJionSession
{
    bi_ptr  IssuerNone;

    ECC_POINT  CapitalF;

    bi_ptr  ch;

    bi_ptr  s;

}TSS_DAA_ISSUER_JOIN_SESSION;

//issuer credential 证书内容

typedef struct tdCredential
{
	ECC_POINT CapitalA;

	ECC_POINT CapitalB;

	ECC_POINT CapitalC;

}TSS_DAA_CREDENTIAL;

// TPM

typedef struct tdTPMSession
{
    bi_ptr f;

}TSS_DAA_TPM_JOIN_SESSION;

// HOST

typedef struct  tdHostJoinSession
{
	COMPLEX *Roa;

	COMPLEX *Rob;

	COMPLEX *Roc;

}TSS_DAA_HOST_JOIN_SESSION;

// signature

typedef struct tdSignature
{
	ECC_POINT CapitalAprime;

	ECC_POINT CapitalBPrime;

	ECC_POINT CapitalCPrime;

	ECC_POINT CapitalEPrime;

	bi_ptr ch;

	bi_ptr s;

	bi_ptr nv;

	bi_ptr nt;

}TSS_DAA_SIGNNATURE;
#endif
