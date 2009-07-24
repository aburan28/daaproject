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

typedef EC_POINT ECC_POINT;

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
    ECC_PARAMETER * Eccparmeter;
    BYTE * CapitalX;
    UINT32 CapitalXLength;
    BYTE * CapitalY;
    UINT32 CapitalYLength;
}TSS_DAA_ISSUER_PK;

// issuer 私钥

typedef struct tdIssuerSk
{
    BYTE * x;
    UINT32 xLength;
    BYTE * y;
    UINT32 yLength;
}TSS_DAA_ISSUER_SK;

//issuer密钥

typedef struct tdIssuerKey
{
    TSS_DAA_ISSUER_PK * IssuerPK;
    TSS_DAA_ISSUER_SK * IssuerSK;
}TSS_DAA_ISSUER_KEY;

// issuer proof 验证 issuer 公钥的正确性

typedef struct tdIssuerProof
{
    BYTE * CapitalXPrime;
    UINT32 CapitalXPrimeLength;
    BYTE * CapitalYPrime;
    UINT32 CapitalYPrimeLength;
}TSS_DAA_ISSUER_PROOF;

// issuer session 存储会话临时值

//TODO bi_ptr
typedef struct tdIssuerJionSession
{
    BYTE * IssuerNone;
    UINT32 IssuerNOneLength;
    BYTE * CapitalF;
    UINT32 CapitalFLength;
}TSS_DAA_ISSUER_JOIN_SESSION;

//issuer credential 证书内容

typedef struct tdCredential
{
    BYTE * CapitalA;
    UINT32 CapitalALength;
    BYTE * CapitalB;
    UINT32 CapitalBLength;
    BYTE * CapitalC;
    UINT32 CapitalCLength;
}TSS_DAA_CREDENTIAL;

// TPM

typedef struct tdTPMSession
{
    bi_ptr f;
    //BYTE * CapitalF;
    //UINT32 CapitalFLength;
    //BYTE * ch;
    //UINT32 chLength;
    //BYTE * s;
    //UINT32 slength;
}TSS_DAA_TPM_JOIN_SESSION;

// HOST

typedef struct tdHostJoinSession
{
    BYTE * Roa;
    UINT32 RoaLength;
    BYTE * Rob;
    UINT32 RobLength;
    BYTE * Roc;
    UINT32 RocLength;
}TSS_DAA_HOST_JOIN_SESSION;

// signature

typedef struct tdSignature
{
    BYTE * CapitalAprime;
    UINT32 CapitalAprimeLength;
    BYTE * CapitalBPrime;
    UINT32 CapitalBPrimeLength;
    BYTE * CapitalCPrime;
    UINT32 CapitalCPrimeLength;
    BYTE * CapitalEPrime;
    UINT32 CapitalEPrimeLength;
    BYTE * ch;
    UINT32 chLength;
    BYTE * s;
    UINT32 sLength;
    BYTE * nv;
    UINT32 nvLrngth;
    BYTE * nt;
    UINT32 ntLength;
}TSS_DAA_SIGNNATURE;
#endif
