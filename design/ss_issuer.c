/*
 * ss_issuer.c
 *
 *  Created on: 2009-7-28
 *      Author: ctqmumu
 */

#include "daa.h"
#include <stdio.h>
#include <stdlib.h>

int TSS_DAA_JOIN_issuer_setup(
                              TSS_DAA_ISSUER_KEY *   IssuerKey,
                              TSS_DAA_ISSUER_PROOF * IssuerProof);
//TODO setup function

int TSS_DAA_JOIN_issuer_init(
							BYTE * 					  	  PlatformEndorsemenPubKey,
                            UINT32 					  	  PlatformEndorsemenPubkeyLength,
                            TSS_DAA_ISSUER_PK * 		  IssuerPK,
                            TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                            BYTE   ** 	   				  EncryptedNonceOfIssuer,
                            UINT32 *					  EncryptedNonceOfIssuerLength)
{
//	{0,1}t -> nI  // bi_random
	bi_ptr nI;

	nI = bi_new_ptr();

	bi_urandom( nI, NONCE_LENGTH );

// 	nI -> commreq   ://RSA_Encypt
//
//	int	RSA_public_encrypt(int flen,  const unsigned char *from,unsigned char *to, RSA *rsa,int padding);
//	int	RSA_private_encrypt(int flen, const unsigned char *from,unsigned char *to, RSA *rsa,int padding);
//	void	RSA_free (RSA *r);
//    int Trspi_RSA_Public_Encrypt(    unsigned char *in, unsigned int inlen,
//			                         unsigned char *out, unsigned int *outlen,
//									 unsigned char *pubkey, unsigned int pubsize,
//									 unsigned int e, int padding)
//	use here

	BYTE *hex_nI = bi_2_hex_char(nI);

	UINT32 hex_nI_len = strlen(hex_nI);

	//TODO we need define the EncryptedNonceOfIssuer  --- how about the length?

	UINT32 EncryptedNonceOfIssuerLength_st;

	EncryptedNonceOfIssuerLength = &EncryptedNonceOfIssuerLength_st;

	Trspi_RSA_Public_Encrypt( hex_nI, hex_nI_len ,
							  EncryptedNonceOfIssuer, EncryptedNonceOfIssuerLength ,
							  IssuerPK, //Is here IssuerPK?
							  ); //TODO unsigned int e, int padding


//	Will do  1||X||Y||nI -> str  in the Issuer_credentia :// EVP_Digest_Update //公钥X.Y
}

int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_JOIN_SESSION * TpmJoinSession,
		                          TSS_DAA_CREDENTIAL2 * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength)
{
	// 1: 1||X||Y||nI -> str   :// EVP_Digest_Update //TODO need X Y  from TSS_DAA_ISSUER_PK  and  a Point we use changhe to char*?
	/*EVP_MD *digest = NULL;
      digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM);
      EVP_MD_CTX mdctx;
      rv = EVP_DigestInit(&mdctx, DAA_PARAM_get_message_digest());
      rv = EVP_DigestUpdate(&mdctx,  encoded_pk, encoded_pkLength);
      rv = EVP_DigestFinal(&mdctx, *result, NULL);
	*/
	 EVP_MD *digest = NULL;

	 digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM ); // TODO  no define the DAA_PARAM_MESSAGE_DIGEST_ALGORITHM

	 EVP_MD_CTX mdctx;

	 int rv;

	 rv = EVP_DigestInit( &mdctx , DAA_PARAM_get_message_digest() ); //TODO no define the DAA_PARAM_get_message_digest

	 rv = EVP_DigestUpdate(&mdctx,  encoded_pk, encoded_pkLength ); // ..



	 // 2: TODO H1(0||DaaSeed||Kk) -> f   :// EVP_Digest_Final

	 rv = EVP_DigestFinal(&mdctx, *str, NULL); //TODO EVP_Digest_Final 's usage

	//Zq -> u   ://bi_random，bi_mod   // f,u私有

		bi_ptr u;

		u = bi_new_ptr();

		bi_urandom( u, NONCE_LENGTH );

	// 3: TODO u*P1 -> U   f*P1 -> F   :// need TSS_DAA_ISSUER_PK
	// 4: TODO H1(str||F||U) -> c   :// EVP_Digst_Final
	// 5: u+c*f (mod q) -> s   :// bi_mul，bi_add,
//		bi_ptr s   = bi_new_ptr();
//		bi_ptr temp = bi_new_ptr();
//
//		bi_mul(temp, c, f);
//		bi_add(s, u, temp);
//		bi_mod(s, s, q);

	// 6: TODO (F，c，s) -> comm.   :// ?
}
