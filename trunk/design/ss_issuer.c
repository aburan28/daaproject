/*
 * ss_issuer.c
 *
 *  Created on: 2009-7-28
 *      Author: ctqmumu
 */

#include "daa.h"
#include <stdio.h>
#include <stdlib.h>

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
	bi_urandom(nI, NONCE_LENGTH);

//	TODO nI -> commreq   ://RSA_Encypt

/*  TODO
	int	RSA_public_encrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa,int padding);
	int	RSA_private_encrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa,int padding);
	int	RSA_public_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa,int padding);
	int	RSA_private_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa,int padding);
	void	RSA_free (RSA *r);
*/
//	Will do in the Issuer_credentia 1||X||Y||nI -> str   :// EVP_Digest_Update //公钥X.Y
}

int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_JOIN_SESSION * TpmJoinSession,
		                          TSS_DAA_CREDENTIAL2 * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength)
{
	// 1: TODO 1||X||Y||nI -> str   :// EVP_Digest_Update
	/*EVP_MD *digest = NULL;
      digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM);
      EVP_MD_CTX mdctx;
      rv = EVP_DigestInit(&mdctx, DAA_PARAM_get_message_digest());
      rv = EVP_DigestUpdate(&mdctx,  encoded_pk, encoded_pkLength);
      rv = EVP_DigestFinal(&mdctx, *result, NULL);
	*/
	// 2: TODO H1(0||DaaSeed||Kk) -> f   :// EVP_Digest_Final

	//Zq -> u   ://bi_random，bi_mod   // f,u私有
		bi_ptr u;
		u = bi_new_ptr();
		bi_urandom(u,NONCE_LENGTH);

	// 3: TODO u*P1 -> U   f*P1 -> F   :// ?
	// 4: TODO H1(str||F||U) -> c   :// EVP_Digst_Final

	// 5: u+c*f (mod q) -> s   :// bi_mul，bi_add,
		bi_ptr s   = bi_new_ptr();
		bi_ptr temp = bi_new_ptr();

		bi_mul(temp, c, f);
		bi_add(s, u, temp);
		bi_mod(s, s, q);
	// 6: TODO (F，c，s) -> comm.   :// ?
}
