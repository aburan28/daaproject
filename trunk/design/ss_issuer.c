/*
 * ss_issuer.c
 *
 *  Created on: 2009-7-28
 *      Author: ctqmumu
 *
 *      About Err
 *      	EVP_DigestInit_ex(), EVP_DigestUpdate() and EVP_DigestFinal_ex() return 1 for success and 0 for failure.
 *      	RSA_public_encrypt() ,On error, -1 is returned;
 *      	BN_bn2bin() returns the length of the big-endian number placed at to. BN_bin2bn() returns the BIGNUM , NULL on error.
 *      	EVP_get_digestbyname() return either an EVP_MD structure or NULL if an error occurs.
 *
 */


#include "daa.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>

int TSS_DAA_JOIN_issuer_setup(
                              TSS_DAA_ISSUER_KEY *   IssuerKey,
                              TSS_DAA_ISSUER_PROOF * IssuerProof);
//TODO setup function

int TSS_DAA_JOIN_issuer_init(
							BYTE * 					  	  PlatformEndorsemenPubKey,
                            UINT32 					  	  PlatformEndorsemenPubkeyLength,
                            TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                            BYTE   ** 	   				  EncryptedNonceOfIssuer,
                            UINT32 *					  EncryptedNonceOfIssuerLength)
{
	unsigned char exp[] = { 0x01, 0x00, 0x01 };
	int rv, e_size = 3;
	RSA *rsa = NULL;
	bi_ptr ni = NULL;
	BYTE  *hex_ni = NULL , *eni_st = NULL;
	UINT32 hex_ni_len;
												//		1.	{0,1}t -> nI  // bi_random
	ni = bi_new_ptr();
	bi_urandom( ni, NONCE_LENGTH );

	IssuerJoinSession.IssuerNone = ni;

	rsa = RSA_new();

	eni_st = malloc(( RSA_MODLE_LENGTH / 8 + 1) * sizeof(BYTE));					   //built the final commreq {RSA_MODLE_LENGTH=2048}

	hex_ni = bi_2_hex_char( ni );
	hex_ni_len = strlen( hex_ni );             //   	change ni to hex_ni

	rsa->e = BN_bin2bn( exp , e_size , rsa->e);
	rsa->n = BN_bin2bn( PlatformEndorsemenPubKey , PlatformEndorsemenPubkeyLength , rsa->n);    // setup rsa
    if ( ( rsa->e == NULL ) || ( rsa->n == NULL ) )
    	goto err;
												//					2.	nI -> commreq
	rv = RSA_public_encrypt( hex_ni_len, hex_ni , eni_st , rsa , RSA_NO_PADDING);
	if (rv == -1)
		goto err;

	*EncryptedNonceOfIssuer = eni_st;          // send out
	*EncryptedNonceOfIssuerLength = rv;

	ni = NULL;      // here we make NULL so not free it

	if (eni_st) free(eni_st);
	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (hex_ni) OPENSSL_free(hex_ni);

	return 1;

err:
	if (eni_st) free(eni_st);
	if (ni) bi_free(ni);
	if (rsa) RSA_free(rsa);
	if (hex_ni) OPENSSL_free(hex_ni);

	return 0;
}

int TSS_DAA_JOIN_issuer_credentia(TSS_DAA_ISSUER_JOIN_SESSION * IssuerJoinSession,
                                  TSS_DAA_CREDENTIAL * Credential,
                                  BYTE **  EncyptedCred,
                                  UINT32 * EncyptedCredLength)
{

}
