#include "bi.h"
#include "bi_openssl.h"
#include "daa.h"
#include "ss_host.h"
#include "ss_issuer.h"
#include "ss_tpm.h"
#include "ss_verifier.h"
#include "ec.h"
#include "transform.h"
#include <stdio.h>

#if 0
int main()
{


    bi_ptr bi_test1;
    bi_ptr bi_test2;
    bi_ptr bi_test3;
    EC_GROUP *group;
    ECC_POINT *P;
    BYTE *X;
    BYTE *Y;
    UINT32 XLength,YLength;


    bi_init(malloc);

	bi_test1 = bi_new_ptr();
    bi_test2 = bi_new_ptr();
    bi_test3 = bi_new_ptr();

    bi_urandom(bi_test1,20);
    bi_urandom(bi_test2,20);
    bi_urandom(bi_test3,20);

/*   取负
 *   printf("\n bil_test  is %s\n",bi_2_dec_char(bi_test1));
 *   bi_test1 = bi_negate(bi_test1);
 */
  //  SESSION


    group = EC_GROUP_new(EC_GFp_mont_method());

    P = EC_POINT_new(group);


    P->X = (*bi_test1);
    P->Y = (*bi_test2);
    if (ecp_2_hex(P,&X,&Y,&XLength,&YLength)==0) printf("ERROR! in ecp_2_hex \n");

    printf("\n X is %ld that's %s", XLength, X);
    printf("\n Y is %ld that's %s\n", YLength, Y);

    if (hex_2_ecp(X,Y,&P,group) == 0) printf("\n Error in Hex to ecp\n");

    printf("\nP->X is %s\n",bi_2_dec_char(&(P->X)));
    printf("\nP->Y is %s\n",bi_2_dec_char(&(P->Y)));

	printf("\n bi_test1  is %s\n",bi_2_dec_char(bi_test1));
	printf("\n bi_test2  is %s\n",bi_2_dec_char(bi_test2));


  //  bi_mod_si(bi_test3,bi_test2,bi_test3);

    printf("\n bi_test3  is %s\n",bi_2_dec_char(bi_test3));

	return 0;

}




//	printf("\n bi_test2 is %s\n",bi_2_hex_char(bi_test2));
#endif
