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



//unsigned char outit[100];
// int nbsize;
//int length,len;
//bi_new(bi_test);     //使用前都要注册么－ －?
//	bi_new(bi_test2);

	//
	// //随机函数测试通过，不过怎么考虑符号呢？  试试前面有的测试>0的函数再使用 m=-m的函数..?
//	bi_urandom(bi_test2,50);


/*
	bi_ptr bi_test_lptr;// typedef struct bignum_st *bi_ptr; 区别在于ptr所指可变？
	bi_test_ptr = bi_new_ptr;  // 这里 bi_new_ptr 注释为产生一个新的bi_ptr但是我怎么传递呢？这样写系统提示从不支持。
	bi_set_as_si( bi_test,55);  //test_ptr
	bi_test_ptr = bi_new_ptr();



	nbsize=bi_nbin_size(bi_test);
	printf("nbin_size is %d\n",nbsize);

	length=bi_length(bi_test);
	printf("length is %d\n",length);

	bi_2_nbin1(&len,outit,bi_test);

	printf("\nnbin1 is %s\n",outit); */

//	printf("\n bi_test2 is %s\n",bi_2_hex_char(bi_test2));

