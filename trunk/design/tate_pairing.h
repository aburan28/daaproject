/*
 * tate_pairing.h
 *
 *  Created on: 2009-7-28
 *      Author: xiaoyi
 */

#ifndef TATE_PAIRING_H_
#define TATE_PAIRING_H_

#include "complex.h"
#include "daa.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* The code coordinate from lib miracl: miracl/source/ibe/ibe_exp.cpp */
#define PBITS 512
#define QBITS 160

// Using SHA-1 as basic hash algorithm

#define HASH_LEN 20
EC_GROUP *ec_group;
BIGNUM *module;
//
// Tate Pairing Code
//
// Extract ECn point in internal ZZn format
//

void extract(EC_POINT *A, BIGNUM *x, BIGNUM *y)
{
    //x=(A.get_point())->X;
    //y=(A.get_point())->Y;
	BN_copy(x, &A->X);
	BN_copy(y, &A->Y);
}

//
// Add A=A+B  (or A=A+A)
// Bump up num and denom
//
// On first pass through precomp=FALSE, and so all points
// and slopes are "recorded" in store[]
//
// On subsequent passes these values ( total < 500 ) are "played back"
//

void g(EC_POINT *A, EC_POINT *B,  BIGNUM *Qx, COMPLEX *Qy, COMPLEX *num, int precomp, BIGNUM *store, int *ptr)
{
    int type;
    /*ZZn  lam,x,y,m,nx;
    ZZn2 u;
    big pointer;
    if (num.iszero()) return;
    */
    BIGNUM lam, x, y, m, nx;
    COMPLEX *u, *tmp;

    u = COMP_new();
    tmp = COMP_new();
    BN_set_word(&nx, 0l);
    /*if (!precomp)
    { // Store line start point and slope.
      // Evaluate line from A, and then evaluate vertical through destination
        extract(A,x,y);
        type=A.add(B,&pointer);
 //       if (pointer==NULL) return;
        lam=pointer;

        store[ptr++]=x; store[ptr++]=y; store[ptr++]=lam;
        if (!type) return;
// line
        m=Qx; u=Qy;
        m-=x; m*=lam;            // 1 ZZn muls
        u-=y; u-=m;
    }*/
    if (!precomp)
    {
    	extract( A, &x, &y);
// TODO ADD POINT and get the slope of line

    	/*store values in store[]  */
    	BN_copy( &store[*(ptr++)], &x );
    	BN_copy( &store[*(ptr++)], &y );
    	BN_copy( &store[*(ptr++)], &lam );

    	if ( !type )
    		return ;

    	BN_mod_sub( &m, Qx, &x, &ec_group->field, Context);
    	BN_mod_mul( &m, &m, &lam, &ec_group->field, Context);

    	//TODO define function sub_big
    	//Sub_Big( &u, &Qy, &y, ec_group->field, Context);
        //SubBig( &u, &u, &m, ec_group->field, Context);
    	COMP_set(tmp, &nx, &y, module );
    	COMP_sub(u, Qy, tmp, module );
    	COMP_set(tmp, &nx, &m, module );
    	COMP_mul(u, u, tmp, module);

    }
    else
    {
    	BN_copy(&x, &store[*(ptr++)]);
    	BN_copy(&y, &store[*(ptr++)]);
    	BN_copy(&lam, &store[*(ptr++)]);

    	BN_mod_sub( &m, Qx, &x, &ec_group->field, Context);
    	BN_mod_mul( &m, &m, &lam, &ec_group->field, Context);

    	//TODO define function sub_big
    	//Sub_Big( &u, &Qy, &y, ec_group->field, Context);
        //SubBig( &u, &u, &m, ec_group->field, Context);

    }
    COMP_mul( num, num, &u, &ec_group->field);
    /*else
    { // extract precalculated values from the store.... - nx is a peek ahead
        x=store[ptr++]; y=store[ptr++]; lam=store[ptr++]; nx=store[ptr];
        if (nx.iszero()) return;

        m=Qx; u=Qy;
        m-=x; m*=lam;              // 1 ZZn muls
        u-=y; u-=m;
    }

    num*=u;                        // 3 ZZn muls*/

}

//
// Tate Pairing
//
//
// P is of order q and Q(x,y) has an order a multiple of q..
// Note that P is a point on the curve over Fp, Q(x,y) a point on the
// quadratic extension field Fp^2
//
// When P is fixed, precomputation helps. Note that each time we are
// calculating q.P where q and P are fixed, and the result O is known. So
// store all points and slopes for re-use the next time. Set precomp=FALSE first
// time, and then precomp=TRUE in subsequent calls. Initialise store to hold
// precomputed ZZn's (about 500 of them).
//

int  fast_tate_pairing(EC_POINT *P,BIGNUM *Qx, COMPLEX *Qy, BIGNUM  *q, int precomp,BIGNUM *store, COMPLEX *res)
{
    /*int i,ptr=0;
    Big p;
    ECn A;

    if (!precomp) get_mip()->coord=MR_AFFINE; // precompute using AFFINE
                                              // coordinates
    res=1;

// q.P = 2^17*(2^142.P +P) + P

    A=P;
    for (i=0;i<142;i++)
    {
        res*=res;
        g(A,A,Qx,Qy,res,precomp,store,ptr);
    }                                   // 6 ZZn muls after first
    g(A,P,Qx,Qy,res,precomp,store,ptr);

    for (i=0;i<17;i++)
    {
        res*=res;
        g(A,A,Qx,Qy,res,precomp,store,ptr);
    }
    g(A,P,Qx,Qy,res,precomp,store,ptr);

    if (res.iszero()) return FALSE;

    if (!precomp)
    {
        if (!A.iszero()) return FALSE;
        get_mip()->coord=MR_PROJECTIVE; // reset
    }

    p=get_modulus();         // get p
    res= pow(res,(p+1)/q);   // raise to power of (p^2-1)/q
    res=conj(res)/res;
    if (res.isunity()) return FALSE;

    return TRUE;
    */
	int i, ptr = 0, ret;
	BIGNUM p;
	EC_POINT A;
	COMPLEX con_res;

	// TODO  precompute using AFFINE

	ret = BN_set_word( &res->x, 1);
	ret = BN_set_word( &res->y, 0);

	ret = EC_POINT_copy(&A, P);
	for ( i = 0; i< 42; i++ )
	{
		COMP_mul( res, res, res, q);
		g(&A, &A, Qx, Qy, res, precomp, store, &ptr);
	}
	g(&A, &A, Qx, Qy, res, precomp, store, &ptr);

	for ( i = 0; i < 17; i++ )
	{
		COMP_mul( res, res, res, q);
		g(&A, &A, Qx, Qy, res, precomp, store, &ptr);
	}
	g(&A, &A, Qx, Qy, res, precomp, store, &ptr);

	if (COMP_is_zero( res ))
		return 0;
	if ( !precomp)
	{
		if (!EC_POINT_is_at_infinity(ec_group, &A))
			return 0;
	}

	ret = BN_copy( &p, &ec_group->field );

	BN_add_word( &p, 1);
	BN_div(&p, NULL, &p, q, Context);
	COMP_pow( res, res, &p, &ec_group->field);

	COMP_init( &con_res );
	COMP_conj( &con_res, res, &ec_group->field);
	COMP_div( res, &con_res, res, &ec_group->field);
	if(COMP_is_zero ( res ))
		return 0;
	return 1;

}

//
// ecap(.) function
//

int  Tate(EC_POINT *P, EC_POINT *Q, BIGNUM *order, int precomp, BIGNUM *store, COMPLEX *res)
{
    BIGNUM  Qx;
    COMPLEX Qy;
    BIGNUM xx,yy;
    int ret, rv;

    ec_group = group;

	/* Get group module p */
	module = bi_new_ptr();
	if ( module == NULL )
		goto err;
	rv = ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context ); //return 1 if success
	if ( !rv )
		goto err;


    ret = EC_POINT_get_affine_coordinates_GFp(ec_group, Q, &xx, &yy, Context);
    /*
    Qx=-xx;
    Qy.set((Big)0,yy);
    */
	if ( BN_is_negative(&xx) )
		BN_set_negative( &xx, 0 );
	else
		BN_set_negative( &xx, 1 );

	if (!BN_copy(&Qx, &xx))
		return 0;

	BN_set_word(&xx, 0);
	// TODO set funtion
	//Set(&Qy, &xx, &yy);
	BN_copy(&Qy.x, &xx);
	BN_copy(&Qy.y, &yy);

    return fast_tate_pairing(P, &Qx, &Qy, order, precomp, store, res);

    err:
    return 0;

}

//
// Hash functions
//

//Big H1(char *string)
//{ // Hash a zero-terminated string to a number < modulus
//    Big h,p;
//    char s[HASH_LEN];
//    int i,j;
//    sha sh;
//
//    shs_init(&sh);
//
//    for (i=0;;i++)
//    {
//        if (string[i]==0) break;
//        shs_process(&sh,string[i]);
//    }
//    shs_hash(&sh,s);
//    p=get_modulus();
//    h=1; j=0; i=1;
//    forever
//    {
//        h*=256;
//        if (j==HASH_LEN)  {h+=i++; j=0;}
//        else         h+=s[j++];
//        if (h>=p) break;
//    }
//    h%=p;
//    return h;
//}

BIGNUM H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    BIGNUM h,p;
    //BIGNUM *moudle = NULL;
    char hash[HASH_LEN];
    int i, j, hash_len, rv;

	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if ( !digest )
		goto err;
	/* Return either an EVP_MD structure or NULL if an error occurs. */
	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;

    for (i=0;;i++)
    {
        if (string[i]==0) break;
    	rv = EVP_DigestUpdate(&mdctx,  &string[i] , 1 );			//  1
    	if (!rv)
    		goto err;
    }

	rv = EVP_DigestFinal_ex(&mdctx, hash, &hash_len );
	if ( !rv || &hash_len <= 0 )
		goto err;


	BN_set_word( &h, 1l);
    j=0; i=1;
    for(;;)
    {
        BN_mul_word(&h, 256l);
        if (j == HASH_LEN)
        {
        	BN_add_word( &h, 1l);
        	i++;

        	j=0;
        }
        else
        {
        	BN_add_word( &h, hash[j]);
        	j++;
        }

        if ( BN_cmp(&h, module) == 1 )
        		break;
    }

    BN_mod( &h, &h, module , Context);

    bi_free_ptr( module );
	EVP_MD_CTX_cleanup(&mdctx);

    return h;

err:
    if( module )
        bi_free_ptr( module );

    EVP_MD_CTX_cleanup(&mdctx);

    //return NULL;
}

//int H2(ZZn2 x,char *s)
//{ // Hash an Fp2 to an n-byte string s[.]. Return n
//    sha sh;
//    Big a,b;
//    int m;
//
//    shs_init(&sh);
//    x.get(a,b);
//    while (a>0)
//    {
//        m=a%256;
//        shs_process(&sh,m);
//        a/=256;
//    }
//    while (b>0)
//    {
//        m=b%256;
//        shs_process(&sh,m);
//        b/=256;
//    }
//    shs_hash(&sh,s);
//
//    return HASH_LEN;
//}

int H2(COMPLEX *x,char *s)
{ // Hash an Fp2 to an n-byte string s[.]. Return n
    BIGNUM a,b;
    int m, ret, rv;
	EVP_MD *digest = NULL;
	EVP_MD_CTX mdctx;

	EVP_MD_CTX_init( &mdctx );
	digest = EVP_get_digestbyname( DAA_PARAM_MESSAGE_DIGEST_ALGORITHM );
	if ( !digest )
		return 0;
	/* Return either an EVP_MD structure or NULL if an error occurs. */
	rv = EVP_DigestInit_ex( &mdctx , digest , NULL );			//  initialization the ||
	if (!rv)
		goto err;

    if ( !COMP_get(x, &a, &b) )
    	goto err;

    while ( !BN_is_zero( &a) &&  BN_is_negative( &a) )
    {

        m = BN_mod_word( &a, 256l);

    	rv = EVP_DigestUpdate(&mdctx,  m, sizeof( m ) );			//  1
    	if (!rv)
    		goto err;

    	BN_div_word( &a, 256l);//TODO
    }
    while ( BN_is_negative( &b ))
    {
    	m = BN_mod_word( &b, 256l);
    	rv = EVP_DigestUpdate(&mdctx,  m, sizeof( m ) );			//  1
    	if (!rv)
    		goto err;;

    	BN_div_word( &b, 256l);//TODO
    }
	rv = EVP_DigestFinal_ex(&mdctx, s, &ret );
	if ( !rv || ret <= 0 )
		goto err;

    EVP_MD_CTX_cleanup(&mdctx);

    return ret;

err:

    EVP_MD_CTX_cleanup(&mdctx);
    return 0;
}

//Big H3(char *x1,char *x2)
//{
//    sha sh;
//    char h[HASH_LEN];
//    Big a;
//    int i;
//
//    shs_init(&sh);
//    for (i=0;i<HASH_LEN;i++)
//        shs_process(&sh,x1[i]);
//    for (i=0;i<HASH_LEN;i++)
//        shs_process(&sh,x2[i]);
//    shs_hash(&sh,h);
//    a=from_binary(HASH_LEN,h);
//    return a;
//}

//void H4(char *x,char *y)
//{ // hashes y=h(x)
//    int i;
//    sha sh;
//    shs_init(&sh);
//    for (i=0;i<HASH_LEN;i++)
//        shs_process(&sh,x[i]);
//    shs_hash(&sh,y);
//}

//
// MapToPoint
//

//ECn map_to_point(char *ID)
//{
//    ECn Q;
//    Big x0=H1(ID);
//
//    if (is_on_curve(x0)) Q.set(x0);
//    else                 Q.set(-x0);
//
//    return Q;
//}
EC_POINT *map_to_point(char *ID)
{
    EC_POINT *Q;
    BIGNUM x0 = H1( ID ), *module;
    int rv;

    Q = EC_POINT_new( group );
    if ( Q == NULL )
    	return 0;

	/* Get group module p */
	module = BN_new();
	if ( module == NULL )
		goto err;
	rv = ec_GFp_simple_group_get_curve( group, module, NULL, NULL, Context ); //return 1 if success
	if ( !rv )
		goto err;

    if ( !EC_POINT_set_compressed_coordinates_GFp( group, Q, &x0, 1, Context))
    		goto err;

    if( !EC_POINT_is_on_curve( group, Q, Context) )
    {
    	/* r->x is neg*/
    	if ( BN_is_negative(&x0) )
    		BN_set_negative( &x0, 0);
    	else
    		BN_set_negative( &x0, 1);

    	BN_mod( &x0, &x0, module, Context );

    	EC_POINT_set_compressed_coordinates_GFp( group, Q, &x0, 1, Context );
    }

    BN_free( module );
    return Q;

    err:
    if ( module )
    	BN_free( module );
}

//void strip(char *name)
//{ /* strip off filename extension */
//    int i;
//    for (i=0;name[i]!='\0';i++)
//    {
//        if (name[i]!='.') continue;
//        name[i]='\0';
//        break;
//    }
//}

//int main()
//{
//    miracl *mip=mirsys(18,0);   // thread-safe ready. (36,0) for 1024 bit p
//    ifstream common("commonx.ibe");
//    ifstream plaintext;
//    ofstream key_file,ciphertext;
//    ECn U,P,Ppub,Qid,infinity;
//    ZZn2 gid,w;
//    ZZn *store;
//    char key[HASH_LEN],pad[HASH_LEN],rho[HASH_LEN],V[HASH_LEN],W[HASH_LEN];
//    char ifname[100],ofname[100],ch,iv[16];
//    Big p,q,r,x,y,cof;
//    int i,bits;
//    long seed;
//    aes a;
//    BOOL Ok,precomp=FALSE;
//
//    cout << "Enter 9 digit random number seed  = ";
//    cin >> seed;
//    irand(seed);
//
//// ENCRYPT
//
//    common >> bits;
//    mip->IOBASE=16;
//    common >> p >> q;
//
//    cof=(p+1)/q;
//
//    common >> x >> y;
//    EBrick B(x,y,(Big)1,(Big)0,p,8,QBITS);   // precomputation based on P, 8-bit window
//
//    ecurve(1,0,p,MR_PROJECTIVE);
//
//    P.set(x,y);
//
//    common >> x >> y;
//    Ppub.set(x,y);
//
//    store=new ZZn[500];
//
//    char id[1000];
//    cout << "Enter your correspondents email address (lower case)" << endl;
//    cin.get();
//    cin.getline(id,1000);
//
//    mip->IOBASE=10;
//    Qid=map_to_point(id);
//
//// This can be done before we know the message to encrypt
//
//    for (int times=0;times<2;times++)
//    {
//
//        Ok=Tate(Ppub,Qid,q,precomp,store,gid);
//        if (!Ok)
//        {  /* Ppub is not of order q ! */
//            cout << "Bad Parameters" << endl;
//            exit(0);
//        }
//
//// Do it again to demonstrate that precomputation has worked
//
//        precomp=TRUE;
//
////
//// prepare to encrypt file with random session key
////
//
//        for (i=0;i<HASH_LEN;i++) key[i]=(char)brand();
//        for (i=0;i<16;i++) iv[i]=i; // set CFB IV
//        aes_init(&a,MR_CFB1,16,key,iv);
//
//// figure out where input is coming from
//
//        cout << "Text file to be encoded = " ;
//        cin >> ifname;
//
//   /* set up input file */
//        strcpy(ofname,ifname);
//        strip(ofname);
//        strcat(ofname,".ibe");
//        plaintext.open(ifname,ios::in);
//        if (!plaintext)
//        {
//            cout << "Unable to open file " << ifname << "\n";
//            return 0;
//        }
//        cout << "encoding message\n";
//        ciphertext.open(ofname,ios::binary|ios::out);
//
//// now encrypt the plaintext file
//
//        forever
//        { // encrypt input ..
//            plaintext.get(ch);
//            if (plaintext.eof()) break;
//            aes_encrypt(&a,&ch);
//            ciphertext << ch;
//        }
//
//        aes_end(&a);
//        ciphertext.close();
//        plaintext.clear();
//        plaintext.close();
////
//// Now IBE encrypt the session key
////
//        for (i=0;i<HASH_LEN;i++) rho[i]=(char)brand();
//
//        r=H3(rho,key);
//
//        B.mul(r,x,y);       // U=r*P
//        U.set(x,y);
//
//        w=pow(gid,r);
//        H2(w,pad);
//
//        for (i=0;i<HASH_LEN;i++)
//        {
//            V[i]=rho[i]^pad[i];
//            pad[i]=0;
//        }
//        H4(rho,rho);
//        for (i=0;i<HASH_LEN;i++)
//        {
//            W[i]=key[i]^rho[i];
//            rho[i]=0;
//        }
//
//        strip(ofname);
//        strcat(ofname,".key");
//        mip->IOBASE=16;
//        key_file.open(ofname);
//        U.get(x,y);
//
//        key_file << x << endl;
//        key_file << y << endl;
//        x=from_binary(20,V);      // output bit strings in handy Big format
//        key_file << x << endl;
//        x=from_binary(20,W);
//        key_file << x << endl;
//        key_file.close();
//    }
//
//    return 0;
//}
#ifdef  __cplusplus
}
#endif

#endif /* TATE_PAIRING_H_ */
