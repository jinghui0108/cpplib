#include "JAlgo.h"

#include "openssl/sha.h"

#include "openssl/evp.h"

#include "openssl/des.h"
#include "openssl/pkcs12.h"
#include "openssl/x509.h"
#include "openssl/err.h"
#include "openssl/md5.h"
#pragma region  RSA_REGION

int pass_cb(char *buf, int size, int rwflag, void *u)
{
       int len;
       char *tmp;
       /* We'd probably do something else if 'rwflag' is 1 */
       printf("Enter pass phrase for \"%s\"\n", u);

       /* get pass phrase, length 'len' into 'tmp' */

       tmp = "11111111";
       len = strlen(tmp);

       if (len <= 0) return 0;
       /* if too long, truncate */
       if (len > size) len = size;
       memcpy(buf, tmp, len);

       return len;
}

JAlgo::JAlgo(){

}

RSA* JAlgo::ReadPrivateKey(char* in_szKeyPath)
{
    FILE    *fp = NULL; 
    char    szKeyPath[1025];
    RSA     *priRsa = NULL,*pOut = NULL;

    memset(szKeyPath, 0 ,sizeof(szKeyPath));

    if(1024 < strlen(in_szKeyPath))
        strncpy(szKeyPath, in_szKeyPath, 1024);
    else
        strncpy(szKeyPath, in_szKeyPath, strlen(in_szKeyPath));

    printf("密钥文件路径[%s]", szKeyPath);

    fopen_s(&fp,szKeyPath, "rb");

    if(NULL ==fp)
    {
        printf( "打开密钥文件[%s]出错", szKeyPath);
        return NULL;
    }


   
    if(NULL == (priRsa = PEM_read_RSAPrivateKey(fp, &priRsa,&pass_cb,NULL)))
    {
        printf( "读出私钥内容出错\n");
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    printf("提取私钥\n");
    pOut = priRsa;
    return pOut;
}



RSA* JAlgo::LoadKeyFile(char* in_szKeyPath,bool ispri)
{
  return 0;
    //FILE    *fp = NULL; 
    //char    szKeyPath[1025];
    //RSA     *rsa = NULL;

    //memset(szKeyPath, 0 ,sizeof(szKeyPath));

    //if(1024 < strlen(in_szKeyPath)){
    //    strncpy(szKeyPath, in_szKeyPath, 1024);
    //}
    //else{
    //    strncpy(szKeyPath, in_szKeyPath, strlen(in_szKeyPath));
    //}


    //EVP_PKEY key;

    //key=EVP_PKEY_new();
    //
    //EVP_PKEY_set1_RSA(key,rsa);



    //if(NULL == (fp = fopen(szKeyPath, "rb")))
    //{

    //    printf( "打开文件[%s]出错", szKeyPath);
    //    return NULL;
    //}

    //if(!ispri)
    //{
    //  rsa = PEM_read_RSAPublicKey(fp,&rsa,NULL,NULL);

    //}else{
    //   rsa = PEM_read_PrivateKey(fp,&rsa,NULL,NULL);

    //}

    //if(NULL == rsa)
    //{
    //    printf("读出内容出错\n");
    //    fclose(fp);
    //    return NULL;
    //}


    //fclose(fp);
    //pOut = rsa;
    //return pOut;
}



RSA* JAlgo::LoadRSAKeyFile(char* in_szKeyPath,bool ispri)
{
    FILE    *fp = NULL; 
    char    szKeyPath[1025];
    RSA     *rsa = NULL, *pOut = NULL;

    memset(szKeyPath, 0 ,sizeof(szKeyPath));

    if(1024 < strlen(in_szKeyPath)){
        strncpy(szKeyPath, in_szKeyPath, 1024);
    }
    else{
        strncpy(szKeyPath, in_szKeyPath, strlen(in_szKeyPath));
    }


    if(NULL == (fp = fopen(szKeyPath, "rb")))
    {

        printf( "打开文件[%s]出错", szKeyPath);
        return NULL;
    }

    if(!ispri)
    {
      rsa = PEM_read_RSAPublicKey(fp,&rsa,NULL,NULL);

    }else{
      rsa = PEM_read_RSAPrivateKey(fp,&rsa,NULL,NULL);
    }

    if(NULL == rsa)
    {
        printf("读出内容出错\n");
        fclose(fp);
        return NULL;
    }


    fclose(fp);
    pOut = rsa;
    return pOut;
}



bool  JAlgo::Sign_ShaWithRSA(unsigned char*data,unsigned int len,unsigned char*ret,unsigned int *retLen,RSA *rsa,int type)
{

	int mType=NID_sha1WithRSAEncryption;


	 switch(type){
	  case 1:mType=NID_sha1WithRSAEncryption;break;
	  case 224:mType=NID_sha224WithRSAEncryption;break;
	  case 256:mType=NID_sha256WithRSAEncryption;break;
	  case 384:mType=NID_sha384WithRSAEncryption;break;
	  case 512:mType=NID_sha512WithRSAEncryption;break;
	  
	 }
	  
	  
	  return 1==RSA_sign(mType, data,len, ret, retLen, rsa);

}


bool  JAlgo::Verify_ShaWithRSA(unsigned char *data,unsigned int len,unsigned char *sig,unsigned int sigLen,RSA *rsa,int type)
{
	int mType=NID_sha1WithRSAEncryption;

	 switch(type){
	  case 1:mType=NID_sha1WithRSAEncryption;break;
	  case 224:mType=NID_sha224WithRSAEncryption;break;
	  case 256:mType=NID_sha256WithRSAEncryption;break;
	  case 384:mType=NID_sha384WithRSAEncryption;break;
	  case 512:mType=NID_sha512WithRSAEncryption;break;
	  
	 }
	 
    return RSA_verify(mType,data,len,sig,sigLen,rsa)== 1;
}


bool JAlgo::MakePublicKey(RSA *rsa,const char *name)
{
  FILE *fp =  fopen(name, "wb");
  int ret=PEM_write_RSAPublicKey(fp, rsa);
  fclose(fp);
  return ret==1;
}


RSA* JAlgo::MakeAndLoadPublicKey(RSA *rsa,const char *name)
{
  FILE *fp =  fopen(name, "wb");
  int ret=PEM_write_RSAPublicKey(fp, rsa);
  fclose(fp);

  if(ret==1){
     fp=  fopen(name, "rb");
     RSA * retRSA=PEM_read_RSAPublicKey(fp,NULL,NULL,NULL);
     fclose(fp);
    return retRSA;
  }
  return NULL;
}


RSA *JAlgo::MakePrivateKey(const char * name,int keyLen)
{
  RSA * rsa=NULL;
  rsa = RSA_generate_key(keyLen,RSA_3,NULL,NULL );
  
  FILE *fp = fopen(name, "wb");
  int ret=PEM_write_RSAPrivateKey(fp, rsa,NULL, NULL,keyLen,NULL, NULL);
  fclose(fp);


  if(ret==1)
  {
    return rsa;

  }else{
    return NULL;
  }

}

int JAlgo::MakeKeyPair(const char * pubKey,const char * priKey,int keyLen)
{
	RSA *keypair = RSA_generate_key(keyLen, RSA_3, NULL, NULL);
	
	
	char *pri_key = NULL;
	char *pub_key = NULL;
	
	
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());
	
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);
	
	size_t pri_len = BIO_pending(pri);
	size_t pub_len = BIO_pending(pub);
	
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);
	
	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);
	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';
	
	
	FILE *pubFile = fopen(pubKey, "w");

	if (pubFile == NULL)
	{
		return -1;
	}

	fputs(pub_key, pubFile);
	fclose(pubFile);
	
	FILE *priFile = fopen(priKey, "w");

	if (priFile == NULL)
	{
		return  -2;
	}

	fputs(pri_key, priFile);
	fclose(priFile);
	
	
	RSA_free(keypair);

	BIO_free_all(pub);

	BIO_free_all(pri);
	
	free(pri_key);
	free(pub_key);
	
	return  0;
	
}

RSA* JAlgo::LoadKeyBuf(unsigned char *key,bool isPri)
{

	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf(key, -1);
	
	
	if(isPri)
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}else{
		rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	}
	
	BIO_free_all(keybio);
	
	return rsa;

}


unsigned char* JAlgo::Rsa_Encode(unsigned char*data,int dataLen,RSA *rsa,int &len,bool isPri)
{

	len = RSA_size(rsa);
	
	unsigned char *buf =new unsigned char[len];
	
	memset(buf,0,len);
	
	int ret=0;
	
	if(isPri)
	{
		ret = RSA_private_encrypt(dataLen,data,buf,rsa,RSA_PKCS1_PADDING);
		
	}else{
	    ret= RSA_public_encrypt(dataLen,data,buf, rsa,RSA_PKCS1_PADDING);

	}
	
	return buf;
}


unsigned char* JAlgo::Rsa_Decode(unsigned char*data,int dataLen,RSA *rsa,int &len,bool isPri)
{
	len = RSA_size(rsa);

	unsigned char *buf =new unsigned char[len];
	
	memset(buf,0,len);
	
	int ret=0;
	
	if(isPri)
	{
		ret = RSA_private_decrypt(dataLen,data,buf,rsa,RSA_PKCS1_PADDING);
		
	}else{
	    ret= RSA_public_decrypt(dataLen,data,buf,rsa,RSA_PKCS1_PADDING);
	}
	
	return buf;
}


#pragma region PFX


bool JAlgo::PFX_ShaSign_Str(const char* szPKCS12FileName, const char* szPKCS12Password, 
    const char* szUnSignData,char* szSignData,int *szSignLen,int sign_Type)
{
    int unSigneLen=strlen(szUnSignData);
    unsigned char *pTemData=new unsigned char[unSigneLen];
    memcpy(pTemData,szUnSignData,unSigneLen);

    bool ret= PFX_ShaSign(szPKCS12FileName,szPKCS12Password,pTemData,unSigneLen,szSignData,szSignLen,sign_Type);

    delete[] pTemData;
    pTemData=NULL;

    return ret;
    
}
bool JAlgo::PFX_ShaSign(const char* szPKCS12FileName, const char* szPKCS12Password, 
    unsigned char* szUnSignData,int unSigneLen, char* szSignData,int *szSignLen,int sign_Type)
{

  int ret=0;

	 if (szPKCS12FileName == NULL || szUnSignData == NULL || szSignData == NULL) {
     ret=-1;
		 goto errCode;
	 }

	 int   err=0;

  EVP_MD_CTX* ctx = NULL;
  ctx = EVP_MD_CTX_create();

  if(ctx == NULL) {
       ret=-2;
		   goto errCode;
  }


	 EVP_PKEY *     pkey = NULL;
	 FILE *     fp   = NULL;
	 X509 *     x509 = NULL;
	 PKCS12*     p12  = NULL;
	 STACK_OF(X509) *ca  = NULL;


	 if(!(fp = fopen(szPKCS12FileName, "rb"))) {
       ret=-3;
		   goto errCode;
	 }
	 
	 p12 = d2i_PKCS12_fp(fp, NULL);
	 fclose (fp);
	 

	 if(!p12) {
		   ret=-4;
		   goto errCode;
	 }
	 
	 if(!PKCS12_parse(p12, szPKCS12Password, &pkey, &x509, &ca)) {
		   ret=-5;
		   goto errCode;
	 }


	 if(pkey == NULL) { 
		  ret=-6;
		   goto errCode;
	 }
	 
   switch(sign_Type)
   {
   case 1:err=EVP_SignInit_ex(ctx, EVP_sha1(),NULL);break;
   case 224:err=EVP_SignInit_ex(ctx, EVP_sha224(),NULL);break;
   case 256:err=EVP_SignInit_ex(ctx, EVP_sha256(),NULL);break;
   case 384:err=EVP_SignInit_ex(ctx, EVP_sha384(),NULL);break;
   case 512:err=EVP_SignInit_ex(ctx, EVP_sha512(),NULL);break;
   default:err=EVP_SignInit_ex(ctx, EVP_sha1(),NULL);break;
   }
   
   
   if(!err)
   {
		   ret=-7;
		   goto errCode;
   }

	 err=EVP_SignUpdate(ctx,szUnSignData,unSigneLen);


    if (err != 1) {
		  ret=-8;
		   goto errCode;
	 }
	  
   unsigned int   sig_len=EVP_PKEY_size(pkey);
   unsigned char  *sig_buf=(unsigned char*)malloc(sig_len);
   memset(sig_buf,0,sig_len);

   err = EVP_SignFinal(ctx,sig_buf,&sig_len,pkey);
	 
	 if (err != 1) {
		   ret=-9;
		   goto errCode;
	 }
	 
	  
  ret=1; 
 
  *szSignLen=sig_len;
  printf("sigLen=%d\n",sig_len);
	memcpy(szSignData, sig_buf,sig_len);


errCode:
  if(ret!=1){
    ERR_print_errors_fp(stderr);
    printf("error=%d",ret);
  }

  if(p12) PKCS12_free(p12);
  if(x509) X509_free(x509);
  if(pkey) EVP_PKEY_free (pkey);

  if(ctx){
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
  }

  free(sig_buf);
  sig_buf=NULL;

	 return ret==1;
}

bool JAlgo::PFX_Sign2(const char *szPKCS12FileName,const char *szPKCS12Password,unsigned char *msg,size_t msgLen,char **buf,size_t &bufLen)
{
  EVP_MD_CTX *mdctx = NULL;
  unsigned char *sig=NULL;
  size_t sigLen=0;

  std::string errstr="";
  int ret = 0;

  if(!(mdctx = EVP_MD_CTX_create())){
    errstr="Create the Message Digest Context";
    ret=-1;
    goto err;
  }


	 EVP_PKEY *     pkey = NULL;
	 FILE *     fp   = NULL;
	 X509 *     x509 = NULL;
	 PKCS12*     p12  = NULL;
	 STACK_OF(X509) *ca  = NULL;

	
	 if(!(fp = fopen(szPKCS12FileName, "rb"))) {
       errstr="Open File Error";
       ret=-2;
		   goto err;
	 }
	 
	 p12 = d2i_PKCS12_fp(fp, NULL);
	 fclose (fp);
	 

	 if(!p12) { 
		   errstr="Error reading PKCS#12 file";
       ret=-3;
		   goto err;
	 }
	 
	 if(!PKCS12_parse(p12, szPKCS12Password, &pkey, &x509, &ca)) {
		 errstr="Error parsing PKCS#12 file/n";
      ret=-4;
		  goto err;
	 }
 

/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
   if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)){
      ret=-5;
     goto err;
   }
 
 /* Call update with the message */
 if(1 != EVP_DigestSignUpdate(mdctx, msg, msgLen)){
      ret=-6;
     goto err;
   }
 
 /* Finalise the DigestSign operation */
 /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
  * signature. Length is returned in slen */
 if(1 != EVP_DigestSignFinal(mdctx, NULL, &sigLen)){
      ret=-7;
     goto err;
   }
 /* Allocate memory for the signature based on size in slen */
 if(!(sig = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * (sigLen)))) {
      ret=-8;
      goto err;
   };
 /* Obtain the signature */
 if(1 != EVP_DigestSignFinal(mdctx, sig, &sigLen)){
      ret=-9;
      goto err;
  }
 

 ret = 1;
 
 bufLen=sigLen;
 *buf=new char[bufLen];
 memset(*buf,0,bufLen);

 memcpy(*buf,sig,bufLen);

 printf("bufLen2=%d\n",bufLen);

 printf("bufLen2D=%s\n",*buf);


 err:
 if(ret != 1)
 {
   printf("%s",errstr);
 }
 
 /* Clean up */
 if(sig && !ret) OPENSSL_free(sig);

 if(mdctx) EVP_MD_CTX_destroy(mdctx);

  if(p12) PKCS12_free(p12);
  if(x509) X509_free(x509);
  if(pkey) EVP_PKEY_free(pkey);

 return ret==1;
}

bool JAlgo::PFX_ShaVerify(const char* szPKCS12FileName, const char* szPKCS12Password, 
      const char* szUnSignData, const char* szSignData,int sign_Type)
{
	 if (szPKCS12FileName == NULL || szSignData == NULL) {
	  return false;
	 }
	 
	 int            err;
	 unsigned int   sig_len;
	 EVP_MD_CTX     md_ctx;
	 EVP_PKEY *     pkey = NULL;
	 FILE *     fp   = NULL;
	 X509 *     x509 = NULL;
	 PKCS12*     p12  = NULL;
	 STACK_OF(X509) *ca  = NULL;
	 

	  SSLeay_add_all_algorithms();
	  ERR_load_crypto_strings();
  

	 if (!(fp = fopen(szPKCS12FileName, "rb"))) {
		 return false;
	 }
	 
	 
	 p12 = d2i_PKCS12_fp(fp, NULL);
	 fclose (fp);
	 
	 
	 if (!p12) {
	  fprintf(stderr, "Error reading PKCS#12 file/n");
	  ERR_print_errors_fp(stderr);
	  return false;
	 }
	 
	 if (!PKCS12_parse(p12, szPKCS12Password, &pkey, &x509, &ca)) {
	  fprintf(stderr, "Error parsing PKCS#12 file/n");
	  ERR_print_errors_fp(stderr);
	  PKCS12_free(p12);
	  return false;
	 }
	
	 if (x509 == NULL) { 
		  ERR_print_errors_fp (stderr);
		  PKCS12_free(p12);
		  return false;
	 }
	
	
	 pkey=X509_get_pubkey(x509);
	 
	 if (pkey == NULL) {
		  ERR_print_errors_fp (stderr);
		  PKCS12_free(p12);
		   X509_free(x509);
		  return false;
	 }
 
	 
	 sig_len = 0;
	 sig_len = strlen(szSignData);
	 
	 
	 
   EVP_MD_CTX_init(&md_ctx);

   switch(sign_Type)
   {
   case 1:EVP_VerifyInit(&md_ctx, EVP_sha1());break;
   case 224:EVP_VerifyInit(&md_ctx, EVP_sha224());break;
   case 256:EVP_VerifyInit(&md_ctx, EVP_sha256());break;
   case 384:EVP_VerifyInit(&md_ctx, EVP_sha384());break;
   case 512:EVP_VerifyInit(&md_ctx, EVP_sha512());break;
   default:EVP_VerifyInit(&md_ctx, EVP_sha1());break;
   }

	 EVP_VerifyUpdate(&md_ctx, szUnSignData, strlen(szUnSignData));
	 
	 err = EVP_VerifyFinal (&md_ctx, (const BYTE*)szSignData, sig_len, pkey);

   EVP_MD_CTX_cleanup(&md_ctx);


	  PKCS12_free(p12);
	  X509_free(x509);
	   EVP_PKEY_free(pkey);
	   
	if (err != 1) {
	  ERR_print_errors_fp (stderr);
	  return false;
	}
	
	 return true;
}
  
#pragma endregion

  
#pragma endregion
  
  
#pragma region HASH_REGION
 
std::string JAlgo::Hash(const char *data,int type,bool upper)
{
	
	
	unsigned char *hashBuf=new unsigned char[type+1];
	memset(hashBuf,0,type+1);
	
	
	switch(type)
	{
		case 16:MD5((const unsigned char *)data,strlen(data),hashBuf);break;
		case 20:SHA1((const unsigned char *)data,strlen(data),hashBuf);break;
		case 28:SHA224((const unsigned char *)data,strlen(data),hashBuf);break;
		case 32:SHA256((const unsigned char *)data,strlen(data),hashBuf);break;
		case 48:SHA384((const unsigned char *)data,strlen(data),hashBuf);break;
		case 64:SHA512((const unsigned char *)data,strlen(data),hashBuf);break;
	}
	
	char *buf=new char[type*2+1];
	
	memset(buf,0,type*2+1);
	

	char tmp[3] = {0};


	char fmt[]="%02x";
	
	if(upper)
	{
		fmt[3]='X';
	}
	
		for (int i = 0; i < type; i++)

		{
			sprintf(tmp, fmt, hashBuf[i]);
			strcat(buf,tmp);
		}
		
		
		std::string retStr=std::string(buf);
		
		delete[] hashBuf;
		delete[] buf;
		
	
	return retStr;

}


///dd724b33aebcab3fea4f23f99f42016a
std::string JAlgo::Md5(const char *data,bool upper)
{
	return Hash(data,16,upper);

}

//ec92a040e3f6c96fbb012131a833089f87187a0e
std::string JAlgo::Sha1(const char *data,bool upper)
{
	return Hash(data,20,upper);
}



///e448e0c7eaecc0396215455629717fd357e37308ec2d023760e0e832
std::string JAlgo::Sha224(const char *data,bool upper)
{
	return Hash(data,28,upper);
}




//89af9620b91779f80f23537a1b45d109981a1c651ce24a46f6d70de36f25ddd7
std::string JAlgo::Sha256(const char *data,bool upper)
{
	return Hash(data,32,upper);
}


///20e560c2c81cd2e6c90376edcec0f65205c246cb3fcc3a3005e49ff190afeb02ac8c53598e5b8ee7e58c354d26fb9135
std::string JAlgo::Sha384(const char *data,bool upper)
{
	return Hash(data,48,upper);
}



//2a77c0982479d2394ce03128a50b45598a00ff0e9b15e8e2c71bb60f8870aee922bceb6939d5b4fea43cd6681b877b0f5db45cf5d865ec5f54251f70785d7df0
std::string JAlgo::Sha512(const char *data,bool upper)
{
	return Hash(data,64,upper);
}

#pragma endregion

#pragma region BASE64_REGION

std::string JAlgo::ToBase64(const char *buffer,bool newLine)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    
    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, strlen(buffer));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    char *buff = new char[bptr->length + 1];
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);
    
    std::string strRet=std::string(buff);
    
    delete[] buff;

    return strRet;
}

std::string JAlgo::FromBase64(const char *input,bool newLine)
{
   
    int length=strlen(input);

    char * bData=new char[length];
    memset(bData,0,length);

    memcpy(bData,input,length);

    BIO *b64 = NULL; 
    BIO *bmem = NULL;
  
    char *buffer =new char[length+1];
    memset(buffer, 0, length+1);

    b64 = BIO_new(BIO_f_base64());

    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }

    bmem = BIO_new_mem_buf(bData, length);
    bmem = BIO_push(b64, bmem);
    int len=BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    if(len<length){
      buffer[len]=0;
    }

	std::string strRet=std::string(buffer);

    delete[] bData;

    delete[] buffer;
    
    return strRet;
}



char *JAlgo::FromBase64(const char *input,int inLen,int &outLen,bool newLine)
{
    int length=strlen(input);

    char * bData=new char[length];
    memset(bData,0,length);

    memcpy(bData,input,length);

    BIO *b64 = NULL; 
    BIO *bmem = NULL;
  
    char *buffer =new char[length+1];
    memset(buffer, 0, length+1);

    b64 = BIO_new(BIO_f_base64());

    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }

    bmem = BIO_new_mem_buf(bData, length);
    bmem = BIO_push(b64, bmem);
    outLen=BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    delete[] bData;

    return buffer;
}

std::string JAlgo::ToBase64(unsigned char *buffer,int bufLen,bool newLine)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    
    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, bufLen);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    char *buff = new char[bptr->length + 1];
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);
    
    std::string strRet=std::string(buff);
    
    delete[] buff;

    return strRet;
}


std::string JAlgo::FromBase64(unsigned char *buffer,int bufLen,bool newLine)
{
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    int length=bufLen;
    char *tem =new char[length+1];
    memset(tem, 0, length+1);
    b64 = BIO_new(BIO_f_base64());
    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(buffer, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, tem, length);
    BIO_free_all(bmem);

	std::string strRet=std::string(tem);
    
    delete[] tem;
    
    return strRet;
}


#pragma endregion

bool JAlgo::Char2Hex_Ex(unsigned char*data,int len,char*buf,bool upper)
{
 
  if(data==NULL)
  {
      printf("ERROR:%d\n",-1);
      return false;
  }

   int length=2*len;

   printf("Char2Hex:Len=%d\n",length);
	
	char tmp[3]={0};

	char fmt[]="%02x";
	
	if(upper)
	{
		fmt[3]='X';
	}
	
	unsigned char c;
	for(int i=0;i<len;i++)
	{
    c=data[i];

    printf(fmt,c);

		sprintf(tmp,fmt,c);

    ///strcat_s(buf,length,fmt);
		strcat(buf, tmp);
	}
	return true;

}

char * JAlgo::Char2Hex(unsigned char*data,int len,int &length,bool upper)
{
 
  if(data==NULL)
  {
      printf("ERROR:%d\n",-1);
      return NULL;
  }

   length=2*len;

   printf("Char2Hex:Len=%d\n",length);

	char *buf=new char[length];
	
	memset(buf,0,length);
	
	
	char tmp[3]={0};

	char fmt[]="%02x";
	
	if(upper)
	{
		fmt[3]='X';
	}
	
	unsigned char c;
	for(int i=0;i<len;i++)
	{
    c=data[i];

    printf(fmt,c);

		sprintf(tmp,fmt,c);

    ///strcat_s(buf,length,fmt);
		strcat(buf, tmp);
	}
	return buf;

}


char * JAlgo::Hex2Char(const char*data,int len,int &length)
{
   length=len/2;

	 char *buf=new char[length];
	 
	memset(buf,0,length);
  char c;
  unsigned char u;
	bool low=false;

	int index=0;
	for(int i=0;i<len;i++)
	{
	
		c=toupper(data[i]);
		
		if(c>='A'&&c<='F'||c>='0'&&c<='9')
		{
			u=(c>='A'?(c-'A'+10):(c-'0'));
			
			if(low)
			{
				buf[index++]+=u;
				low=false;
			
			}else
			{
				buf[index]=u<<4;
				low=true;
			}
		}
	}

 return buf;

}
   
   

 
 
#pragma region URL_REGION

static int h2c(char *s)  
{  
    int value;  
    int c;  
  
    c = ((unsigned char *)s)[0];  
    if (isupper(c))  
        c = tolower(c);  
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;  
  
    c = ((unsigned char *)s)[1];  
    if (isupper(c))  
        c = tolower(c);  
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;  
  
    return (value);  
}  



std::string JAlgo::UrlEncode(const char * strIn)
{
	const char  *in_str = strIn;
    int in_str_len = strlen(in_str);  
    int out_str_len = 0;  
    std::string out_str = "";
    
    unsigned char c;  
    unsigned char *to, *start;  
    const unsigned char *from, *end;  
    unsigned char hexchars[] = "0123456789ABCDEF";  
  
    from = (unsigned char *)in_str;  
    end = (unsigned char *)in_str + in_str_len;  
    start = to = (unsigned char *) malloc(3*in_str_len+1);  
  
    while (from < end) {  
        c = *from++;  
  
        if (c == ' ') {  
            *to++ = '+';  
        } else if ((c < '0' && c != '-' && c != '.') ||  
            (c < 'A' && c > '9') ||  
            (c > 'Z' && c < 'a' && c != '_') ||  
            (c > 'z')) {   
                to[0] = '%';  
                to[1] = hexchars[c >> 4];  
                to[2] = hexchars[c & 15];  
                to += 3;  
        } else {  
            *to++ = c;  
        }  
    }  
    *to = 0;  
  
    out_str_len = to - start;  
    out_str = (char *) start;  
    free(start);  
    return out_str;
}
 
std::string JAlgo::UrlDecode(const char * strIn)
{
	const char  *in_str = strIn;  
    int in_str_len = strlen(in_str);  
    int out_str_len = 0;  
    std::string out_str="";  
    char *str;  
  
    str = _strdup(in_str);  
    char *dest = str;  
    char *data = str;  
  
    while (in_str_len--) {  
        if (*data == '+') {  
            *dest = ' ';  
        }  
        else if (*data == '%' && in_str_len >= 2 && isxdigit((int) *(data + 1))   
            && isxdigit((int) *(data + 2))) {  
                *dest = (char) h2c(data + 1);  
                data += 2;  
                in_str_len -= 2;  
        } else {  
            *dest = *data;  
        }  
        data++;  
        dest++;  
    }  
    *dest = '\0';  
    out_str_len =  dest - str;  
    out_str = str;  
    free(str);  
    return out_str;  
}

#pragma endregion


#include<vector>
std::string JAlgo::Des_ECB_Encode(const char *data,const char * key)
{

	std::string retStr="";
	
	DES_cblock keyEncrypt;
	
	int dataLen=strlen(data);
	
	int keyLen=strlen(key);
	
	memset(keyEncrypt, 0, 8);
	
	
	if (keyLen <= 8) memcpy(keyEncrypt, key,keyLen);
	else memcpy(keyEncrypt,key, 8);
	
	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);
	
	
	const_DES_cblock inputText;
	DES_cblock outputText;
	
	std::vector<unsigned char> vecCiphertext;
	
	//unsigned char *vecCiphertext=new unsigned char[];
	
	unsigned char tmp[8];
	

	for (int i = 0; i < dataLen / 8; i++)
	{
		memcpy(inputText,data + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp,outputText, 8);
		
		
		for (int j = 0; j < 8; j++)
		    vecCiphertext.push_back(tmp[j]);
	
	}
	
	
	if (dataLen% 8 != 0)
	{
		int tmp1 = dataLen/ 8 * 8;
		int tmp2 = dataLen - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, data + tmp1, tmp2);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);
		
		
	}
	
	retStr.clear();
	retStr.assign(vecCiphertext.begin(), vecCiphertext.end());
	
	return retStr;

}


unsigned char * JAlgo::Des_CBC_Encode(const char *key, const char *ivBuf,const char *data,size_t dataLen
  , size_t &enDataLen,int mode) 
 {
   DES_key_schedule schedule;
  unsigned char key1[8]={0};
  
  des_cblock *iv_block=NULL;
  int pading ;
  
  size_t ivLen ;
  char *tem_buf=NULL;
  
  memcpy( key1, key, 8 );
  
  DES_set_key_unchecked( (const_DES_cblock*)&key1, &schedule);
  
  ivLen = strlen( ivBuf );
  
  iv_block = (des_cblock *)malloc(ivLen * sizeof(unsigned char));
  
  memcpy(iv_block,ivBuf,ivLen);
  
  pading = 8 - (dataLen % 8);

  enDataLen = dataLen + pading;
  
  tem_buf = (char*)malloc(enDataLen);
  memcpy(tem_buf,data,dataLen );
  
  if(mode==0){
	  for (size_t i = dataLen ; i < enDataLen; i++ ) {
			 tem_buf[i] =0;
	  }
  }else{
	 for (size_t i = dataLen ; i < enDataLen; i++ ) {
			tem_buf[i] = pading;
	 }
  }
 unsigned char * enDataBuf = new unsigned char[enDataLen];
  
  DES_cbc_encrypt( (const unsigned char*)tem_buf, (unsigned char *)enDataBuf, enDataLen, &schedule, iv_block, DES_ENCRYPT);
  
  free(iv_block);
  free(tem_buf);
  return enDataBuf;
}




unsigned char * JAlgo::Des_CBC_Decode(const char *key, const char *iv, const char *data,size_t dataLen
    , size_t &deDataLen,int mode)
    {
    
   DES_key_schedule schedule;
  
  unsigned char keyBuf[8]={0};
  des_cblock *iv_block;
  size_t ivLen ;
  memcpy( keyBuf, key, 8 );
  DES_set_key_unchecked( (const_DES_cblock*)&keyBuf, &schedule);
  ivLen = strlen( iv );
  
  iv_block = (des_cblock *)malloc(ivLen * sizeof(unsigned char));
  
  memcpy(iv_block,iv,ivLen);
  
  unsigned char *deDataBuf = new unsigned char[dataLen];
  
  memset(deDataBuf,0,dataLen);
  
  DES_cbc_encrypt( (const unsigned char*)data, deDataBuf, dataLen, &schedule, iv_block, DES_DECRYPT);
 
  unsigned char delBuf[8]={0};
  
  memcpy(delBuf,deDataBuf+dataLen-8,8);
  
  bool hasPadding=false;
  int tCount=0;
  int tLen=0;
  deDataLen=dataLen;

if(mode==0)
{
}else{
  for(int i=0;i<8;i++)
  {
		if(i+delBuf[i]==8)
		{
				hasPadding=true;
				tLen=delBuf[i];
				tCount=0;
	
		}
		
		if(hasPadding&&delBuf[i]==tLen)
		{
				tCount++;
		}
  
  }
  
  if(tCount==tLen)
  {
		 for(int i=0;i<tCount;i++)
		{
			deDataBuf[dataLen-1-i]=0;
		}
		 deDataLen=dataLen-tCount;
  }
 
 }
  free(iv_block);
  
  return deDataBuf;
}
#include <sstream>
 #include <fstream>
 
 
EVP_PKEY*JAlgo::LoadEVPKey(const char *file)
{
		X509 *	x509;
		
		std::ifstream in(file);
		std::ostringstream tmp;
		tmp << in.rdbuf();
		std::string strData = tmp.str();

		EVP_PKEY *pkey;
		
		 char *pemCert;
		 BIO * b = BIO_new_mem_buf((char*)(strData.c_str()), strData.length());
		 
		  if (NULL == b){
				return NULL;
		   }
		   
		   PEM_read_bio_X509(b, &x509, NULL, NULL);
		   
		  if (NULL == x509){
				BIO_free(b), b=NULL;
				X509_free(x509), x509=NULL;
			    return NULL;
		 }
		 
		  if (x509 == NULL) {
				ERR_print_errors_fp(stderr);
				
		   }

		   pkey=X509_get_pubkey(x509);
    
			if (pkey == NULL) {
				ERR_print_errors_fp (stderr);
				return NULL;
			}
		
		  return pkey;
		   
}


bool JAlgo::LoadKeyFromPFX(const char *pfxFile,const char *pfxPass,EVP_PKEY *pkey)
{
	 EVP_MD_CTX     md_ctx;

   EVP_MD_CTX_init(&md_ctx);

	 FILE *     fp   = NULL;
	 X509 *     x509 = NULL;
	 PKCS12*     p12  = NULL;
	 STACK_OF(X509) *ca  = NULL;
	

	 if (!(fp = fopen(pfxFile, "rb"))) {
		    return false;
	 }
	 
	 p12 = d2i_PKCS12_fp(fp, NULL);
	 fclose (fp);
	 

	 if (!p12) {
		  fprintf(stderr, "Error reading PKCS#12 file/n");
		  ERR_print_errors_fp(stderr);
		  return false;
	 }
	 
	 if (!PKCS12_parse(p12, pfxPass, &pkey, &x509, &ca)) {
		  fprintf(stderr, "Error parsing PKCS#12 file/n");
		  ERR_print_errors_fp(stderr);
		  PKCS12_free(p12);
		  return false;
	 }


	 if (pkey == NULL) { 
		 ERR_print_errors_fp(stderr);
		 PKCS12_free(p12);	  
		 X509_free(x509);
		 return false;
	 }
	 
	    EVP_MD_CTX_cleanup(&md_ctx);
	    
	    return true;
}