#ifndef JSIGN_H

#define JSIGN_H

#include<string>

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/objects.h"
#include "openssl/ssl.h"

#pragma comment(lib,"libeay32_mt.lib")

#pragma comment(lib,"ssleay32_mt.lib")

class JAlgo
{
public:
  JAlgo();
private:
   std::string Hash(const char *data,int type,bool upper=false);
public:
   RSA* LoadRSAKeyFile(char* in_szKeyPath,bool ispri);
  RSA* LoadKeyFile(char* in_szKeyPath,bool ispri);
   RSA* ReadPrivateKey(char* in_szKeyPath);
  
   bool Sign_ShaWithRSA(unsigned char *data,unsigned int len,unsigned char *ret,unsigned int *retLen,RSA *rsa,int type);

   bool Verify_ShaWithRSA(unsigned char *data,unsigned int len,unsigned char *sig,unsigned int sigLen,RSA *rsa,int type);


   bool MakePublicKey(RSA *rsa,const char *name);
  
   RSA* MakeAndLoadPublicKey(RSA *rsa,const char *name);


   RSA *MakePrivateKey(const char * name,int keyLen=256);
  
   int MakeKeyPair(const char * pubKey,const char * priKey,int keyLen=2048);
  
  
   std::string Md5(const char *data,bool upper=false);

   char * Char2Hex(unsigned char*data,int len,int &length,bool uppe=false);
   char * Hex2Char(const char*data,int len,int &length);
   bool Char2Hex_Ex(unsigned char*data,int len,char*buf,bool upper=false);

   std::string Sha1(const char *data,bool upper=false);
   std::string Sha224(const char *data,bool upper=false);
   std::string Sha256(const char *data,bool upper=false);
   std::string Sha384(const char *data,bool upper=false);
   std::string Sha512(const char *data,bool upper=false);
  
  
   std::string FromBase64(const char *input,bool newLine=false);
   std::string ToBase64(const char *buffer,bool newLine=false);
    std::string ToBase64(unsigned char *buffer,int bufLen,bool newLine=false);
   std::string FromBase64(unsigned char *buffer,int bufLen,bool newLine=false);
    char *JAlgo::FromBase64(const char *input,int inLen,int &outLen,bool newLine=false);

 public:
   std::string UrlEncode(const char * strIn);
   std::string UrlDecode(const char *strIn);
  
  
 
  unsigned char* Rsa_Encode(unsigned char*data,int dataLen,RSA *rsa,int &len,bool isPri=true);
  unsigned char* Rsa_Decode(unsigned char*data,int dataLen,RSA *rsa,int &len,bool isPri=true);
  
   RSA* LoadKeyBuf(unsigned char *key,bool isPri);   
  
  
   std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey);
  
  
   std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey);

   bool PFX_ShaSign(const char* szPKCS12FileName, const char* szPKCS12Password, 
    unsigned char* szUnSignData,int unSigneLen,char* szSignData,int *szSignLen,int sign_Type=256);
   
   bool PFX_ShaSign_Str(const char* szPKCS12FileName, const char* szPKCS12Password, 
    const char* szUnSignData,char* szSignData,int *szSignLen,int sign_Type);

   bool PFX_ShaVerify(const char* szPKCS12FileName, const char* szPKCS12Password, 
     const char* szUnSignData, const char* szSignData,int sign_Type=256);
  
   bool PFX_Sign2(const char *szPKCS12FileName,const char *szPKCS12Password,unsigned char *msg,size_t msgLen,char **buf,size_t &bufLen);


  ///des
public:
   std::string Des_ECB_Encode(const char *data,const char * key);
 //  std::string Des_CBC_Encode(const char *data,const char *key,const char *iv);
  // std::string Des_CBC_Decode(const char *data,const char *key,const char *iv);

	 unsigned char * Des_CBC_Decode(const char *key, const char *iv,const char *data,size_t dataLen
    , size_t &deDataLen,int mode=1);
    
     unsigned char * Des_CBC_Encode(const char *key, const char *ivBuf,const char *data,size_t dataLen
  , size_t &enDataLen,int mode=1) ;
 
  EVP_PKEY*LoadEVPKey(const char *file);

  bool LoadKeyFromPFX(const char *pfxFile,const char *pfxPass,EVP_PKEY *pkey);

};
#endif
