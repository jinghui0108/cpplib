#ifndef JHTTP_H
#define JHTTP_H

#include <iostream>
#include"curl.h"
#include<string>
#include <sstream>
#include<map>
#include<list>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"wldap32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")


  #ifdef USE_MTD
  #pragma comment(lib,"libcurl_mtd.lib")
  #else
  #pragma comment(lib,"libcurl_mt.lib")

  #endif

typedef std::map<std::string,std::string> KeyValueMap;
typedef std::list<std::string> HeadList;


class JHttp
{
public:
	static bool InitAll();
	static void ClearAll();
	
public:
	JHttp(void);
	~JHttp(void);
	
	bool isOk();
    bool isOk(CURLcode code);

	CURL *getHandle();
	
	CURLcode request();
	CURLcode setParam(CURLoption option,const char *data);
	
	CURLcode setUrl(const char *url);

	std::string HttpGet(const char * url,int timeout);
  std::string HttpGet(const char * url,HeadList heads,int timeout);

	std::string HttpPost(const char * url,const char * data,int timeout);
  std::string HttpPost(const char * url,const char * data,HeadList heads,int timeout);
  	std::string HttpPostJson(const char * url,const char * data,int timeout);
	std::string HttpPostJson(const char * url,const char * data,int timeout,int &rspcode);
     std::string HttpPostJson(const char * url,const char * data,HeadList heads,int timeout);
  std::string HttpPostJson(const char * url,const char * data,HeadList heads,int timeout,int &rspcode);

  std::string HttpPostXml(const char * url,const char * data,int timeout);
  std::string HttpPostXml(const char * url,const char * data,HeadList heads,int timeout);

	std::string HttpPostForm(const char * url,KeyValueMap values,int timeout);
  std::string HttpPostForm(const char * url,KeyValueMap values,HeadList heads,int timeout);

	std::string HttpPostFile(const char * url,const char* name,const char *path,const char *type);

  static int HttpCheck(std::string url,int timeout=10);
	/*
	std::wstring AsciiToUnicode(const string& str);
	std::string UnicodeToUtf8(const wstring& wstr);*/
private:
	CURLcode m_retCode;
	CURL *m_curl;
	std::string m_retStr;

  void setHttps(std::string url);
};


#endif