#include "StdAfx.h"
#include "JHttp.h"

static size_t RequestCallBack(void *data, size_t size, size_t nmemb, void *userp)
{
		((std::string*)userp)->append((char*)data,size * nmemb);
		return size * nmemb;

}

bool JHttp::InitAll()
{
	return CURLE_OK==curl_global_init(CURL_GLOBAL_ALL);
}

void JHttp::ClearAll()
{
	curl_global_cleanup();
}


JHttp::JHttp(void)
{
	m_curl=curl_easy_init();
	
	m_retCode=CURLE_OK;


}

JHttp::~JHttp(void)
{
  if(m_curl){
	  curl_easy_cleanup(m_curl);
    m_curl=NULL;
  }
}

bool JHttp::isOk()
{
	return CURLE_OK==m_retCode;
}


bool JHttp::isOk(CURLcode code)
{
	return CURLE_OK==code;
}

CURLcode JHttp::setParam(CURLoption option,const char *data)
{
	m_retCode=curl_easy_setopt(m_curl,option,data);

	return m_retCode;
}


CURL * JHttp::getHandle()
{
	return m_curl;
}


CURLcode JHttp::request()
{
	return m_retCode=curl_easy_perform(m_curl);
}


 CURLcode JHttp::setUrl(const char *url)
 {
   setHttps(std::string(url));

	return m_retCode=setParam(CURLOPT_URL,url);
 
 }

std::string  JHttp::HttpGet(const char * url,int timeout)
{
	std::string strBuf;

		m_retCode=setUrl(url);
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		request();
		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "";

}



std::string  JHttp::HttpGet(const char * url,HeadList heads,int timeout)
{
	  std::string strBuf;

		m_retCode=setUrl(url);

    if(heads.size()>0)
    {
      struct curl_slist* headers = NULL;
 
      HeadList::iterator it=heads.begin();
      std::string hValue="";
      for(;it!=heads.end();it++)
      {
        hValue=*it;
        headers=curl_slist_append(headers,hValue.c_str());
      }

      curl_easy_setopt(m_curl,CURLOPT_HTTPHEADER,headers);
		
    }


		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		request();
		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "";

}




std::string  JHttp::HttpPost(const char * url,const char * data,int timeout)
{
	  std::string strBuf;

		m_retCode=setUrl(url);
		
		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		

		curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE,strlen(data));
	  
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS,data);

		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		request();
		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "";

}

std::string  JHttp::HttpPost(const char * url,const char * data,HeadList heads,int timeout)
{
	  std::string strBuf;
    std::string strData=data;
  
		m_retCode=setUrl(url);
		
    if(heads.size()>0)
    {
      struct curl_slist* headers = NULL;
      
    char tmp[64]={0};
    sprintf_s(tmp,sizeof(tmp),"Content-Length:%d",strData.length());
    headers=curl_slist_append(headers, tmp);


      HeadList::iterator it=heads.begin();
      std::string hValue="";
      for(;it!=heads.end();it++)
      {
        hValue=*it;
        headers=curl_slist_append(headers,hValue.c_str());
      }

      curl_easy_setopt(m_curl,CURLOPT_HTTPHEADER,headers);
		
    }


		
    curl_easy_setopt(m_curl,CURLOPT_POST,1);
		

		curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE,strlen(data));
	  
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS,data);

		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		request();
		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "";
}

std::string JHttp::HttpPostXml(const char * url,const char * data,int timeout)
{
	  std::string strBuf;
    std::string strData=data;
  
    struct curl_slist* headers = NULL;
    
    char tmp[64]={0};

		m_retCode=setUrl(url);

    ///
    sprintf_s(tmp,sizeof(tmp),"Content-Length:%d",strData.length());
    headers=curl_slist_append(headers, tmp);
    headers=curl_slist_append(headers, "Content-Type:text/xml");
    headers=curl_slist_append(headers, "charset:utf-8");

		curl_easy_setopt(m_curl,CURLOPT_HTTPHEADER,headers);

		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
		curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE,strlen(data));
	  
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS,data);

		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		request();
		
    curl_slist_free_all(headers);


		if(isOk())
		{
			return  strBuf;
		}
		
	return "";

}



std::string JHttp::HttpPostXml(const char * url,const char * data,HeadList heads,int timeout)
{
   std::string strBuf;
    std::string strData=data;
  
    struct curl_slist* headers = NULL;
    
    char tmp[64]={0};

		m_retCode=setUrl(url);

    ///
    sprintf_s(tmp,sizeof(tmp),"Content-Length:%d",strData.length());
    headers=curl_slist_append(headers, tmp);
    headers=curl_slist_append(headers, "Content-Type:text/xml");
    headers=curl_slist_append(headers, "charset:utf-8");


      if(heads.size()>0){
      HeadList::iterator it=heads.begin();
      std::string hValue="";
      for(;it!=heads.end();it++)
      {
        hValue=*it;
        headers=curl_slist_append(headers,hValue.c_str());
      }

    }


		curl_easy_setopt(m_curl,CURLOPT_HTTPHEADER,headers);

		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
		curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE,strlen(data));
	  
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS,data);

		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		request();
		
    curl_slist_free_all(headers);


		if(isOk())
		{
			return  strBuf;
		}
		
	return "";

}

std::string  JHttp::HttpPostJson(const char * url,const char * data,int timeout)
{
    int rspcode=-200;

    return HttpPostJson(url,data,timeout,rspcode);

}

std::string  JHttp::HttpPostJson(const char * url,const char * data,int timeout,int &rspcode)
{
	  std::string strBuf;

    std::string strData=data;
  
	  struct curl_slist* headers = NULL;
    
    char tmp[64]={0};

		m_retCode=setUrl(url);
		
    sprintf_s(tmp,sizeof(tmp),"Content-Length:%d",strData.length());
   
    headers=curl_slist_append(headers, "Accept:application/json");
    headers=curl_slist_append(headers, "Content-Type:application/json");
    headers=curl_slist_append(headers, "charset:utf-8");
    headers=curl_slist_append(headers, tmp);

		curl_easy_setopt(m_curl,CURLOPT_HTTPHEADER,headers);
		
		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS,strData.c_str());

    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE,strData.length());
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);

        if(rspcode!=-200)
        {
            curl_easy_setopt(m_curl,CURLOPT_HEADER,1);  
        }
		
		request();

		curl_slist_free_all(headers);

		
		if(isOk())
		{
          	if(!isOk(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &rspcode)))
            {
                rspcode=-200;
            }

			return  strBuf;
		}
		
	return "";

}



////with head
std::string  JHttp::HttpPostJson(const char * url,const char * data,HeadList heads,int timeout){
    int rspcode=-200;

    return HttpPostJson(url,data,heads,timeout,rspcode);
}

std::string  JHttp::HttpPostJson(const char * url,const char * data,HeadList heads,int timeout,int &rspcode)
{
	std::string strBuf;

    std::string strData=std::string(data);
  
	struct curl_slist* headers = NULL;

    char tmp[64]={0};

	m_retCode=setUrl(url);
		
    sprintf_s(tmp,sizeof(tmp),"Content-Length:%d",strData.length());
    headers=curl_slist_append(headers, tmp);

    headers=curl_slist_append(headers, "Accept:application/json");
    headers=curl_slist_append(headers, "Content-Type:application/json");
    headers=curl_slist_append(headers, "charset:utf-8");

    if(heads.size()>0){
      HeadList::iterator it=heads.begin();
      std::string hValue="";
      for(;it!=heads.end();it++)
      {
        hValue=*it;
        headers=curl_slist_append(headers,hValue.c_str());
      }
    }

		curl_easy_setopt(m_curl,CURLOPT_HTTPHEADER,headers);
		
		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS,strData.c_str());

        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE,strData.length());
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);

         if(rspcode!=-200)
        {
            curl_easy_setopt(m_curl,CURLOPT_HEADER,1);  
        }
		
		request();

      

		
		curl_slist_free_all(headers);

		
		if(isOk())
		{
              if(!isOk(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &rspcode)))
              {
                    rspcode=-200;
              }
			return  strBuf;
		}
		
	return "";

}







std::string  JHttp::HttpPostForm(const char * url,KeyValueMap values,int timeout)
{
	    std::string strBuf;
	       
	    curl_httppost *form1=NULL;
	    
	    curl_httppost *form2=NULL;
	     

      if(values.size()<=0) return "NULL PARAM";
	     
      std::string tmeKey;
      std::string tmeValue;

	    for(KeyValueMap::iterator it=values.begin();it!=values.end();it++)
	    {
	      tmeKey=it->first;
        tmeValue=it->second;
	    	curl_formadd(&form1,&form2,CURLFORM_COPYNAME,tmeKey.c_str(),CURLFORM_COPYCONTENTS, tmeValue.c_str(), CURLFORM_END);
		 
	    }


    struct curl_slist*		headerlist	= NULL;

    headerlist=curl_slist_append(headerlist,"Content-Type:application/x-www-form-urlencoded");

	 curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headerlist);

		m_retCode=setUrl(url);
		
		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
		curl_easy_setopt(m_curl,CURLOPT_VERBOSE,1);   
		
		curl_easy_setopt(m_curl,CURLOPT_HEADER,1);  
    
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		curl_easy_setopt(m_curl, CURLOPT_HTTPPOST, form1);


		request();
	
		curl_formfree(form1);
		
    curl_slist_free_all(headerlist); 
		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "Fail";

}



std::string  JHttp::HttpPostForm(const char * url,KeyValueMap values,HeadList heads,int timeout)
{
	    std::string strBuf;
	       
	    curl_httppost *form1=NULL;
	    
	    curl_httppost *form2=NULL;
	     

      if(values.size()<=0) return "NULL PARAM";
	     
      std::string tmeKey;
      std::string tmeValue;

	    for(KeyValueMap::iterator it=values.begin();it!=values.end();it++)
	    {
        tmeKey=it->first;
        tmeValue=it->second;
        curl_formadd(&form1, &form2, CURLFORM_COPYNAME, tmeKey.c_str(), CURLFORM_COPYCONTENTS, tmeValue.c_str(), CURLFORM_END);

		 
	    }


    struct curl_slist*		headers	= NULL;
    
    //  headers=curl_slist_append(headers,"Content-Type:application/x-www-form-urlencoded");
    
  headers=curl_slist_append(headers,"Content-Type:multipart/form-data");

    if(heads.size()>0){
      HeadList::iterator it=heads.begin();
      std::string hValue="";
      for(;it!=heads.end();it++)
      {
        hValue=*it;
        headers=curl_slist_append(headers,hValue.c_str());
      }

    }

	 curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headers);

		m_retCode=setUrl(url);
		
		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
		curl_easy_setopt(m_curl,CURLOPT_VERBOSE,1);   
		
		curl_easy_setopt(m_curl,CURLOPT_HEADER,1);  
    
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);
		
		curl_easy_setopt(m_curl,CURLOPT_TIMEOUT,timeout);
		
		curl_easy_setopt(m_curl, CURLOPT_HTTPPOST, form1);


		request();
	
		curl_formfree(form1);
		
    curl_slist_free_all(headers); 
		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "Fail";

}





std::string  JHttp::HttpPostFile(const char * url,const char* name,const char *path,const char *type)
{
	    std::string strBuf;
	     
	    curl_httppost *form1=NULL;
	    
	    curl_httppost *form2=NULL;
	    

		curl_formadd(&form1,&form2,CURLFORM_COPYNAME,name,CURLFORM_FILE, path,CURLFORM_CONTENTTYPE,type, CURLFORM_END);
		

		m_retCode=setUrl(url);
		
		curl_easy_setopt(m_curl,CURLOPT_POST,1);
		
	//	curl_easy_setopt(m_curl,CURLOPT_VERBOSE,1);   
		
	//	curl_easy_setopt(m_curl,CURLOPT_HEADER,1);  
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEFUNCTION,RequestCallBack);
		
		
		curl_easy_setopt(m_curl,CURLOPT_WRITEDATA,&strBuf);

		curl_easy_setopt(m_curl,CURLOPT_HTTPPOST, form1);


		request();
		
		curl_formfree(form1);

		
		if(isOk())
		{
			return  strBuf;
		}
		
	return "";

}


//
//std::wstring  JHttp::AsciiToUnicode(const string &str) 
//{
//    // 预算-缓冲区中宽字节的长度  
//    int unicodeLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
//    // 给指向缓冲区的指针变量分配内存  
//    wchar_t *pUnicode = (wchar_t*)malloc(sizeof(wchar_t)*unicodeLen);
//    // 开始向缓冲区转换字节  
//    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, pUnicode, unicodeLen);
//    wstring ret_str = pUnicode;
//    free(pUnicode);
//    return ret_str;
//}
//
//std::string JHttp::UnicodeToUtf8(const wstring& wstr) 
//{
//    // 预算-缓冲区中多字节的长度  
//    int ansiiLen = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
//    // 给指向缓冲区的指针变量分配内存  
//    char *pAssii = (char*)malloc(sizeof(char)*ansiiLen);
//    // 开始向缓冲区转换字节  
//    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, pAssii, ansiiLen, nullptr, nullptr);
//    string ret_str = pAssii;
//    free(pAssii);
//    return ret_str;
//}


void  JHttp::setHttps(std::string url)
{
  if( url.find("https:")!=std::string::npos){
    curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, true);
  }
}

//
//string UTF8ToGBK(const string& strUTF8)  
//{  
//	int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8.c_str(), -1, NULL, 0);  
//	unsigned short * wszGBK = new unsigned short[len + 1];  
//	memset(wszGBK, 0, len * 2 + 2);  
//	MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)strUTF8.c_str(), -1, (LPWSTR)wszGBK, len);  
// 
//	len = WideCharToMultiByte(CP_ACP, 0, (LPWSTR)wszGBK, -1, NULL, 0, NULL, NULL);  
//	char *szGBK = new char[len + 1];  
//	memset(szGBK, 0, len + 1);  
//	WideCharToMultiByte(CP_ACP,0,(LPWSTR)wszGBK, -1, szGBK, len, NULL, NULL);  
//	//strUTF8 = szGBK;  
//	string strTemp(szGBK);  
//	delete[]szGBK;  
//	delete[]wszGBK;  
//	return strTemp;  
//}


int JHttp::HttpCheck(std::string url,int timeout)
{
      CURL *curl;
      CURLcode res;
      curl = curl_easy_init();
      if(curl)
      {
          curl_easy_setopt(curl, CURLOPT_URL,url.c_str());
          curl_easy_setopt(curl,CURLOPT_TIMEOUT,timeout);
          curl_easy_setopt(curl,CURLOPT_HEADER,1);  
          curl_easy_setopt(curl,CURLOPT_NOBODY,1);  
		
       if(url.find("https:")!=std::string::npos){
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, true);
       }

          res = curl_easy_perform(curl);

          if(res!=0)
          {
               return -1;
          }
          else{
                return 0;
          }
      }

      return -2;
}