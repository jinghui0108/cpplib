#ifndef JSON_JSON_H_INCLUDED
# define JSON_JSON_H_INCLUDED

# include "autolink.h"
# include "value.h"
# include "reader.h"
# include "writer.h"
# include "features.h"


//////////////////////////////////////////////Add by yjh
typedef Json::Value JsonValue;

typedef Json::FastWriter JsonWriter;
typedef Json::StyledWriter JsonStyleWriter;

typedef Json::Reader JsonReader;

#define JNull  Json::nullValue
#define JInt  Json::intValue
#define JUint  Json::uintValue
#define JDouble  Json::realValue
#define JString  Json::stringValue
#define JBool  Json::booleanValue
#define JArray  Json::arrayValue
#define JObject  Json::objectValue
///////////////////////////////////////////Add by yjh
#endif // JSON_JSON_H_INCLUDED
