// Name.cpp: implementation of the CName class.
//

#include "name.h"
// #include "asn1_exception.h"
// #include "ASN1PrintableString.h"
#include "asn1/asn1_set_of.h"
#include "asn1_object_identifier.h"
#include "properties.h"

extern Properties g_mapOIDProps;

CName::CName(BufferedReader& reader) : CASN1Sequence(reader) {}

CName::CName(const CASN1Object& name) : CASN1Sequence(name) {}

std::string CName::getField(const char* fieldOID) {
  std::string strname = "";

  for (size_t i = 0; i < size(); i++) {
    CASN1SetOf element = elementAt(i);
    CASN1Sequence value = element.elementAt(0);

    if (value.elementAt(0) == CASN1ObjectIdentifier(fieldOID)) {
      CASN1Object name(value.elementAt(1));
      strname.append(reinterpret_cast<const char*>(name.getValue()->data()),
                     name.getValue()->size());
      break;
    }
  }

  return strname;
}

void CName::getNameAsString(ByteDynArray& sname) {
  LOG_DBG((0, "--> CName::getNameAsString", ""));

  int sz = size();

  // LOG_DBG((0, "CName::getNameAsString", "size: %d", sz));

  for (int i = 0; i < sz; i++)
  // for (int i = sz-1; i >= 0; i--)
  {
    // LOG_DBG((0, "CName::getNameAsString", "i: %d", i));

    CASN1SetOf element = elementAt(i);

    CASN1Sequence value = element.elementAt(0);
    ByteDynArray oid;
    ByteDynArray OID;
    CASN1ObjectIdentifier fieldOID = value.elementAt(0);
    fieldOID.ToOidString(OID);

    // LOG_DBG((0, "CName::getNameAsString", "OID: %s", OID.data()));

    const char* szOID =
        g_mapOIDProps.getProperty(reinterpret_cast<const char*>(OID.data()),
                                  reinterpret_cast<const char*>(OID.data()));

    // LOG_DBG((0, "CName::getNameAsString", "szOID: %s", szOID));

    if (value.size() > 1) {
      CASN1Object name(value.elementAt(1));
      if (sname.size() != 0) sname.push(',');

      sname.append(
          ByteArray(reinterpret_cast<const BYTE*>(szOID), strlen(szOID)));
      sname.push('=');

      sname.append(ByteArray(name.getValue()->data(), name.getLength()));

      // LOG_DBG((0, "CName::getNameAsString", "strname: %s",
      // sname.data()));
    }

    //		LOG_DBG((0, "CName::getNameAsString", "next"));
  }

  sname.push(static_cast<BYTE>('\0'));
  LOG_DBG((0, "<-- CName::getNameAsString", "%s", sname.data()));
}

/*
CName::CName(LPCTSTR lpszName)
{
        // parse the string
        char szName1[256];// = new char[strlen(lpszName)];
        char* szName = szName1;

        strcpy(szName, lpszName);

        szName = strtok(szName, "=");

        LPSTR lpszOID;
        LPSTR lpszVal;

        CAttributeValueAssertion* pAttVal;

        while(szName != nullptr)
        {
                // OID
                lpszOID = szName;
                lpszVal = strtok(nullptr, ";");

                szName = lpszVal + strlen(lpszVal) + 1;
                // Check OID
                if(stricmp(lpszOID, "CN") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_COMMON_NAME),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "O") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_ORGANIZATION_NAME),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "OU") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_ORGANIZATIONAL_UNIT_NAME),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "C") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_COUNTRY_NAME),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "email") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_EMAIL_ADDRESS),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "L") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_LOCALITY_NAME),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "S") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_STATE_OR_PROVINCE_NAME),
                                                                                         CASN1PrintableString(lpszVal));
                }
                else if(stricmp(lpszOID, "SN") == 0)
                {
                        pAttVal =
                                new
CAttributeValueAssertion(CAttributeType(CAttributeType::STR_SURNAME),
                                                                                         CASN1PrintableString(lpszVal));
                }

                CRelativeDistinguishedName relName;

                relName.addAttributeValue((*pAttVal));

                addName(relName);

                delete pAttVal;

                szName = strtok(szName, "=");
        }

        //delete[] szName1;
}

*/
/*
void CName::addName(const CRelativeDistinguishedName& name)
{
        addElement(new CRelativeDistinguishedName(name));
}
*/
CName::~CName() {}
