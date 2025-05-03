#undef UNICODE

#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h> // for ConvertStringSidToSid

#include <string>
#include <iostream>
#include <array>
#include <cassert>

class WinAPI {
public:
    struct WinAPI_SID {
        PSID sid;
        SID_NAME_USE type;
        std::string domain, name;

        std::string toStringSid() const;
        std::string toString() const;
        bool fromString(const std::string& sidStr);
        bool updateSidInfo();

        WinAPI_SID(bool _dyn=false): sid(NULL), type(SidTypeInvalid), domain({}), name({}), _dyn(_dyn) {}
        ~WinAPI_SID() {
            if(_dyn && sid != NULL){
                FreeSid(sid);
            }
        }

    private:
        bool _dyn;
    };

    struct WinAPI_ACL {
        PACL acl;
        
        bool loadACL(const std::string& filePath);
        bool saveACL(const std::string& filePath) const;

        bool modifyACL(WinAPI_SID sid, EXPLICIT_ACCESS ex_access); // update the new ACL with new permissions - overwrites the acl except for the origin acl
        
        bool loadACLFromObject(const std::string& filePath); // load the origin acl from an object
        bool applyACLToObject(const std::string& filePath); // apply the current ACL on an object

        WinAPI_ACL(): acl(NULL) {}
        ~WinAPI_ACL() {
            if(acl != NULL){
                LocalFree(acl);
            }
        }
    };

    WinAPI_SID GetEveryoneSID();
    WinAPI_SID GetTokenSID();

    bool EnablePrivilege(LPCSTR privilegeName);

    bool TakeOwnership(const std::string& filePath, WinAPI_SID sid);
    WinAPI_SID GetOwnership(const std::string& filePath);

    bool IsElevated();

};