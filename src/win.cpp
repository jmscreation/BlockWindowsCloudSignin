#include "win.h"

#include <iostream>
#include <fstream>
#include <sstream>

/*
    ---------------------
    | WinAPI SID Object |
    ---------------------
*/

bool WinAPI::WinAPI_SID::updateSidInfo() {
    std::array<std::byte,1024> _buf {}; // 2K temporary memory buffer for this function
    void* buf = reinterpret_cast<void*>(_buf.data());

    DWORD szName = 512, szDomain = 512;
    char *_name, *_domain;
    {
        char* ptr = (char*)buf;
        _name = ptr; ptr += szName;
        _domain = ptr; ptr += szDomain;
        
        assert( (std::byte*)(ptr) - _buf.data() >= 0);
        assert( (std::byte*)(ptr) - _buf.data() <= _buf.size());
    }

    if (LookupAccountSid(nullptr, sid, _name, &szName, _domain, &szDomain, &type)) {
        domain = _domain;
        name = _name;
        return true;
    }
    return false;
}

bool WinAPI::WinAPI_SID::fromString(const std::string& sidStr) {
    if(ConvertStringSidToSid((LPCSTR)sidStr.c_str(), &sid)){
        return updateSidInfo();
    }
    return false;
}

std::string WinAPI::WinAPI_SID::toStringSid() const {
    std::string strSid;
    LPSTR sidbuf = NULL;
    if(ConvertSidToStringSid(sid, &sidbuf)){
        strSid.assign(sidbuf);
        LocalFree(sidbuf);
    }
    return strSid;
}

std::string WinAPI::WinAPI_SID::toString() const {
    return domain + "\\" + name;
}

/*
    ---------------------
    | WinAPI ACL Object |
    ---------------------
*/

bool WinAPI::WinAPI_ACL::modifyACL(WinAPI_SID sid, EXPLICIT_ACCESS ex_access) {

    EXPLICIT_ACCESS ea = ex_access;

    // ea.grfAccessPermissions = FILE_EXECUTE;
    // ea.grfAccessMode = DENY_ACCESS;

    // folders:
        // ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = (TRUSTEE_TYPE)sid.type;
    ea.Trustee.ptstrName = (LPSTR)sid.sid;

    PACL _newACL = NULL;
    if(SetEntriesInAcl(1, &ea, acl, &_newACL) == ERROR_SUCCESS){
        if(acl != NULL){
            LocalFree(acl);
        }
        acl = _newACL;
        return true;
    }

    return false;
}

bool WinAPI::WinAPI_ACL::loadACLFromObject(const std::string& filePath) {
    bool success = false;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL _oldACL;
    // Get current DACL
    if(GetNamedSecurityInfo(filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &_oldACL, NULL, &pSD) == ERROR_SUCCESS){
        success = SetEntriesInAcl(0, NULL, _oldACL, &acl) == ERROR_SUCCESS;
    }

    LocalFree(pSD);
    return success;
}

bool WinAPI::WinAPI_ACL::applyACLToObject(const std::string& filePath) {
    // Apply new DACL
    return SetNamedSecurityInfo( (LPSTR)filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL) == ERROR_SUCCESS;
}

bool WinAPI::WinAPI_ACL::saveACL(const std::string& filePath) const {
    ACL_SIZE_INFORMATION aclSize;
    if(!GetAclInformation(acl, &aclSize, sizeof(aclSize), AclSizeInformation)){
        std::cout << "Invalid ACL\n";
        return false;
    }
    
    std::ofstream file(filePath, std::ios::out | std::ios::binary);
    
    if(!file.is_open()){
        std::cout << "Error opening file for writing\n";
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(acl), aclSize.AclBytesInUse);

    return file.tellp() == aclSize.AclBytesInUse;
}

bool WinAPI::WinAPI_ACL::loadACL(const std::string& filePath) {
    
    std::streamsize length;
    std::ifstream file(filePath, std::ios::in | std::ios::binary | std::ios::ate);
    
    if(!file.is_open()){
        std::cout << "Error opening file for reading\n";
        return false;
    }
    length = file.tellg();
    if(length > 1024 * 16){ // 16KB is the maximum ACL file
        std::cout << "ACL file is too large!\n";
        return false;
    }

    file.seekg(0); // position to beginning of file
    
    if(acl != NULL){
        LocalFree(acl);
    }

    acl = (PACL)LocalAlloc(LMEM_FIXED, length);

    file.read(reinterpret_cast<char*>(acl), length);

    return true;
}

/*
    ---------------------
    | WinAPI Controller |
    ---------------------
*/

WinAPI::WinAPI_SID WinAPI::GetEveryoneSID() {
    WinAPI_SID everyone_sid(true); // dynamic - free after
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

    if(AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid.sid)){
        everyone_sid.updateSidInfo();
    }

    return everyone_sid;
}

WinAPI::WinAPI_SID WinAPI::GetTokenSID() {
    WinAPI_SID rSid(true);
    HANDLE hToken = NULL;
    if( OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) ){
        std::array<std::byte,512> _buf {}; // temporary memory buffer for this function
        void* buf = reinterpret_cast<void*>(_buf.data());

        DWORD cbSize;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &cbSize);

        TOKEN_USER& User = *reinterpret_cast<TOKEN_USER*>(buf);
        if( GetTokenInformation(hToken, TokenUser, &User, cbSize, &cbSize) ){
            DWORD len = GetLengthSid(User.User.Sid);
            rSid.sid = LocalAlloc(LMEM_FIXED, len);

            CopySid(len, rSid.sid, User.User.Sid);
            rSid.updateSidInfo();
        }
    }
    if( hToken ){
        CloseHandle(hToken);
    }
    return rSid;
}

bool WinAPI::IsElevated() {
    bool fRet = false;
    HANDLE hToken = NULL;
    if( OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) ){
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof( TOKEN_ELEVATION );
        if( GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize) ){
            fRet = !!Elevation.TokenIsElevated;
        }
    }
    if( hToken ) {
        CloseHandle( hToken );
    }
    return fRet;
}

bool WinAPI::EnablePrivilege(LPCSTR privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() == ERROR_SUCCESS;
}

bool WinAPI::TakeOwnership(const std::string& filePath, WinAPI_SID sid) {
    PSID User = sid.type == SidTypeUser ? sid.sid : NULL, Group = (sid.type == SidTypeGroup || sid.type == SidTypeAlias) ? sid.sid : NULL;

    return SetNamedSecurityInfo((LPSTR)filePath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, User, Group, NULL, NULL);
}

WinAPI::WinAPI_SID WinAPI::GetOwnership(const std::string& filePath) {
    WinAPI_SID rSid(true);
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID _sid = NULL;

    if(GetNamedSecurityInfo((LPCSTR)filePath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &_sid, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS &&
       _sid != NULL){

        DWORD len = GetLengthSid(_sid);
        rSid.sid = LocalAlloc(LMEM_FIXED, len);
    
        CopySid(len, rSid.sid, _sid);
        rSid.updateSidInfo();
    }

    LocalFree(pSD);

    return rSid;
}