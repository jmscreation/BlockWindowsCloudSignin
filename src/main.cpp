#include "win.h"

#include <iostream>
#include <string>
#include <chrono>
#include <vector>
#include <thread>
#include <algorithm>


// Make a public instance of the custom windows API wrapper
static WinAPI windows;

void timeout(){
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

bool yes_or_no(){
    bool rval;
    do {
        if(GetAsyncKeyState('Y') & 0x8000) { rval = true; break; }
        if(GetAsyncKeyState('N') & 0x8000) { rval = false; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while(1);
     // wait until release
    do {
        if(rval && !(GetAsyncKeyState('Y') & 0x8000)) return true;
        if(!rval && !(GetAsyncKeyState('N') & 0x8000)) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while(1);
}

bool BlockApplication(fs::path targetPath) {
    fs::path aclPath = targetPath;
    if(fs::is_regular_file(aclPath)){
        aclPath.replace_extension(".acl");
    } else {
        aclPath = aclPath.parent_path() / (aclPath.filename().string() + ".acl");
    }

    bool restricted = true;
    
    WinAPI::WinAPI_ACL acl;

    if(!acl.loadACL(aclPath)){ // Load the ACL backup
        if(!acl.loadACLFromObject(targetPath)){ // if the backup doesn't exist, load the current ACL from the target
            std::cout << "failed to load acl from target\n";
            return false;
        }
        if(!acl.saveACL(aclPath)){ // backup the ACL to the ACL Path
            std::cout << "failed to backup acl\n";
            return false;
        }
    } else {
        std::cout << "An ACL backup was loaded.\nWould you like to restore the backup? Y/N\n";
        if(!yes_or_no()){
            std::cout << "user abort\n";
            return false;
        }

        if(!fs::remove(aclPath)){
            std::cout << "failed to remove backup acl\n";
            timeout();
        }
        restricted = false;
    }

    if(restricted){
        EXPLICIT_ACCESS ea {};
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfAccessPermissions = FILE_EXECUTE | FILE_READ_DATA;
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;

        if(!acl.modifyACL(windows.GetTokenSID(), ea)){
            std::cout << "failed to modify in-memory acl\n";
            timeout();
            return 1;
        }
    }

    if(!acl.applyACLToObject(targetPath)){
        std::cout << "failed to apply acl to target\n";
        timeout();
        return 1;
    }

    std::cout << "successfully applied acl policy\n";
    timeout();

    return true;
}


int main(int argc, char** argv) {
    
    if( !windows.IsElevated() ){
        std::cout << "Must run as Administrator\n";
        timeout();
        return false;
    }
    
    windows.EnablePrivilege(SE_RESTORE_NAME); // Gain Bypass Access To Allow Full ACL Overwrite

    std::vector<std::string> blockList {
        "Microsoft.Windows.CloudExperienceHost",
        "Microsoft.AAD.BrokerPlugin",
        "Microsoft.AccountsControl"
    };


    fs::directory_iterator it(fs::path(getenv("WINDIR")).append("SystemApps"));
    for(auto path : it){
        std::string ref = path.path().string();
        
        if(std::find_if(blockList.begin(), blockList.end(), [&ref](const auto& b){
            return ref.find(b) != std::string::npos;
        }) != blockList.end() && fs::is_directory(ref)){
            std::cout << "Block Application: " << ref << "\n";
            BlockApplication(ref);
        }
    }

    return 0;
}