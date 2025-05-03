#include "win.h"

#include <iostream>
#include <filesystem>
#include <string>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

// Make a public instance of the custom windows API wrapper
static WinAPI windows;

void timeout(){
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

int main(int argc, char** argv) {

    std::string targetPath = "C:\\Windows\\System32\\WWAHost.exe";
    std::string aclPath = "C:\\Windows\\System32\\WWAHOST.acl";

    bool restricted = true;

    if( !windows.IsElevated() ){
        std::cout << "Must run as Administrator\n";
        timeout();
        return 1;
    }
    windows.EnablePrivilege(SE_RESTORE_NAME); // Gain Bypass Access To Allow Full ACL Overwrite
    
    WinAPI::WinAPI_ACL acl;

    if(!acl.loadACL(aclPath)){ // Load the ACL backup
        if(!acl.loadACLFromObject(targetPath)){ // if the backup doesn't exist, load the current ACL from the target
            std::cout << "failed to load acl from target\n";
            return 1;
        }
        if(!acl.saveACL(aclPath)){ // backup the ACL to the ACL Path
            std::cout << "failed to backup acl\n";
            return 1;
        }
    } else {
        std::cout << "An ACL backup was loaded.\nWould you like to restore the backup? Y/N\n";
        do {
            if(GetAsyncKeyState('Y') & 0x8000){
                break;
            }
            if(GetAsyncKeyState('N') & 0x8000){
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } while(1);

        if(!fs::remove(aclPath)){
            std::cout << "failed to remove backup acl\n";
            timeout();
        }
        restricted = false;
    }

    if(restricted){
        EXPLICIT_ACCESS ea {};
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfAccessPermissions = FILE_EXECUTE;
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
    return 0;
}