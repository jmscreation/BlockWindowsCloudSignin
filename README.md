# Windows Account Block Cloud Sign In
## Force Block Microsoft Sign In, Cloud Sign In, and Any Email Sign In For A Window's User Account

The purpose for this application is to toggle the accessibility of the Microsoft Sign In Prompts. These are typically found via the WWAHost application. In order to block access to the sign-in prompts, there are several UWP Apps that need to be blocked. This application will find those applications and block the user from accessing them, which will block the user from adding any online account or Microsoft account.

Please note that this will also block the _"Add someone else to this PC"_ option*

## Restore Settings

To restore everything back to normal, simply re-run the program and press Y for each application to restore the ACL policies.

## The following sign in apps will be blocked:

### Access work or school
<img src="https://github.com/jmscreation/WWAHost_Disable/blob/main/github/sc1.png" />

### Sign in with a Microsoft account
<img src="https://github.com/jmscreation/WWAHost_Disable/blob/main/github/sc2.png" />

### Email and accounts
#### Add an account
#### Add a work or school account
Block all email sign in!<br/>
<img src="https://github.com/jmscreation/WWAHost_Disable/blob/main/github/sc3.png" />

### Family & other users
#### Sign in with a Microsoft account
#### Add someone else to this PC*
<img src="https://github.com/jmscreation/WWAHost_Disable/blob/main/github/sc4.png" />

_*This is part of the CloudExperienceHost package, and cannot be avoided_
