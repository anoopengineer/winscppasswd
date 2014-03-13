WinSCP Password Extractor/Decrypter/Revealer
=============================================

WinSCP stores ssh session passwords in an encrypted format in the windows registry. If you have passwords saved in WinSCP sessions but have forgotten them, use this tool to get it back.

Steps
-----
1. Open your windows registry (you can do this by hitting Win + R and entering `regedit`)
1. Navigate to [HKEY_CURRENT_USER\\Software\\Martin Prikryl\\WinSCP 2\\Sessions] to get the hostname, username and encrypted password
1. Take a command prompt and run winscppasswd passing hostname, username and encrypted password as parameter.

```sh
winscppasswd.exe <host> <username> <encrypted_password>
```
Decrypted password will be shown on the command prompt

About
------
This utility was written to "scratch my own itch" of me constantly forgetting my saved passwords. There are couple of third party tools available that can decrypt the password, but I wasn't overly joyed at the concept of handing over my password to an unkonwn tool downloaded from the internet. So I decided to write my own.

You can download a ready made binary [here](https://github.com/anoopengineer/winscppasswd/releases/download/1.0/winscppasswd.exe) or from "Releases" section in GitHub. But you are welcome to compile the source yourself if you don't trust binary files. 

This is written in Go lang. Head over to http://golang.org/ to download the compiler.

