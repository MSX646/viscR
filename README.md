# About
Binary file shellcode injector.  
ELF injection based on [Silvio Cesar Text Segment padding](https://web.archive.org/web/20131008165947/http://vxheaven.org/lib/vsc01.html)  
Saves original binary execution flow

# Installation
`pip install -r requirements.txt`

# Usage
Works only with amd64 ELF bins, for now...  
Put your "*cooked*" shellcode into script (`payload` variable, between quotations mark)  
*Proper arguments handling is WIP*

# Todo
+ PE, Mach-O support
+ ARM64 support
+ Shellcode encoding/ubfuscation/encryption
+ etc. etc. etc.
