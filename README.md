# About
ELF file packer
Saves original binary execution flow
The flow:
1. Compress a whole file
2. Encrypt the blob with AES128 CBC
3. Create new ELF section in stub bin and put binary blob inside of it 

# Installation
Just *Make* it
**zlib1g-dev is required**

# Usage
Works only with 64-bits ELF bins  
Example:  
```
./viscR <binary to pack> -->
./binary_protected
```

# Todo
+ Make section less "suspicious"
+ PE, Mach-O support - Why Not
+ Packed blob encoding/ubfuscation/encryption
+ ughhhhh
