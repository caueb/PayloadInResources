# PayloadInResources
This is a POC based on the research done by [White Knight Labs](https://github.com/WKL-Sec).

- Sandbox bypass checking if name of the executable is in the path.
- Store/fetch the shellcode in resources and XOR encrypt/decrypt it.
- Using unconventional method for process injection.
The above is capable of bypassing AV(I tested against Defender), possibly some EDRs.

# Usage
1. XOR encrypt the raw shellcode using the `xorencrypt.py`:
```powershell
# python .\xorencrypt.py <payload_file> <output_file> <xor_key>
python .\xorencrypt.py .\calc.bin encrypted.bin ABCD
```
2. Modify the `metadata.rc` to reflect the `<output_file>` name:
```powershell
SHELLCODE_RESOURCE RCDATA "encrypted.bin"
```
3. Compile the `metadata.rc` to `.res`:
```powershell
rc.exe /r /fo .\metadata.res .\metadata.rc
```
4. Modify the `Caue.cpp` line 52 with the XOR key you used and compile with clang++:
```powershell
clang++.exe -O2 -Ob2 -Os -fno-stack-protector -g -Xlinker -pdb:none -Xlinker -subsystem:console -o Caue.exe Caue.cpp metadata.res -luser32 -lkernel32 -fno-unroll-loops -fno-exceptions -fno-rtti
```

# Credits
- [Tales of AV/EDR Bypass - Double Feature w/ Greg Hatcher & John Stigerwalt](https://www.youtube.com/watch?v=Qo27gQK725g)
- [GregsBestFriend](https://github.com/WKL-Sec/GregsBestFriend)
