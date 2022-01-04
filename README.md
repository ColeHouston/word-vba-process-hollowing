# word-vba-process-hollowing
Code to perform process hollowing in a Word macro

## Usage: 
Replace the SHELLCODE_HERE variable with shellcode that has been modified by crypt.cs (or manually XOR each byte by 2 then add 7 and format the resulting numbers for the macro), then replace both instances of SHELLCODE_LENGTH with the shellcode's length. Svchost.exe may be replaced with whatever process is most suitable to hide shellcode in.

After modifying the code in macro.vb, it is ready for use in a Word macro.

Note that just copying and pasting the code will not fully evade antivirus. Defender can be bypassed by using VBA stomping (zeroing out some bytes with a hex editor). Other AV can be bypassed by doing some simple obfuscation of the variable names and strings in the macro, then using the VBA stomping technique. The following antiscan.me scan was performed on a word document that ran meterpreter reverse HTTPS shellcode using the techniques in this repo that had been obfuscated and VBA stomped: https://antiscan.me/scan/new/result?id=wXiOHYMb1HMC. **This code is meant for 64 bit versions of Microsoft Word.** 

Shoutout to Khris Tolbert for this blog post: [Yet Another Update to Bypass AMSI in VBA](https://medium.com/maverislabs/yet-another-update-to-bypass-amsi-in-vba-19ddf9065c04) which provided me the idea of using CryptBinaryToStringA as an alternative to RtlMoveMemory in a VBA AMSI bypass.
