# word-vba-process-hollowing
Code to perform process hollowing in a Word macro

Replace the SHELLCODE_HERE variable with shellcode that has been modified by crypt.cs (or manually XOR each byte by 2 then add 7 and format the resulting numbers for the macro), then replace both instances of SHELLCODE_LENGTH with the shellcode's length. Svchost.exe may be replaced with whatever process is most suitable to hide shellcode in.
