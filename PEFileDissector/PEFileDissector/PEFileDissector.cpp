// PEFileDissector.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"


int AnalyzePEFile(LPCWSTR strPEFile)
{
	int nReturnValue = 0;
	HANDLE hFile = NULL;
	HANDLE hFileMapping = NULL;
	LPVOID lpFileBase = NULL;
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS ntHeader = NULL;

	hFile = CreateFile(strPEFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		nReturnValue = -1;
		return nReturnValue;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(0 == hFileMapping)
	{
		nReturnValue = -2;
		CloseHandle(hFile);
		return nReturnValue;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(0 == lpFileBase)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		nReturnValue = -3;

		return nReturnValue;
	}

	dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;

	if(dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		//This is an Exe file
		ntHeader = (PIMAGE_NT_HEADERS)dosHeader + dosHeader->e_lfanew;
		
		if(ntHeader->Signature == IMAGE_NT_SIGNATURE)
		{
		}
		else
		{
			//UnmapViewOfFile(lpFileBase);
			//CloseHandle(hFileMapping);
			//CloseHandle(hFile);
			nReturnValue = -5;

		}

		
	}
	else if(dosHeader->e_magic == 0x014C && dosHeader->e_sp == 0)
	{
		//This is an Obj File
	}
	else
	{
		//Unsupported File Format
		nReturnValue = -4;
	}

	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	
	return nReturnValue;
}