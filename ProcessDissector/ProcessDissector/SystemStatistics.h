#ifndef SYSTEMSTATISTICS_H
#define SYSTEMSTATISTICS_H

#include<Windows.h>
#include<stdio.h>
#include<string.h>
#include <tlhelp32.h>
#include "Shlwapi.h"
#include "psapi.h"

#define MAX_NAME 256


extern "C" __declspec(dllexport) int ListFiles(char* strOption);
extern "C" __declspec(dllexport) int TakeProcessSnapshotOfSystem();

typedef struct structFileFolder
{
	WCHAR* strFileFolderName;
	__int64 Size;
	WCHAR* strAbsolutePath;
	WCHAR* strParent;
	WCHAR* strAlternameName;
	SYSTEMTIME* sysTimeCreation;
	SYSTEMTIME* sysTimeLastAccess;
	SYSTEMTIME* sysTimeLastWrite;
	DWORD dwAttributes;
	bool isFolder;
	bool isReadonly;
	bool isHidden;
	bool isSystem;
	bool isEncrypted;
	bool isCompressed;
	bool isArchived;
}FileFolderInfo;

int ListFilesinPath(WCHAR* strPath, WCHAR* strParentPath);
int ListFilesOfDirectory(FileFolderInfo* folderInfo);
FileFolderInfo* GetFolderFileInfo();
int CleanUpFolderFileInfo(FileFolderInfo* folderInfo);
bool IsFile(WCHAR* strFileFolder);
SYSTEMTIME* GetSystemTimeFromFileTimeCustom(FILETIME ftTime);
WCHAR* GetDateTimeStringFromSystemTime(SYSTEMTIME* sysTime, WCHAR* strDateTime);

#endif