#ifndef SYSTEMSTATISTICS_H
#define SYSTEMSTATISTICS_H

#include<Windows.h>
#include<stdio.h>
#include<string.h>
#include "Shlwapi.h"


extern "C" __declspec(dllexport) int ListFiles(char* strOption);

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