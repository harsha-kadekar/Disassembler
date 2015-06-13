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
}FileFolderInfo;

#endif