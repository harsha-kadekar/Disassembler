#include "SystemStatistics.h"


/*
*Name: ListFiles
*Description: This will list all the files in the system. If path is given then it will list all those files within that path.
*Parameters: strOption - ALL -> list all the files of the system. Else path from where files needs to be displayed
*ReturnValue: 0 for success else error
*/
int ListFiles(char* strOption)
{
	int nReturnValue = 0;
	WCHAR strFILEFOLDER[MAX_PATH] = {0};
	size_t sizeNumberOfConverted = 0;
	DWORD dwSize = MAX_PATH;
	WCHAR szLogicalDrives[MAX_PATH] = {0};
	WCHAR szExtra[MAX_PATH] = L"*";
	WCHAR szDrive[MAX_PATH] = {0};
	WCHAR szPath[MAX_PATH] = {0};
	DWORD dwResult = 0;

	if(NULL == strOption)
	{
		//Error nothing is specified in the strOption
		nReturnValue = -1;
		return nReturnValue;
	}

	if(0 == strcmp(strOption, "ALL"))
	{
		//List all the files in the system

		//List all the physical drives in the system
		
		dwResult = GetLogicalDriveStrings(dwSize,szLogicalDrives);

		if (dwResult > 0 && dwResult <= MAX_PATH)
		{
			WCHAR* szSingleDrive = szLogicalDrives;
			while(*szSingleDrive)
			{
				wprintf(L"\nDrive: %s\n", szSingleDrive);

					// get the next drive
				
				wsprintf(szDrive, L"%s%s", szSingleDrive, szExtra); 

				wprintf(L"\n\nName\tAbsolute Path\tParent Folder\tAlternate Name\tFolder Or File\tIsHidden\tIsReadonly\tIsSystem File or Folder\tIsArchieved\tIsCompressed\tIsEncrypted\tAttributesValue\tCreationTime\tLast Access Time\tLast Write Time\tSize\n");
				nReturnValue = ListFilesinPath(szDrive, szSingleDrive);
				if(0 != nReturnValue)
				{
					//Error - Abort
					wprintf(L"\nERROR::Some error has occurred - so aborting the listing of files\n");
					break;
				}

				szSingleDrive += wcslen(szSingleDrive) + 1;
			}
		} 
	}
	else
	{
		//List the files as given by the path - strOption
		memset(strFILEFOLDER, '\0', MAX_PATH);
		mbstowcs_s(&sizeNumberOfConverted, strFILEFOLDER, MAX_PATH, strOption, _TRUNCATE);
		if(IsFile(strFILEFOLDER))
		{
			//File
			WCHAR* pdest = wcsrchr(strFILEFOLDER, '\\');
			int nIndex = (int)(pdest - strFILEFOLDER + 1);
			if(pdest != NULL)
			{
				wcsncpy_s(szPath, strFILEFOLDER, nIndex);
				wprintf(L"\n\nName\tAbsolute Path\tParent Folder\tAlternate Name\tFolder Or File\tIsHidden\tIsReadonly\tIsSystem File or Folder\tIsArchieved\tIsCompressed\tIsEncrypted\tAttributesValue\tCreationTime\tLast Access Time\tLast Write Time\tSize\n");
				nReturnValue = ListFilesinPath(strFILEFOLDER, szPath);
				if(0 != nReturnValue)
				{
					//Error - Abort
					wprintf(L"\nERROR::Some error has occurred - so aborting the listing of files\n");
				}

			}

		}
		else
		{
			//Folder
			if(strOption[strlen(strOption)-1] == '\\')
			{
				wsprintf(szPath, L"%s%s", strFILEFOLDER, szExtra);
				
				
			}
			else
			{
				wsprintf(szPath, L"%s\\%s", strFILEFOLDER, szExtra);
				wsprintf(strFILEFOLDER, L"%s\\", strFILEFOLDER);
			}

			wprintf(L"\n\nName\tAbsolute Path\tParent Folder\tAlternate Name\tFolder Or File\tIsHidden\tIsReadonly\tIsSystem File or Folder\tIsArchieved\tIsCompressed\tIsEncrypted\tAttributesValue\tCreationTime\tLast Access Time\tLast Write Time\tSize\n");
			nReturnValue = ListFilesinPath(szPath, strFILEFOLDER);
			if(0 != nReturnValue)
			{
				//Error - Abort
				wprintf(L"\nERROR::Some error has occurred - so aborting the listing of files\n");
			}
			//wsprintf(szDrive, L"%s%s", szSingleDrive, szExtra);
		}

	}

	return nReturnValue;
}


/*
*Name: ListFilesinPath
*Description: This will list all the files present inside that path. Also it will give information about that path.
*Parameters: strPath - Path whose information has to be listed. All the files and folders inside that will also be displayed
*ReturnValue: 0 for success else error
*/
int ListFilesinPath(WCHAR* strPath, WCHAR* strParentPath)
{
	int nReturnValue = 0;
	HANDLE hFind = NULL;
	WIN32_FIND_DATA FindFileData;
	LARGE_INTEGER filesize = {0};
	LARGE_INTEGER tempfilesize = {0};
	WCHAR strFullPath[MAX_PATH] = {0};
	WCHAR strToBeSent[MAX_PATH] = {0};
	WCHAR strCreationDateTime[25] = {0};
	WCHAR strAccessDateTime[25] = {0};
	WCHAR strWriteDateTime[25] = {0};

	FileFolderInfo *fileInfo = NULL;
	FileFolderInfo *folderInfo = NULL;

	SYSTEMTIME* ptrSysTimeTemp = NULL;

	if(NULL == strPath)
	{
		//No path is passed
		wprintf(L"ERROR::No path has been passed\n");
		nReturnValue = -1;
		return nReturnValue;
	}

	/*if(TRUE != PathFileExists(strPath))
	{
		wprintf(L"ERROR::File or Folder doesnot exists = %s", strPath);
		nReturnValue = -3;
		return nReturnValue;
	}*/

	
		 
	hFind = FindFirstFile(strPath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFind)
	{

		do
		{
			if((0 == wcscmp(FindFileData.cFileName, L"."))||(0 == wcscmp(FindFileData.cFileName, L"..")))
			{
				continue;
			}

			if(FILE_ATTRIBUTE_DIRECTORY ==  (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				folderInfo = GetFolderFileInfo();

				

				wsprintf(strFullPath,L"%s%s", strParentPath, FindFileData.cFileName);

				folderInfo->strAbsolutePath = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(strFullPath)+1));
				memset(folderInfo->strAbsolutePath, L'\0', wcslen(strFullPath)+1);
				wcscpy(folderInfo->strAbsolutePath, strFullPath);

				folderInfo->strFileFolderName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cFileName)+1));
				memset(folderInfo->strFileFolderName, L'\0', wcslen(FindFileData.cFileName)+1);
				wcscpy(folderInfo->strFileFolderName, FindFileData.cFileName);

				folderInfo->strParent = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(strParentPath)+1));
				memset(folderInfo->strParent, L'\0', wcslen(strParentPath)+1);
				wcscpy(folderInfo->strParent, strParentPath);

				if(FindFileData.cAlternateFileName != NULL && (0 != wcscmp(FindFileData.cAlternateFileName, L"")))
				{
					folderInfo->strAlternameName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cAlternateFileName)+1));
					memset(folderInfo->strAlternameName, L'\0', wcslen(FindFileData.cAlternateFileName)+1);
					wcscpy(folderInfo->strAlternameName, FindFileData.cAlternateFileName);
				}

				folderInfo->isFolder = true;

				folderInfo->dwAttributes = FindFileData.dwFileAttributes;

				if(FILE_ATTRIBUTE_HIDDEN == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN))
				{
					folderInfo->isHidden = true;
				}

				if(FILE_ATTRIBUTE_READONLY == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
				{
					folderInfo->isReadonly = true;
				}

				if(FILE_ATTRIBUTE_SYSTEM == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
				{
					folderInfo->isSystem = true;
				}

				if(FILE_ATTRIBUTE_ARCHIVE == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE))
				{
					folderInfo->isArchived = true;
				}

				if(FILE_ATTRIBUTE_COMPRESSED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED))
				{
					folderInfo->isCompressed = true;
				}

				if(FILE_ATTRIBUTE_ENCRYPTED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED))
				{
					folderInfo->isEncrypted = true;
				}

				folderInfo->sysTimeCreation = GetSystemTimeFromFileTimeCustom(FindFileData.ftCreationTime);
				folderInfo->sysTimeLastAccess = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastAccessTime);
				folderInfo->sysTimeLastWrite = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastWriteTime);

				ListFilesOfDirectory(folderInfo);

				wprintf(L"%s\t%s\t%s\t%s\tFOLDER\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%u\n", 
					folderInfo->strFileFolderName, 
					folderInfo->strAbsolutePath, 
					folderInfo->strParent,
					folderInfo->strAlternameName == NULL?L"":folderInfo->strAlternameName,
					folderInfo->isHidden?L"HIDDEN":L"DISPLAYED", 
					folderInfo->isReadonly?L"READ_ONLY":L"NOT_READ_ONLY", 
					folderInfo->isSystem?L"SYSTEM":L"NORMAL",
					folderInfo->isArchived?L"ARCHIEVED":L"NOT_ARCHIEVED",
					folderInfo->isCompressed?L"COMPRESSED":L"NOT_COMPRESSED",
					folderInfo->isEncrypted?L"ENCRYPTED":L"NOT_ENCRYPTED",
					folderInfo->dwAttributes,
					GetDateTimeStringFromSystemTime(folderInfo->sysTimeCreation, strCreationDateTime),
					GetDateTimeStringFromSystemTime(folderInfo->sysTimeLastAccess, strAccessDateTime),
					GetDateTimeStringFromSystemTime(folderInfo->sysTimeLastWrite, strWriteDateTime),
					folderInfo->Size);
								
				tempfilesize.QuadPart += folderInfo->Size;

				CleanUpFolderFileInfo(folderInfo);
				folderInfo = NULL;

			}
			else
			{
				fileInfo = GetFolderFileInfo();

				wsprintf(strFullPath,L"%s%s", strParentPath, FindFileData.cFileName);

				fileInfo->strAbsolutePath = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(strFullPath)+1));
				memset(fileInfo->strAbsolutePath, L'\0', wcslen(strFullPath)+1);
				wcscpy(fileInfo->strAbsolutePath, strFullPath);

				fileInfo->strFileFolderName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cFileName)+1));
				memset(fileInfo->strFileFolderName, L'\0', wcslen(FindFileData.cFileName)+1);
				wcscpy(fileInfo->strFileFolderName, FindFileData.cFileName);

				fileInfo->strParent = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(strParentPath)+1));
				memset(fileInfo->strParent, L'\0', wcslen(strParentPath)+1);
				wcscpy(fileInfo->strParent, strParentPath);

				if(FindFileData.cAlternateFileName != NULL && (0 != wcscmp(FindFileData.cAlternateFileName, L"")))
				{
					fileInfo->strAlternameName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cAlternateFileName)+1));
					memset(fileInfo->strAlternameName, L'\0', wcslen(FindFileData.cAlternateFileName)+1);
					wcscpy(fileInfo->strAlternameName, FindFileData.cAlternateFileName);
				}

				fileInfo->isFolder = false;

				fileInfo->dwAttributes = FindFileData.dwFileAttributes;

				if(FILE_ATTRIBUTE_HIDDEN == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN))
				{
					fileInfo->isHidden = true;
				}

				if(FILE_ATTRIBUTE_READONLY == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
				{
					fileInfo->isReadonly = true;
				}

				if(FILE_ATTRIBUTE_SYSTEM == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
				{
					fileInfo->isSystem = true;
				}

				if(FILE_ATTRIBUTE_ARCHIVE == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE))
				{
					fileInfo->isArchived = true;
				}

				if(FILE_ATTRIBUTE_COMPRESSED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED))
				{
					fileInfo->isCompressed = true;
				}

				if(FILE_ATTRIBUTE_ENCRYPTED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED))
				{
					fileInfo->isEncrypted = true;
				}

				fileInfo->sysTimeCreation = GetSystemTimeFromFileTimeCustom(FindFileData.ftCreationTime);
				fileInfo->sysTimeLastAccess = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastAccessTime);
				fileInfo->sysTimeLastWrite = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastWriteTime);

				filesize.HighPart = FindFileData.nFileSizeHigh;
				filesize.LowPart = FindFileData.nFileSizeLow;

				fileInfo->Size = filesize.QuadPart;

				//wsprintf(strFullPath,L"%s%s", strParentPath, FindFileData.cFileName);

				wprintf(L"%s\t%s\t%s\t%s\tFILE\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%u\n", 
					fileInfo->strFileFolderName, 
					fileInfo->strAbsolutePath, 
					fileInfo->strParent,
					fileInfo->strAlternameName == NULL?L"":fileInfo->strAlternameName,
					fileInfo->isHidden?L"HIDDEN":L"DISPLAYED", 
					fileInfo->isReadonly?L"READ_ONLY":L"NOT_READ_ONLY", 
					fileInfo->isSystem?L"SYSTEM":L"NORMAL",
					fileInfo->isArchived?L"ARCHIEVED":L"NOT_ARCHIEVED",
					fileInfo->isCompressed?L"COMPRESSED":L"NOT_COMPRESSED",
					fileInfo->isEncrypted?L"ENCRYPTED":L"NOT_ENCRYPTED",
					fileInfo->dwAttributes,
					GetDateTimeStringFromSystemTime(fileInfo->sysTimeCreation, strCreationDateTime),
					GetDateTimeStringFromSystemTime(fileInfo->sysTimeLastAccess, strAccessDateTime),
					GetDateTimeStringFromSystemTime(fileInfo->sysTimeLastWrite, strWriteDateTime),
					fileInfo->Size);

				tempfilesize.QuadPart += filesize.QuadPart;

				CleanUpFolderFileInfo(fileInfo);
				fileInfo = NULL;

			}

					
		}
		while (FindNextFile(hFind, &FindFileData) != 0);

		wprintf(L"%s\t%u\n", strPath, tempfilesize.QuadPart);

	}	 //CloseHandle(hFind);
	else
	{
		 
		//Error not able to find the file's information
		wprintf(L"\nERROR:: Not able to get File's or Folder's information:%s\n", strPath);
		nReturnValue = -2;

		return nReturnValue;
	}
		
	return nReturnValue;
}


/*
*Name: ListFilesOfDirectory
*Description: This will help to list all the files. This is a recurrsive function.
*Parameter: folderInfo - Folder whose files and child folders needs to be parsed and info needs to be put.
*ReturnValue: 0 for no error else error
*/
int ListFilesOfDirectory(FileFolderInfo* folderInfo)
{
	int nReturnValue = 0;
	HANDLE hFind = NULL;
	WIN32_FIND_DATA FindFileData;
	LARGE_INTEGER filesize = {0};
	LARGE_INTEGER tempfilesize = {0};
	WCHAR strFullPath[MAX_PATH] = {0};
	WCHAR strToBeSent[MAX_PATH] = {0};
	WCHAR strCreationDateTime[25] = {0};
	WCHAR strAccessDateTime[25] = {0};
	WCHAR strWriteDateTime[25] = {0};

	FileFolderInfo *newFolderInfo = NULL;
	//FileFolderInfo *folderInfo = NULL;
	FileFolderInfo *fileInfo = NULL;

	if(NULL == folderInfo->strAbsolutePath)
	{
		//No path is passed
		wprintf(L"ERROR::No path has been passed\n");
		nReturnValue = -1;
		return nReturnValue;
	}

	/*if(TRUE != PathFileExists(folderInfo->strAbsolutePath))
	{
		wprintf(L"ERROR::File or Folder doesnot exists = %s", folderInfo->strAbsolutePath);
		nReturnValue = -3;
		return nReturnValue;
	}*/

	wsprintf(strToBeSent, L"%s\\*", folderInfo->strAbsolutePath);

	hFind = FindFirstFile(strToBeSent, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFind)
	{
		

			do
			{	
				if((0 == wcscmp(FindFileData.cFileName, L"."))||(0 == wcscmp(FindFileData.cFileName, L"..")))
				{
					continue;
				}

				
				if(FILE_ATTRIBUTE_DIRECTORY ==  (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				{
					newFolderInfo = GetFolderFileInfo();

					wsprintf(strFullPath,L"%s\\%s", folderInfo->strAbsolutePath, FindFileData.cFileName);
					
					newFolderInfo->strAbsolutePath = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(strFullPath)+1));
					memset(newFolderInfo->strAbsolutePath, L'\0', wcslen(strFullPath)+1);
					wcscpy(newFolderInfo->strAbsolutePath, strFullPath);

					newFolderInfo->strFileFolderName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cFileName)+1));
					memset(newFolderInfo->strFileFolderName, L'\0', wcslen(FindFileData.cFileName)+1);
					wcscpy(newFolderInfo->strFileFolderName, FindFileData.cFileName);

					newFolderInfo->strParent = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(folderInfo->strAbsolutePath)+1));
					memset(newFolderInfo->strParent, L'\0', wcslen(folderInfo->strAbsolutePath)+1);
					wcscpy(newFolderInfo->strParent, folderInfo->strAbsolutePath);

					if(FindFileData.cAlternateFileName != NULL && (0 != wcscmp(FindFileData.cAlternateFileName, L"")))
					{
						newFolderInfo->strAlternameName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cAlternateFileName)+1));
						memset(newFolderInfo->strAlternameName, L'\0', wcslen(FindFileData.cAlternateFileName)+1);
						wcscpy(newFolderInfo->strAlternameName, FindFileData.cAlternateFileName);
					}
					
					newFolderInfo->isFolder = true;

					newFolderInfo->dwAttributes = FindFileData.dwFileAttributes;

					if(FILE_ATTRIBUTE_HIDDEN == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN))
					{
						newFolderInfo->isHidden = true;
					}

					if(FILE_ATTRIBUTE_READONLY == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
					{
						newFolderInfo->isReadonly = true;
					}

					if(FILE_ATTRIBUTE_SYSTEM == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
					{
						newFolderInfo->isSystem = true;
					}

					if(FILE_ATTRIBUTE_ARCHIVE == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE))
					{
						newFolderInfo->isArchived = true;
					}

					if(FILE_ATTRIBUTE_COMPRESSED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED))
					{
						newFolderInfo->isCompressed = true;
					}

					if(FILE_ATTRIBUTE_ENCRYPTED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED))
					{
						newFolderInfo->isEncrypted = true;
					}

					newFolderInfo->sysTimeCreation = GetSystemTimeFromFileTimeCustom(FindFileData.ftCreationTime);
					newFolderInfo->sysTimeLastAccess = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastAccessTime);
					newFolderInfo->sysTimeLastWrite = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastWriteTime);

					ListFilesOfDirectory(newFolderInfo);

					wprintf(L"%s\t%s\t%s\t%s\tFOLDER\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%u\n", 
						newFolderInfo->strFileFolderName, 
						newFolderInfo->strAbsolutePath, 
						newFolderInfo->strParent,
						newFolderInfo->strAlternameName == NULL?L"":newFolderInfo->strAlternameName,
						newFolderInfo->isHidden?L"HIDDEN":L"DISPLAYED", 
						newFolderInfo->isReadonly?L"READ_ONLY":L"NOT_READ_ONLY", 
						newFolderInfo->isSystem?L"SYSTEM":L"NORMAL",
						newFolderInfo->isArchived?L"ARCHIEVED":L"NOT_ARCHIEVED",
						newFolderInfo->isCompressed?L"COMPRESSED":L"NOT_COMPRESSED",
						newFolderInfo->isEncrypted?L"ENCRYPTED":L"NOT_ENCRYPTED",
						newFolderInfo->dwAttributes,
						GetDateTimeStringFromSystemTime(newFolderInfo->sysTimeCreation, strCreationDateTime),
						GetDateTimeStringFromSystemTime(newFolderInfo->sysTimeLastAccess, strAccessDateTime),
						GetDateTimeStringFromSystemTime(newFolderInfo->sysTimeLastWrite, strWriteDateTime),
						newFolderInfo->Size);

					tempfilesize.QuadPart += newFolderInfo->Size;

					CleanUpFolderFileInfo(newFolderInfo);
					newFolderInfo = NULL;
					
				}
				else
				{
					fileInfo = GetFolderFileInfo();

					wsprintf(strFullPath,L"%s\\%s", folderInfo->strAbsolutePath, FindFileData.cFileName);

					fileInfo->strAbsolutePath = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(strFullPath)+1));
					memset(fileInfo->strAbsolutePath, L'\0', wcslen(strFullPath)+1);
					wcscpy(fileInfo->strAbsolutePath, strFullPath);

					fileInfo->strFileFolderName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cFileName)+1));
					memset(fileInfo->strFileFolderName, L'\0', wcslen(FindFileData.cFileName)+1);
					wcscpy(fileInfo->strFileFolderName, FindFileData.cFileName);

					fileInfo->strParent = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(folderInfo->strAbsolutePath)+1));
					memset(fileInfo->strParent, L'\0', wcslen(folderInfo->strAbsolutePath)+1);
					wcscpy(fileInfo->strParent, folderInfo->strAbsolutePath);

					if(FindFileData.cAlternateFileName != NULL && (0 != wcscmp(FindFileData.cAlternateFileName, L"")))
					{
						fileInfo->strAlternameName = (WCHAR*)malloc(sizeof(WCHAR)*(wcslen(FindFileData.cAlternateFileName)+1));
						memset(fileInfo->strAlternameName, L'\0', wcslen(FindFileData.cAlternateFileName)+1);
						wcscpy(fileInfo->strAlternameName, FindFileData.cAlternateFileName);
					}

					fileInfo->isFolder = false;

					fileInfo->dwAttributes = FindFileData.dwFileAttributes;

					if(FILE_ATTRIBUTE_HIDDEN == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN))
					{
						fileInfo->isHidden = true;
					}

					if(FILE_ATTRIBUTE_READONLY == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
					{
						fileInfo->isReadonly = true;
					}

					if(FILE_ATTRIBUTE_SYSTEM == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
					{
						fileInfo->isSystem = true;
					}

					if(FILE_ATTRIBUTE_ARCHIVE == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE))
					{
						fileInfo->isArchived = true;
					}

					if(FILE_ATTRIBUTE_COMPRESSED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED))
					{
						fileInfo->isCompressed = true;
					}

					if(FILE_ATTRIBUTE_ENCRYPTED == (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED))
					{
						fileInfo->isEncrypted = true;
					}

					fileInfo->sysTimeCreation = GetSystemTimeFromFileTimeCustom(FindFileData.ftCreationTime);
					fileInfo->sysTimeLastAccess = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastAccessTime);
					fileInfo->sysTimeLastWrite = GetSystemTimeFromFileTimeCustom(FindFileData.ftLastWriteTime);

					filesize.HighPart = FindFileData.nFileSizeHigh;
					filesize.LowPart = FindFileData.nFileSizeLow;

					fileInfo->Size = filesize.QuadPart;

					//wsprintf(strFullPath,L"%s%s", strParentPath, FindFileData.cFileName);

					wprintf(L"%s\t%s\t%s\t%s\tFILE\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%u\n", 
						fileInfo->strFileFolderName, 
						fileInfo->strAbsolutePath, 
						fileInfo->strParent,
						fileInfo->strAlternameName == NULL?L"":fileInfo->strAlternameName,
						fileInfo->isHidden?L"HIDDEN":L"DISPLAYED", 
						fileInfo->isReadonly?L"READ_ONLY":L"NOT_READ_ONLY", 
						fileInfo->isSystem?L"SYSTEM":L"NORMAL",
						fileInfo->isArchived?L"ARCHIEVED":L"NOT_ARCHIEVED",
						fileInfo->isCompressed?L"COMPRESSED":L"NOT_COMPRESSED",
						fileInfo->isEncrypted?L"ENCRYPTED":L"NOT_ENCRYPTED",
						fileInfo->dwAttributes,
						GetDateTimeStringFromSystemTime(fileInfo->sysTimeCreation, strCreationDateTime),
						GetDateTimeStringFromSystemTime(fileInfo->sysTimeLastAccess, strAccessDateTime),
						GetDateTimeStringFromSystemTime(fileInfo->sysTimeLastWrite, strWriteDateTime),
						fileInfo->Size);

					tempfilesize.QuadPart += filesize.QuadPart;

					CleanUpFolderFileInfo(fileInfo);
					fileInfo = NULL;

				}

				memset(strFullPath, '\0', MAX_PATH);
					
			}
			while (FindNextFile(hFind, &FindFileData) != 0);

			folderInfo->Size = tempfilesize.QuadPart;
		

		//CloseHandle(hFind);
	}
	else
	{
		//Error not able to find the file's information
		wprintf(L"\nERROR:: Not able to get File's or Folder's information:%s\n", folderInfo->strAbsolutePath);
		nReturnValue = -2;

		return nReturnValue;

	}

	return nReturnValue;
}

/*
*Name: GetFolderFileInfo
*Description: this will allocate dynamic memory of FolderFileInfo structure. Then initializes it
*Parameter:
*ReturnValue: This will return pointer to filefolderinfo
*/
FileFolderInfo* GetFolderFileInfo()
{
	FileFolderInfo* folderInfo = (FileFolderInfo*)malloc(sizeof(FileFolderInfo));

	folderInfo->isFolder = false;
	folderInfo->isHidden = false;
	folderInfo->isReadonly = false;
	folderInfo->isSystem = false;
	folderInfo->isArchived = false;
	folderInfo->isCompressed = false;
	folderInfo->isEncrypted = false;
	folderInfo->Size = 0;
	folderInfo->strAbsolutePath = NULL;
	folderInfo->strFileFolderName = NULL;
	folderInfo->strParent = NULL;
	folderInfo->strAlternameName = NULL;
	folderInfo->dwAttributes = 0;
	folderInfo->sysTimeCreation = NULL;
	folderInfo->sysTimeLastAccess = NULL;
	folderInfo->sysTimeLastWrite = NULL;

	return folderInfo;
}

/*
*Name: CleanUpFolderFileInfo
*Description: This will deallocate the memory given to folder info structure.
*Parameter: folderInfo - this is the pointer to the dynamically allocated FileFolderStructure which needs to be deallocated
*Returnvalue: 0 for success else error
*/
int CleanUpFolderFileInfo(FileFolderInfo* folderInfo)
{
	int nReturnValue = 0;

	if(NULL != folderInfo)
	{
		if(NULL != folderInfo->strAbsolutePath)
		{
			free(folderInfo->strAbsolutePath);
			folderInfo->strAbsolutePath = NULL;
		}

		if(NULL != folderInfo->strFileFolderName)
		{
			free(folderInfo->strFileFolderName);
			folderInfo->strFileFolderName = NULL;
		}

		if(NULL != folderInfo->strParent)
		{
			free(folderInfo->strParent);
			folderInfo->strParent = NULL;
		}

		if(NULL != folderInfo->strAlternameName)
		{
			free(folderInfo->strAlternameName);
			folderInfo->strAlternameName = NULL;
		}

		if(NULL != folderInfo->sysTimeCreation)
		{
			free(folderInfo->sysTimeCreation);
			folderInfo->sysTimeCreation = NULL;
		}

		if(NULL != folderInfo->sysTimeLastAccess)
		{
			free(folderInfo->sysTimeLastAccess);
			folderInfo->sysTimeLastAccess = NULL;
		}

		if(NULL != folderInfo->sysTimeLastWrite)
		{
			free(folderInfo->sysTimeLastWrite);
			folderInfo->sysTimeLastWrite = NULL;
		}

		free(folderInfo);
		folderInfo = NULL;
	}

	return nReturnValue;
}

/*
*Name: IsFile
*Description: This function will say whether given path is a file or a folder
*Parameter: strFileFolder - a path which needs to be determined whether it is folder or file
*ReturnValue: true if it is a file , false if it is a folder
*/
bool IsFile(WCHAR* strFileFolder)
{
	bool bIsFile = false;

	if(NULL != strFileFolder)
	{
		if(FILE_ATTRIBUTE_DIRECTORY ==  (GetFileAttributes(strFileFolder) & FILE_ATTRIBUTE_DIRECTORY))
		{
			bIsFile = false;
		}
		else
		{
			bIsFile = true;
		}
		
	}

	return bIsFile;
}

/*
*Name: GetSystemTimeFromFileTimeCustom
*Description: This function returns a dynamic memory allocated system time if we send file time.
*Parameter: ftTime - file time which needs to be converted to systemtime
*ReturnValue: Pointer to the converted Systemtime.
*/
SYSTEMTIME* GetSystemTimeFromFileTimeCustom(FILETIME ftTime)
{
	SYSTEMTIME *sysTime = NULL, *tempTime = NULL;

	
	sysTime = (SYSTEMTIME*)malloc(sizeof(SYSTEMTIME));

	FileTimeToSystemTime( &ftTime, sysTime);

	/*sysTime->wDay = tempTime->wDay;
	sysTime->wDayOfWeek = tempTime->wDayOfWeek;
	sysTime->wHour = tempTime->wHour;
	sysTime->wMilliseconds = tempTime->wMilliseconds;
	sysTime->wMinute = tempTime->wMinute;
	sysTime->wMonth = tempTime->wMonth;
	sysTime->wSecond = tempTime->wSecond;
	sysTime->wYear = tempTime->wYear;*/

	return sysTime;
}

/*
*Name: GetDateTimeStringFromSystemTime
*Description: If you give a SYSTEMTIME it will convert into a string format of date time -> dd-mm-yyyy hh:MM:ss
*Parameter: sysTime - pointer to the SYSTEMTIME structure which needs to be displayed in string format
*ReturnValue: WCHAR* - date time in string format.
*/
WCHAR* GetDateTimeStringFromSystemTime(SYSTEMTIME* sysTime, WCHAR* strDateTime)
{
	//WCHAR strDateTime[25] = {0};

	memset(strDateTime, '\0', 25);

	wsprintf(strDateTime, L"%d-%d-%d %d:%d:%d", sysTime->wDay, sysTime->wMonth, sysTime->wYear, sysTime->wHour, sysTime->wMinute, sysTime->wSecond);

	return strDateTime;
}


//PID
//User Name
//Session ID
//CPU Usage
//CPU Time
//Memory - Working Set
//Memory - Peak Working Set
//Memory - Working Set Delta
//Memory - Private Working Set
//Memory - Commit Size
//Memory - Paged Pool
//Memory - Non Paged pool
//Page Faults
//Page Fault Delta
//Base Priority
//Handles
//Threads
//User Objects
//GDI Objects
//I/O Reads
//I/O Writes
//I/O Other
//I/O Read Bytes
//I/O Write Bytes
//I/O Other Bytes
//Image Path Name
//Command Line
//User Account Control Virtualization
//Description
//Data Exectuion prevention
//Company Name
//Verified Signer
//Version
//Image Type - 64 vs 32
//Package Name
//Window Title
//Window Status
//Start Time
//CPU Cycles
//CPU Cycles Delta
//Context Switches
//Context Swtich Delta
//I/O Delta Reads
//I/O Delta Reads Byte
//I/O Delta Writes
//I/O Delta Writes Byte
//I/O Delta Others
//I/O Delta Others Byte
//GPU Usage
//GPU Dedicated Bytes
//GPU Committed Bytes
//GPU System Bytes
//DLL Description
//DLL Version
//DLL Timestamp
//DLL Name
//DLL Path
//DLL Company Name
//Dll Verified Signer
//DLL Image Base Address
//DLL Base Address
//DLL Mapped Size
//DLL Mapping Type
//DLL WS Total Bytes
//DLL WS Private Bytes
//DLL WS Shareable Bytes
//DLL WS Shared Bytes
//DLL Image Type
//DLL ASLR Enabled

/*
*Name: TakeProcessSnapshotOfSystem
*Description: This will list all the process which are currently running in the system. This will try to list all the information of those process also
*ReturnValue: 0 For success else some error has occurred
*/
int TakeProcessSnapshotOfSystem()
{
	int nReturnValue = 0;

	HANDLE hProcessSnap = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	PROCESSENTRY32 pe32;
	PTOKEN_USER ptu = NULL;
	DWORD dwLength = 0;
	DWORD dwSize = MAX_NAME;
	DWORD dwSizeGlobal = 0;
	SID_NAME_USE SidType;
    WCHAR lpName[MAX_NAME];
    WCHAR lpDomain[MAX_NAME];
	DWORD dwResult = 0;
	DWORD dwSessionID = 0;
	SIZE_T virtualMemUsedByMe = 0;

	MEMORYSTATUSEX memInfo;
	PROCESS_MEMORY_COUNTERS pmc;
	PERFORMANCE_INFORMATION pfInfo;
	pfInfo.cb = sizeof(PERFORMANCE_INFORMATION);
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if(GlobalMemoryStatusEx(&memInfo))
	{

		wprintf(L"\n===================================================================================\n");
		wprintf(L"TOTAL PHYSICAL MEMORY USAGE: %d\n", memInfo.dwMemoryLoad);
		wprintf(L"PHYSICAL MEMORY: %u bytes\n", memInfo.ullTotalPhys);
		wprintf(L"AVAILABLE PHYSICAL MEMORY: %u bytes\n", memInfo.ullAvailPhys);
		wprintf(L"TOTAL VIRTUAl MEMORY (SWAP FILE + RAM): %u bytes\n", memInfo.ullTotalPageFile);
		wprintf(L"MAXIMUM AMOUNT OF MEMORY PROCESS CAN COMMIT: %u bytes\n", memInfo.ullAvailPageFile);
		wprintf(L"TOTAL VIRTUAL MEMORY CURRENTLY USED: %u bytes\n", memInfo.ullTotalPageFile - memInfo.ullAvailPageFile);
		wprintf(L"USER-MODE PORTION OF VIRTUAL ADDRESS SPACE: %u bytes\n", memInfo.ullTotalVirtual);
		wprintf(L"UNRESERVED AND UNCOMMITTED MEMORY IN USER MODE: %u bytes\n", memInfo.ullAvailVirtual);
		wprintf(L"\n===================================================================================\n");
	}
	else
	{
		wprintf(L"\nGlobal memory related information not available\n");
	}

	if(GetPerformanceInfo(&pfInfo, sizeof(PERFORMANCE_INFORMATION)))
	{
		wprintf(L"\n======================================================================================\n");
		wprintf(L"TOTAL PAGES COMMITTED BY SYSTEM: %d\n", pfInfo.CommitTotal);
		wprintf(L"MAX NUMBER OF PAGES CAN BE COMMITTED: %d\n", pfInfo.CommitLimit);
		wprintf(L"MAX NUMBER OF PAGES IN COMMIT STATE: %d\n", pfInfo.CommitPeak);
		wprintf(L"AMOUNT OF ACTUAL PHYSICAL MEMORY IN PAGES: %u\n", pfInfo.PhysicalTotal);
		wprintf(L"AMOUNT OF AVAILABLE PHYSICAL MEMORY IN PAGES: %u\n", pfInfo.PhysicalAvailable);
		wprintf(L"SYSTEM CACHE IN PAGES: %u\n", pfInfo.SystemCache);
		wprintf(L"MEMORY IN PAGED AND NONPAGED KERNEL POOLS IN PAGES: %u\n", pfInfo.KernelTotal);
		wprintf(L"MEMORY IN PAGED KERNEL POOL IN PAGES: %u\n", pfInfo.KernelPaged);
		wprintf(L"MEMORY IN NON PAGED KERNEL POOL IN PAGES: %u\n", pfInfo.KernelNonpaged);
		wprintf(L"SIZE OF PAGE: %d bytes\n", pfInfo.PageSize);
		wprintf(L"HANDLE COUNT: %d\n", pfInfo.HandleCount);
		wprintf(L"PROCESS COUNT: %d\n", pfInfo.ProcessCount);
		wprintf(L"THREAD COUNT: %d\n", pfInfo.ThreadCount);
		wprintf(L"\n======================================================================================\n");
	}
	else
	{
		wprintf(L"\nPerformance Related information not available\n");
	}
	
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		wprintf(L"Error while getting snapshot of the processes in system\n");
		nReturnValue = -1;
		return nReturnValue;
	}

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if( !Process32First( hProcessSnap, &pe32 ) )
	{
		wprintf(L"Error while getting the first process from snapshot\n");
		CloseHandle( hProcessSnap );          // clean the snapshot object
		return( FALSE );
	}

	wprintf(L"\nList Of Processes and its details\n\n");
	do
	{
		dwResult = 0;
		dwSize = MAX_NAME;
		dwLength = 0;

		memset(lpName, '\0', MAX_NAME);
		memset(lpDomain, '\0', MAX_NAME);

		wprintf(L"\n===============================================================\n");
		wprintf(L"PROCESS NAME: %s\n", pe32.szExeFile);
		wprintf(L"PROCESS ID: %d\n", pe32.th32ProcessID);
		wprintf(L"THREAD COUNT: %d\n", pe32.cntThreads);
		wprintf(L"PARENT PROCESS ID: %d\n", pe32.th32ParentProcessID);
		wprintf(L"PRIORITY BASE: %d\n", pe32.pcPriClassBase);

		hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
		//hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID );
		if(NULL == hProcess)
		{
			dwResult = GetLastError();
			wprintf(L"ERROR!! Cannot retrieve further information about the process, ERROR NUMBER = %d\n",dwResult);
			
		}
		else
		{
			if( !OpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) )
			{
				dwResult = GetLastError();
				wprintf(L"ERROR!! Failed to open the token information of process, ERROR NUMBER = %d\n",dwResult);
				
				
				
			}
			else
			{

				
				if(GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
				{
					wprintf(L"PAGE FAULT COUNT: %d\n", pmc.PageFaultCount);
					wprintf(L"WORKING SET SIZE: %d bytes\n", pmc.WorkingSetSize);
					wprintf(L"PAGE FILE USAGE: %d bytes\n", pmc.PagefileUsage);
					wprintf(L"PEAK PAGE FILE USAGE: %d bytes\n", pmc.PeakPagefileUsage);
					wprintf(L"PEAK WORKING SET SIZE: %d bytes\n", pmc.PeakWorkingSetSize);
					wprintf(L"QUOTA NON PAGED POOL USAGE: %d bytes\n", pmc.QuotaNonPagedPoolUsage);
					wprintf(L"QUOTA PAGED POOL USAGE: %d bytes\n", pmc.QuotaPagedPoolUsage);
					wprintf(L"QUOTA PEAK NON PAGED POOL USAGE: %d bytes\n", pmc.QuotaPeakNonPagedPoolUsage);
					wprintf(L"QUOTA PEAK PAGED USAGE: %d bytes\n", pmc.QuotaPeakPagedPoolUsage);
					
				}
				else
				{
					wprintf(L"ERROR!! Not able to get process memory related information\n");
				}
				

				if(!GetTokenInformation(hToken, TokenUser, (LPVOID) ptu, 0, &dwLength ))
				//if(!GetTokenInformation(hToken, TokenUser, ptu, sizeof(TOKEN_USER), &dwLength ))
				{
					dwResult = GetLastError();

					if(ERROR_INSUFFICIENT_BUFFER != dwResult)
					{
						wprintf(L"ERROR!! Faled to get the token information of process, ERROR NUMBER = %d\n",dwResult);
					}
					else
					{
						ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
						if(NULL == ptu)
						{
							//Error
							dwResult = GetLastError();
							wprintf(L"ERROR!!while allocating memory to Token User, ERROR NUMBER = %d\n",dwResult);
						
						}
						else
						{
							if(!GetTokenInformation( hToken, TokenUser, (LPVOID) ptu, dwLength, &dwLength )) 
							{
								//ERROR
								dwResult = GetLastError();
								wprintf(L"ERROR!! not able to get token informaation for process, ERROR NUMBER = %d\n",dwResult);
							
							}
							else
							{
								if( !LookupAccountSid( NULL , ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) )                                    
								{
									dwResult = GetLastError();
									if( dwResult == ERROR_NONE_MAPPED )
									{
									   wcscpy(lpName, L"NONE_MAPPED" );
									   wprintf(L"PROCESS USER NAME: %s\n", lpName);
									}
									else 
									{
										wprintf(L"LookupAccountSid Error %u\n", GetLastError());
									}
								}
								else
								{
									wprintf(L"PROCESS USER NAME: %s\\%s\n",lpDomain, lpName);
								
								}

							}
						}

						if(NULL != ptu)
						{
							HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
							ptu = NULL;
						}

					}


					
				}
				else
				{
					
				}
			}
			if(NULL != hToken)
			{
				CloseHandle(hToken);
				hToken = NULL;
			}
			if(NULL != hProcess)
			{
				CloseHandle(hProcess);
				hProcess = NULL;
			}
		}

		if(ProcessIdToSessionId(pe32.th32ProcessID, &dwSessionID))
		{
			wprintf(L"PROCESS SESSION ID: %d\n", dwSessionID);
		}
		else
		{
			wprintf(L"NOT ABLE TO ACCESS SESSION ID OF PROCESS\n");
		}

		wprintf(L"\n===============================================================\n");

	}while(Process32Next( hProcessSnap, &pe32 ));

	CloseHandle( hProcessSnap );
	return nReturnValue;
}