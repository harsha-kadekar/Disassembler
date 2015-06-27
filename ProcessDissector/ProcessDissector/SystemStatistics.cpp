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