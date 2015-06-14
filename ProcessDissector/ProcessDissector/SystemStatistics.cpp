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
		DWORD dwSize = MAX_PATH;
		WCHAR szLogicalDrives[MAX_PATH] = {0};
		WCHAR szExtra[MAX_PATH] = L"*";
		WCHAR szDrive[MAX_PATH] = {0};
		DWORD dwResult = GetLogicalDriveStrings(dwSize,szLogicalDrives);

		if (dwResult > 0 && dwResult <= MAX_PATH)
		{
			WCHAR* szSingleDrive = szLogicalDrives;
			while(*szSingleDrive)
			{
				wprintf(L"Drive: %s\n", szSingleDrive);

					// get the next drive
				
				wsprintf(szDrive, L"%s%s", szSingleDrive, szExtra); 

				nReturnValue = ListFilesinPath(szDrive);
				if(0 != nReturnValue)
				{
					//Error - Abort
					wprintf(L"ERROR::Some error has occurred - so aborting the listing of files\n");
					break;
				}

				szSingleDrive += wcslen(szSingleDrive) + 1;
			}
		} 
	}
	else
	{
		//List the files as given by the path - strOption
	}

	return nReturnValue;
}


/*
*Name: ListFilesinPath
*Description: This will list all the files present inside that path. Also it will give information about that path.
*Parameters: strPath - Path whose information has to be listed. All the files and folders inside that will also be displayed
*ReturnValue: 0 for success else error
*/
int ListFilesinPath(WCHAR* strPath)
{
	int nReturnValue = 0;
	HANDLE hFind = NULL;
	WIN32_FIND_DATA FindFileData;
	LARGE_INTEGER filesize = {0};
	LARGE_INTEGER tempfilesize = {0};

	FileFolderInfo *fileInfo = NULL;
	FileFolderInfo *folderInfo = NULL;

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
			if(FILE_ATTRIBUTE_DIRECTORY ==  (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				folderInfo = (FileFolderInfo*)malloc(sizeof(FileFolderInfo));

				folderInfo->strAbsolutePath = (WCHAR*)malloc(sizeof(WCHAR)*wcslen(strPath));

				memset(folderInfo->strAbsolutePath, L'\0', wcslen(strPath));

				wcscpy(folderInfo->strAbsolutePath, strPath);

				folderInfo->isFolder = true;

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

				ListFilesOfDirectory(folderInfo);

				//wprintf(L"%s\t%uld\n", folderInfo->strAbsolutePath, folderInfo->Size);

				tempfilesize.QuadPart += folderInfo->Size;

				free(folderInfo->strAbsolutePath);
				free(folderInfo);
					//tempfilesize.LowPart = FindFileData.nFileSizeLow;
					//tempfilesize.HighPart = FindFileData.nFileSizeHigh;
			}
			else
			{
				filesize.HighPart = FindFileData.nFileSizeHigh;
				filesize.LowPart = FindFileData.nFileSizeLow;

				wprintf(L"%s\t%uld\n", FindFileData.cFileName, filesize.QuadPart);

				tempfilesize.QuadPart += filesize.QuadPart;

			}

					
		}
		while (FindNextFile(hFind, &FindFileData) != 0);

		wprintf(L"%s\t%uld\n", strPath, tempfilesize.QuadPart);

	}	 //CloseHandle(hFind);
	else
	{
		 
		//Error not able to find the file's information
		wprintf(L"ERROR:: Not able to get File's or Folder's information:%s", strPath);
		nReturnValue = -2;

		return nReturnValue;
	}

		 


		 
	 

	 


	return nReturnValue;
}


/*
*Name: ListFilesOfDirectory
*Description: This will help to list all the files. This is a recurrsive function.
*Parameter: folderInfo - Folder whose files and child folders needs to be parsed and info needs to be put.
*/
int ListFilesOfDirectory(FileFolderInfo* folderInfo)
{
	int nReturnValue = 0;
	HANDLE hFind = NULL;
	WIN32_FIND_DATA FindFileData;
	LARGE_INTEGER filesize = {0};
	LARGE_INTEGER tempfilesize = {0};

	FileFolderInfo *newFolderInfo = NULL;
	//FileFolderInfo *folderInfo = NULL;

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

	hFind = FindFirstFile(folderInfo->strAbsolutePath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFind)
	{
		

			do
			{	
				if(FILE_ATTRIBUTE_DIRECTORY ==  (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				{
					newFolderInfo = (FileFolderInfo*)malloc(sizeof(FileFolderInfo));

					newFolderInfo->strAbsolutePath = (WCHAR*)malloc(sizeof(WCHAR)*wcslen(FindFileData.cFileName));

					memset(newFolderInfo->strAbsolutePath, L'\0', wcslen(FindFileData.cFileName));

					wcscpy(newFolderInfo->strAbsolutePath, FindFileData.cFileName);

					newFolderInfo->isFolder = true;

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

					ListFilesOfDirectory(newFolderInfo);

					wprintf(L"%s\t%uld\n", newFolderInfo->strAbsolutePath, folderInfo->Size);

					tempfilesize.QuadPart += newFolderInfo->Size;

					free(newFolderInfo->strAbsolutePath);
					free(newFolderInfo);
					
				}
				else
				{
					filesize.LowPart = FindFileData.nFileSizeLow;
					filesize.HighPart = FindFileData.nFileSizeHigh;

					tempfilesize.QuadPart += filesize.QuadPart;

				}
					
			}
			while (FindNextFile(hFind, &FindFileData) != 0);

			folderInfo->Size = tempfilesize.QuadPart;
		

		//CloseHandle(hFind);
	}
	else
	{
		//Error not able to find the file's information
		wprintf(L"ERROR:: Not able to get File's or Folder's information:%s", folderInfo->strAbsolutePath);
		nReturnValue = -2;

		return nReturnValue;

	}

	return nReturnValue;
}