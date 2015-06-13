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
		DWORD dwResult = GetLogicalDriveStrings(dwSize,szLogicalDrives);

		if (dwResult > 0 && dwResult <= MAX_PATH)
		{
			WCHAR* szSingleDrive = szLogicalDrives;
			while(*szSingleDrive)
			{
				wprintf(L"Drive: %s\n", szSingleDrive);

					// get the next drive
				szSingleDrive += wcslen(szSingleDrive) + 1;

				nReturnValue = ListFilesinPath(szSingleDrive);
				if(0 != nReturnValue)
				{
					//Error - Abort
					wprintf(L"ERROR::Some error has occurred - so aborting the listing of files\n");
					break;
				}
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

	if(TRUE != PathFileExists(strPath))
	{
		wprintf(L"ERROR::File or Folder doesnot exists = %s", strPath);
		nReturnValue = -3;
		return nReturnValue;
	}

	 if(FILE_ATTRIBUTE_DIRECTORY ==  (GetFileAttributes(strPath) & FILE_ATTRIBUTE_DIRECTORY))
	 {
		 //This is directory
		 hFind = FindFirstFile(strPath, &FindFileData);
		 if(INVALID_HANDLE_VALUE != hFind)
		 {

			 do
			{				
					tempfilesize.LowPart = FindFileData.nFileSizeLow;
					tempfilesize.HighPart = FindFileData.nFileSizeHigh;
					
			}
			while (FindNextFile(hFind, &FindFileData) != 0);

			 //CloseHandle(hFind);
		 }
		 else
		 {
			 //Error not able to find the file's information
			 wprintf(L"ERROR:: Not able to get File's or Folder's information:%s", strPath);
			 nReturnValue = -2;

			 return nReturnValue;

		 }


		 wprintf(L"%s\t%uld\n", strPath, filesize.QuadPart);
	 }
	 else
	 {
		 //This is a file
		 hFind = FindFirstFile(strPath, &FindFileData);
		 if(INVALID_HANDLE_VALUE != hFind)
		 {

			 filesize.HighPart = FindFileData.nFileSizeHigh;
			 filesize.LowPart = FindFileData.nFileSizeLow;


			 wprintf(L"%s\t%ld\n",strPath, filesize.QuadPart);
			 CloseHandle(hFind);
		 }
		 else
		 {
			 //Error not able to find the file's information
			 wprintf(L"ERROR:: Not able to get File's information:%s", strPath);
			 nReturnValue = -2;

		 }

	 }


	return nReturnValue;
}


int ListFilesOfDirectory()
{

}