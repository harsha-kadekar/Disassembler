/*
*	This is just a small tool to consume the dlls I have produced and test it whether it executes properly or not. Not much of importance. 
*	This will dynamically load the dll and call the function.
*
*/

#include "ConsumerDll.h"

int main(int argc, char** argv)
{
	int nReturnValue = 0;
	HMODULE hDll = NULL;
	Parseptr ParsePEFile = NULL;
	char* strFileName = NULL;

	if(argc != 2)
	{
		printf("Invalid number of arguments....");
		return -1;
	}



	
	hDll = LoadLibrary(L"ProcessDissector.dll");
	if(NULL == hDll)
	{
		printf("Failed to load library ProcessDissector\n");
		return -2;
	}

	ParsePEFile = (Parseptr)GetProcAddress(hDll, "ParsePEFile");
	if(NULL == ParsePEFile)
	{
		printf("Failed to get the function ParsePEFile\n");
		FreeLibrary(hDll);
		return -3;
	}

	printf("File to be parsed is %s\n", argv[1]);

	fflush(0);
	getchar();
	
	
	strFileName = argv[1];
	nReturnValue = ParsePEFile(strFileName);

	

	FreeLibrary(hDll);
	


}