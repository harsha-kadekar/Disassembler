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
	FunctionPTR ParsePEFile = NULL, ListFiles = NULL;
	FunctionPTR2 Snapshot = NULL;
	char* strFileName = NULL;

	/*if(argc != 2)
	{
		printf("Invalid number of arguments....");
		return -1;
	}*/



	
	hDll = LoadLibrary(L"ProcessDissector.dll");
	if(NULL == hDll)
	{
		printf("Failed to load library ProcessDissector\n");
		return -2;
	}

	

	/*ParsePEFile = (FunctionPTR)GetProcAddress(hDll, "ParsePEFile");
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
	nReturnValue = ParsePEFile(strFileName);*/

	/*ListFiles = (FunctionPTR)GetProcAddress(hDll, "ListFiles");
	if(NULL == ListFiles)
	{
		printf("Failed to get the function ListFiles");
		FreeLibrary(hDll);
		return -3;
	}*/

	Snapshot = (FunctionPTR2)GetProcAddress(hDll, "TakeProcessSnapshotOfSystem");
	if(NULL == Snapshot)
	{
		printf("Failed to get the function TakeProcessSnapshotOfSystem");
		FreeLibrary(hDll);
		return -3;
	}

	nReturnValue = Snapshot();

	/*printf("Waiting to be linked......\n");
	Sleep(30000);
	printf("Finished wait.\n");*/
	
	//nReturnValue = ListFiles("ALL");

	//nReturnValue = ListFiles("E:\\Coding\\");

	//nReturnValue = ListFiles("E:\\My Interests\\");

	//nReturnValue = ListFiles("E:\\My Interests");

	//nReturnValue = ListFiles("E:\\My Interests\\Sanatana Dharma\\10120488-Hindu-TemplesWhat-Happend-to-Them-by-Sita-Ram-Goel.pdf");
	

	FreeLibrary(hDll);
	


}