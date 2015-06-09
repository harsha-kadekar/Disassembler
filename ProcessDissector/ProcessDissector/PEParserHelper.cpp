/*
*	This file contains various functions which will help to parse a PE file. Functions which will help to retrive complete information about PE File, functions which will help to retrieve only export table, import table, different sections, etc.
*	Idea is to this will help to simulate the DumpBin utility.
*
*/


#include "PEParserHelper.h"

typedef int (*pt2Function)(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
pt2Function DecodeFunctions[256] = {NULL};
pt2Function DecodeFunctions_2[256] = {NULL};
pt2Function DecodeFunctions_3[256] = {NULL};

char** archREGFields_8 = {NULL};
char** archREGFields_16 = {NULL};
char** archREGFields_32 = {NULL};
char** archREGFields_mm = {NULL};
char** archREGFields_xmm = {NULL};

char** archMODRMFields_16 = {NULL};
char** archMODRMFields_32 = {NULL};
//char** archMODRMFields_2 = {NULL};

char** archSIBIndex = {NULL};
char** archSIBBase = {NULL};







/*
 Name: ParsePEFile
 Parameters: lpstrFileName - Complete Path of the PE file which needs to read
 Return Value:	0 - Success
 Description: This function will read the PE file and display information present in various structures present in the PE FILE.
*/
int ParsePEFile(char* lpstrFileName)
{
	int nReturnValue = 0;

	int i = 0, j = 0, k = 0, l = 0;
	wchar_t strFileName[1024];
	bool bFoundSectionCharacteristic = false;
	int nSectionSize = 0;
	BYTE* pbSectionBuffer = NULL;
	DWORD dwBytesRead = 0;
	char archSectionLine[69];
	BYTE bTempByte = 0x00;
	char chTempChar = '.';
	char archtempByteArray[3];
	DWORD dwSectionAddresses = 0;
	bool bIsItDll = false;
	bool bFoundDllCharacteristics = false;
	DWORD dwImportDirectory = 0;
	DWORD dwExportDirectory = 0;
	PCHAR libname = NULL;
	PCHAR funName = NULL;
	DWORD dwBase = 0;
	DWORD dwFunctions = 0;
	DWORD dwNamesOfFunctions = 0;
	DWORD dwFunctionOrdinals = 0;
	DWORD dwTempRVA = 0;
	PDWORD* pdwNamesOfFunctions = 0;
	PDWORD* pdwFunctionAddresses = 0;
	PDWORD* pdwFunctionOrdinals = 0;
	WORD* wTempFunctionOrdinals = 0;

	HANDLE hFile = NULL;
	HANDLE hFileMapping = NULL;
	LPVOID lpFileBase = NULL;
	PIMAGE_DOS_HEADER imdosHeader = NULL;
	PIMAGE_NT_HEADERS imNTHeader = NULL;
	PIMAGE_SECTION_HEADER imsectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY imimageDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR  imImportDescript = NULL;
	PIMAGE_THUNK_DATA imThunkData = NULL;
	PIMAGE_IMPORT_BY_NAME imFunNameImport = NULL;
	PIMAGE_EXPORT_DIRECTORY imExportDir = NULL;
	
	memset(strFileName, '\0', 1024);
	MultiByteToWideChar(CP_ACP, 0, lpstrFileName, -1, strFileName, strlen(lpstrFileName));

	printf("\n************************************************************************************************************************************************************************************\n");
	printf("\n**************************************************************************************START OF PARSING PE FILE***********************************************************************\n");
	printf("\n************************************************************************************************************************************************************************************\n");

	printf("File going to parse is %s\n", lpstrFileName);

	hFile = CreateFile(strFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(NULL == hFile)
	{
		nReturnValue = -2;
		//Failed to open the exe or PE File
		printf("Failed to open the input file\n");
		return nReturnValue;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(NULL == hFileMapping)
	{
		//Failed to map the openned file
		nReturnValue = -3;
		printf("Failed to map the openned file\n");
		CloseHandle(hFile);
		return nReturnValue;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(NULL == lpFileBase)
	{
		//Failed to get the mapped file base
		nReturnValue = -4;
		printf("Failed to get the mapped view of file\n");
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return nReturnValue;
	}

	imdosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if(imdosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		imNTHeader = (PIMAGE_NT_HEADERS)((DWORD)imdosHeader + imdosHeader->e_lfanew);

		if(imNTHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			//It is not a PE File
			printf("This is not a PE file\n");
			printf("Got signature as %d\n", imNTHeader->Signature);
			nReturnValue = -6;
			UnmapViewOfFile(lpFileBase);
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
			return nReturnValue;

		}

		switch(imNTHeader->FileHeader.Machine)
		{
		/*case 0x14d:
			{
				break
			}*/
		case IMAGE_FILE_MACHINE_I386:
			{
				printf("This PE File executes in Intel 386 machine\n");
				break;
			}		
		case IMAGE_FILE_MACHINE_R3000:
			{
				printf("This PE File executes in MIPS little-endian, 0x160 big-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_R4000:
			{
				printf("This PE File executes in MIPS little-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_R10000:
			{
				printf("This PE File executes in MIPS little-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_WCEMIPSV2:
			{
				printf("This PE File executes in MIPS little-endian WCE v2\n");
				break;
			}
		case IMAGE_FILE_MACHINE_ALPHA:
			{
				printf("This PE File executes in Alpha_AXP\n");
				break;
			}
		case IMAGE_FILE_MACHINE_SH3:
			{
				printf("This PE File executes in SH3 little-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_SH3DSP:
			{
				printf("This PE File executes in SH3 DSP\n");
				break;
			}
		case IMAGE_FILE_MACHINE_SH3E:
			{
				printf("This PE File executes in SH3E little-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_SH4:
			{
				printf("This PE File executes in SH4 little-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_SH5:
			{
				printf("This PE File executes in SH5\n");
				break;
			}
		case IMAGE_FILE_MACHINE_ARM:
			{
				printf("This PE File executes in ARM Little-Endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_THUMB:
			{
				printf("This PE File executes in Thumb\n");
				break;
			}
		case IMAGE_FILE_MACHINE_AM33:
			{
				printf("This PE File executes in AM33\n");
				break;
			}
		case IMAGE_FILE_MACHINE_POWERPC:
			{
				printf("This PE File executes in IBM PowerPC Little-Endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_POWERPCFP:
			{
				printf("This PE File executes in POWER PCFP\n");
				break;
			}
		case IMAGE_FILE_MACHINE_IA64:
			{
				printf("This PE File executes in Intel 64\n");
				break;
			}
		case IMAGE_FILE_MACHINE_MIPS16:
			{
				printf("This PE File executes in MIPS\n");
				break;
			}
		case IMAGE_FILE_MACHINE_ALPHA64:
		//case IMAGE_FILE_MACHINE_AXP64:
			{
				printf("This PE File executes in ALPHA64\n");
				break;
			}
		case IMAGE_FILE_MACHINE_MIPSFPU:
			{
				printf("This PE File executes in MIPS\n");
				break;
			}
		case IMAGE_FILE_MACHINE_MIPSFPU16:
			{
				printf("This PE File executes in MIPS\n");
				break;
			}
		case IMAGE_FILE_MACHINE_TRICORE:
			{
				printf("This PE File executes in Infineon\n");
				break;
			}
		case IMAGE_FILE_MACHINE_CEF:
			{
				printf("This PE File executes in CEF\n");
				break;
			}
		case IMAGE_FILE_MACHINE_EBC:
			{
				printf("This PE File executes in EFI Byte Code\n");
				break;
			}
		case IMAGE_FILE_MACHINE_AMD64:
			{
				printf("This PE File executes in AMD64 (K8)\n");
				break;
			}
		case IMAGE_FILE_MACHINE_M32R:
			{
				printf("This PE File executes in M32R little-endian\n");
				break;
			}
		case IMAGE_FILE_MACHINE_CEE:
			{
				printf("This PE File executes in CEE\n");
				break;
			}
		default:
			{
				printf("This PE File executes in UNKOWN type of machine\n");
				break;
			}
		}


		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			printf("This is an executable\n");
		}
		
		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		{
			printf("This is DLL\n");
			bIsItDll = true;
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == IMAGE_FILE_RELOCS_STRIPPED)
		{
			printf("In this file Relocation info is stripped\n");

		}

		if((imNTHeader->FileHeader.Characteristics &IMAGE_FILE_LINE_NUMS_STRIPPED) ==IMAGE_FILE_LINE_NUMS_STRIPPED)
		{
			printf("In this file Line nunbers are stripped\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) == IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		{
			printf("In this file Local symbols are stripped\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) == IMAGE_FILE_AGGRESIVE_WS_TRIM)
		{
			printf("In this file Agressively trim working set\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE)
		{
			printf("This App can handle >2gb addresses\n");
		}

		if((imNTHeader->FileHeader.Characteristics &IMAGE_FILE_BYTES_REVERSED_LO) == IMAGE_FILE_BYTES_REVERSED_LO)
		{
			printf("Bytes of machine word are reversed\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE)
		{
			printf("32 bit word machine\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) == IMAGE_FILE_DEBUG_STRIPPED)
		{
			printf("Debugging info stripped from file in .DBG file\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) == IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		{
			printf("If Image is on removable media, copy and run from the swap file\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) == IMAGE_FILE_NET_RUN_FROM_SWAP)
		{
			printf("If Image is on Net, copy and run from the swap file\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) == IMAGE_FILE_SYSTEM)
		{
			printf("This is a System File\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) == IMAGE_FILE_UP_SYSTEM_ONLY)
		{
			printf("File should only be run on a UP machine\n");
		}

		if((imNTHeader->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) == IMAGE_FILE_BYTES_REVERSED_HI)
		{
			printf("Bytes of machine word are reversed\n");
		}

		
		printf("Number of sections :%d\n",imNTHeader->FileHeader.NumberOfSections);
		printf("Size of optional header: %d\n",imNTHeader->FileHeader.SizeOfOptionalHeader);
		printf("Number of symbols: %d\n",imNTHeader->FileHeader.NumberOfSymbols);
		printf("Address of the Symbol table: %d\n",imNTHeader->FileHeader.PointerToSymbolTable);

		if(imNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			printf("This is 32 bit application\n");
		}
		else if(imNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			printf("This is a 64 bit application\n");
		}
		else if(imNTHeader->OptionalHeader.Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC)
		{
			printf("This is a ROM image\n");
		}

		printf("Size of code: %d\n",imNTHeader->OptionalHeader.SizeOfCode);
		printf("Size of Headers: %d\n",imNTHeader->OptionalHeader.SizeOfHeaders);
		printf("Size of Heap to be committed: %d\n",imNTHeader->OptionalHeader.SizeOfHeapCommit);
		printf("Size of Heap to be reserved: %d\n",imNTHeader->OptionalHeader.SizeOfHeapReserve);
		printf("Size of Image: %d\n",imNTHeader->OptionalHeader.SizeOfImage);
		printf("Size of initialized Data: %d\n",imNTHeader->OptionalHeader.SizeOfInitializedData);
		printf("Size of Stack to be committed: %d\n",imNTHeader->OptionalHeader.SizeOfStackCommit);
		printf("Size of Stack to be reserved: %d\n",imNTHeader->OptionalHeader.SizeOfStackReserve);
		printf("Size of uninitialized data: %d\n",imNTHeader->OptionalHeader.SizeOfUninitializedData);

		printf("Address of Entry point: %d\n",imNTHeader->OptionalHeader.AddressOfEntryPoint);
		printf("Base of Data: %d\n",imNTHeader->OptionalHeader.BaseOfData);
		printf("Base of Code: %d\n",imNTHeader->OptionalHeader.BaseOfCode);
		printf("Image Base: %d\n",imNTHeader->OptionalHeader.ImageBase);

		switch(imNTHeader->OptionalHeader.Subsystem)
		{
		case IMAGE_SUBSYSTEM_NATIVE:
			{
				printf("This doesnt require any subsystem\n");
				break;
			}
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			{
				printf("This is a GUI application\n");
				break;
			}
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			{
				printf("This is a command line interface application\n");
				break;
			}
		case IMAGE_SUBSYSTEM_OS2_CUI:
			{
				printf("This requires OS/2 CUI subsystem\n");
				break;
			}
		case IMAGE_SUBSYSTEM_POSIX_CUI:
			{
				printf("This requires POSIX CUI subsystem\n");
				break;
			}
		case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			{
				printf("This requires Windows CE system\n");
				break;
			}
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			{
				printf("This is an Extensible Firmware Interface (EFI) application\n");
				break;
			}
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			{
				printf("This is an EFI driver with boot services\n");
				break;
			}
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			{
				printf("This is an EFI driver with run-time services\n");
				break;
			}
		case IMAGE_SUBSYSTEM_EFI_ROM:
			{
				printf("This is an EFI ROM image\n");
				break;
			}
		case IMAGE_SUBSYSTEM_XBOX:
			{
				printf("This requires Xbox system\n");
				break;
			}
		case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			{
				printf("This is a Boot application\n");
				break;
			}
		default:
			{
				printf("This requires an unkown subsystem\n");
				break;
			}
		}

		if(bIsItDll)
		{
			bFoundDllCharacteristics = false;
			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
			{
				printf("The DLL can be relocated at load time\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) == IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
			{
				printf("Code integrity checks are forced\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
			{
				printf("The image is compatible with data execution prevention (DEP)\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) == IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
			{
				printf("The image is isolation aware, but should not be isolated\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == IMAGE_DLLCHARACTERISTICS_NO_SEH)
			{
				printf("The image does not use structured exception handling (SEH). No handlers can be called in this image\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) == IMAGE_DLLCHARACTERISTICS_NO_BIND)
			{
				printf("Do not bind the image\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) == IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
			{
				printf("A WDM driver\n");
				bFoundDllCharacteristics = true;
			}

			if((imNTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) == IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
			{
				printf("The image is terminal server aware\n");
				bFoundDllCharacteristics = true;
			}

			if(!bFoundDllCharacteristics)
			{
				printf("Found a reserved or unkown dll characteristics. ");
				printf("Dll Characteristics: %d\n", imNTHeader->OptionalHeader.DllCharacteristics);
			}

		}
		/*if(imNTHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
		{
			printf("This is a GUI application\n");
		}
		else if(imNTHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
		{
			printf("This is a command line interface application\n");
		}*/


		printf("Number of Rva and Sizes: %d\n",imNTHeader->OptionalHeader.NumberOfRvaAndSizes);

		printf("\n");
		printf("%d [%d] RVA [size] of Export Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
		printf("%d [%d] RVA [size] of Import Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
		printf("%d [%d] RVA [size] of Resource Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
		printf("%d [%d] RVA [size] of Exception Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
		printf("%d [%d] RVA [size] of Certificates Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
		printf("%d [%d] RVA [size] of Base Relocation Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		printf("%d [%d] RVA [size] of Debug Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
		printf("%d [%d] RVA [size] of Architecture Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
		printf("%d [%d] RVA [size] of Global Pointer Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
		printf("%d [%d] RVA [size] of Thread Storage Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
		printf("%d [%d] RVA [size] of Load Configuration Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
		printf("%d [%d] RVA [size] of Bound Import Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
		printf("%d [%d] RVA [size] of Import Address Table Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
		printf("%d [%d] RVA [size] of Delay Import Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
		printf("%d [%d] RVA [size] of COM Descriptor Directory\n",imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);
		printf("%d [%d] RVA [size] of Reserved Directory\n",imNTHeader->OptionalHeader.DataDirectory[15].VirtualAddress, imNTHeader->OptionalHeader.DataDirectory[15].Size);
		printf("\n");
		

		
		
		imsectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileBase + imdosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

		for(i = 0; i < imNTHeader->FileHeader.NumberOfSections; i++)
		{
			printf("\nSection Name: %.8s\n", imsectionHeader->Name);
			printf("Virtual Size: %d\n", imsectionHeader->Misc.VirtualSize);
			printf("Virtual Address: %d\n", imsectionHeader->VirtualAddress);
			printf("Size of raw data: %d\n", imsectionHeader->SizeOfRawData);
			printf("Pointer to the raw data: %d\n", imsectionHeader->PointerToRawData);
			printf("Pointer to relocation: %d\n", imsectionHeader->PointerToRelocations);
			printf("Pointer to LineNumbers: %d\n", imsectionHeader->PointerToLinenumbers);
			printf("Number of relocations in this section: %d\n", imsectionHeader->NumberOfRelocations);
			printf("Number of line numbers: %d\n", imsectionHeader->NumberOfLinenumbers);

			

			bFoundSectionCharacteristic = false;

			if((imsectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)
			{
				printf("This section contains executable code\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA)
			{
				printf("This section contains initialized data\n");
				bFoundSectionCharacteristic = true;
			}
			
			if((imsectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				printf("This section contains uninitialized data");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_LNK_INFO) == IMAGE_SCN_LNK_INFO)
			{
				printf("This section contains comments and other information. Applicable for obj files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_LNK_REMOVE) == IMAGE_SCN_LNK_REMOVE)
			{
				printf("This section will not be part of the image. Applicable for obj files\n");
					bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_LNK_COMDAT) == IMAGE_SCN_LNK_COMDAT)
			{
				printf("This section contains COMDAT data\n");
				bFoundSectionCharacteristic = true;

			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC) == IMAGE_SCN_NO_DEFER_SPEC_EXC)
			{
				printf("Reset speculative exceptions handling bits in the TLB entries for this section\n");
				bFoundSectionCharacteristic = true;

			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_GPREL) == IMAGE_SCN_GPREL)
			{
				printf("The section contains data referenced through the global pointer\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_1BYTES) == IMAGE_SCN_ALIGN_1BYTES)
			{
				printf("Align data on a 1-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;

			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_2BYTES) == IMAGE_SCN_ALIGN_2BYTES)
			{
				printf("Align data on a 2-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_4BYTES) == IMAGE_SCN_ALIGN_4BYTES)
			{
				printf("Align data on a 4-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_8BYTES) == IMAGE_SCN_ALIGN_8BYTES)
			{
				printf("Align data on a 8-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_16BYTES) == IMAGE_SCN_ALIGN_16BYTES)
			{
				printf("Align data on a 16-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_32BYTES) == IMAGE_SCN_ALIGN_32BYTES)
			{
				printf("Align data on a 32-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_64BYTES) == IMAGE_SCN_ALIGN_64BYTES)
			{
				printf("Align data on a 64-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_128BYTES) == IMAGE_SCN_ALIGN_128BYTES)
			{
				printf("Align data on a 128-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_256BYTES) == IMAGE_SCN_ALIGN_256BYTES)
			{
				printf("Align data on a 256-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_512BYTES) == IMAGE_SCN_ALIGN_512BYTES)
			{
				printf("Align data on a 512-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_1024BYTES) == IMAGE_SCN_ALIGN_1024BYTES)
			{
				printf("Align data on a 1024-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_2048BYTES) == IMAGE_SCN_ALIGN_2048BYTES)
			{
				printf("Align data on a 2048-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_4096BYTES) == IMAGE_SCN_ALIGN_4096BYTES)
			{
				printf("Align data on a 4096-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_ALIGN_8192BYTES) == IMAGE_SCN_ALIGN_8192BYTES)
			{
				printf("Align data on a 8192-byte boundary. This is valid only for object files\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) == IMAGE_SCN_LNK_NRELOC_OVFL)
			{
				printf("This section contains extended relocations\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == IMAGE_SCN_MEM_DISCARDABLE)
			{
				printf("This section can be discarded as needed\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED)
			{
				printf("This section cannot be cached\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == IMAGE_SCN_MEM_NOT_PAGED)
			{
				printf("This section cannot be paged\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
			{
				printf("This section can be shared in memory\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
			{
				printf("This section can be executed as code\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)
			{
				printf("This section can be read\n");
				bFoundSectionCharacteristic = true;
			}

			if((imsectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)
			{
				printf("This section can be written to\n");
				bFoundSectionCharacteristic = true;
			}

			if(!bFoundSectionCharacteristic)
			{
				printf("Found an unkown or reserved characteristic. ");	
				printf("Characteristics of this section: %d\n", imsectionHeader->Characteristics);
			}

			if(imsectionHeader->SizeOfRawData != 0)
			{
				printf("\n\nRaw data of the %.8s section\n", imsectionHeader->Name);
				nSectionSize = imsectionHeader->SizeOfRawData;
				pbSectionBuffer = (BYTE*)malloc(nSectionSize*sizeof(BYTE));
				memset(pbSectionBuffer, '\0', imsectionHeader->SizeOfRawData);
				SetFilePointer(hFile, imsectionHeader->PointerToRawData, NULL, FILE_BEGIN);
				ReadFile(hFile, pbSectionBuffer, imsectionHeader->SizeOfRawData, &dwBytesRead, NULL);
				memset(archSectionLine, '\0', 69);
				memset(archSectionLine, ' ', 67);
				k = 0;
				dwSectionAddresses = imNTHeader->OptionalHeader.ImageBase + imsectionHeader->VirtualAddress;
				for(j = 0; j < nSectionSize; j++)
				{

					bTempByte = pbSectionBuffer[j];
					memset(archtempByteArray, '\0', 3);
					archtempByteArray[0]= '0';
					archtempByteArray[1] = '0';
					switch(bTempByte)
					{
					case 0x00:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '0';
							break;
						}
					case 0x01:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '1';
							break;
						}
					case 0x02:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '2';
							break;
						}
					case 0x03:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '3';
							break;
						}
					case 0x04:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '4';
							break;
						}
					case 0x05:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '5';
							break;
						}
					case 0x06:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '6';
							break;
						}
					case 0x07:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '7';
							break;
						}
					case 0x08:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '8';
							break;
						}
					case 0x09:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = '9';
							break;
						}
					case 0x0a:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = 'a';
							break;
						}
					case 0x0b:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = 'b';
							break;
						}
					case 0x0c:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = 'c';
							break;
						}
					case 0x0d:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = 'd';
							break;
						}
					case 0x0e:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = 'e';
							break;
						}
					case 0x0f:
						{
							archtempByteArray[0]= '0';
							archtempByteArray[1] = 'f';
							break;
						}
					default:
						{
							sprintf(archtempByteArray, "%x", bTempByte);
							break;
						}
					}
					//sprintf(archtempByteArray, "%x", bTempByte);
					if(bTempByte != 0x00)
					{
						chTempChar = bTempByte;
					}
					else
					{
						chTempChar = '.';
					}
					switch(k)
					{
					case 0:
					{
						archSectionLine[0] = ':';
						archSectionLine[1] = archSectionLine[4] = archSectionLine[7] = archSectionLine[10] = archSectionLine[13] = archSectionLine[16] = archSectionLine[19] = archSectionLine[22] = archSectionLine[25] = archSectionLine[28] = archSectionLine[31] = archSectionLine[34] = archSectionLine[37] = archSectionLine[40] = archSectionLine[43] = archSectionLine[46] = archSectionLine[49] = archSectionLine[50] = ' ';
						for(l = 51; l < 66; l++)
							archSectionLine[l] = '.';

						archSectionLine[2] = archtempByteArray[0];
						archSectionLine[3] = archtempByteArray[1];
						archSectionLine[51] = chTempChar;

						k++;
						break;

					}
					case 1:
						{
							archSectionLine[5] = archtempByteArray[0];
							archSectionLine[6] = archtempByteArray[1];
							archSectionLine[52] = chTempChar;
							k++;
							break;
						}
					case 2:
						{
							archSectionLine[8] = archtempByteArray[0];
							archSectionLine[9] = archtempByteArray[1];
							archSectionLine[53] = chTempChar;
							k++;
							break;
						}
					case 3:
						{
							archSectionLine[11] = archtempByteArray[0];
							archSectionLine[12] = archtempByteArray[1];
							archSectionLine[54] = chTempChar;
							k++;
							break;
						}
					case 4:
						{
							archSectionLine[14] = archtempByteArray[0];
							archSectionLine[15] = archtempByteArray[1];
							archSectionLine[55] = chTempChar;
							k++;
							break;
						}
					case 5:
						{
							archSectionLine[17] = archtempByteArray[0];
							archSectionLine[18] = archtempByteArray[1];
							archSectionLine[56] = chTempChar;
							k++;
							break;
						}
					case 6:
						{
							archSectionLine[20] = archtempByteArray[0];
							archSectionLine[21] = archtempByteArray[1];
							archSectionLine[57] = chTempChar;
							k++;
							break;
						}
					case 7:
						{
							archSectionLine[23] = archtempByteArray[0];
							archSectionLine[24] = archtempByteArray[1];
							archSectionLine[58] = chTempChar;
							k++;
							break;
						}
					case 8:
						{
							archSectionLine[26] = archtempByteArray[0];
							archSectionLine[27] = archtempByteArray[1];
							archSectionLine[59] = chTempChar;
							k++;
							break;
						}
					case 9:
						{
							archSectionLine[29] = archtempByteArray[0];
							archSectionLine[30] = archtempByteArray[1];
							archSectionLine[60] = chTempChar;
							k++;
							break;
						}
					case 10:
						{
							archSectionLine[32] = archtempByteArray[0];
							archSectionLine[33] = archtempByteArray[1];
							archSectionLine[61] = chTempChar;
							k++;
							break;
						}
					case 11:
						{
							archSectionLine[35] = archtempByteArray[0];
							archSectionLine[36] = archtempByteArray[1];
							archSectionLine[62] = chTempChar;
							k++;
							break;
						}
					case 12:
						{
							archSectionLine[38] = archtempByteArray[0];
							archSectionLine[39] = archtempByteArray[1];
							archSectionLine[63] = chTempChar;
							k++;
							break;
						}
					case 13:
						{
							archSectionLine[41] = archtempByteArray[0];
							archSectionLine[42] = archtempByteArray[1];
							archSectionLine[64] = chTempChar;
							k++;
							break;
						}
					case 14:
						{
							archSectionLine[44] = archtempByteArray[0];
							archSectionLine[45] = archtempByteArray[1];
							archSectionLine[65] = chTempChar;
							k++;
							break;
						}
					case 15:
						{
							archSectionLine[47] = archtempByteArray[0];
							archSectionLine[48] = archtempByteArray[1];
							archSectionLine[66] = chTempChar;
							printf("%x%s\n", dwSectionAddresses,archSectionLine);
							dwSectionAddresses += 16;
							k = 0;
							break;
						}

					}

				}

				if(k != 15)
				{
					printf("%x%s\n", dwSectionAddresses,archSectionLine);
					k = 0;
				}

				free(pbSectionBuffer);
				printf("\n\n");
			}

			imsectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)imsectionHeader + sizeof(IMAGE_SECTION_HEADER));
		}

		if(imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
		{
			printf("\n\nExport Function Details\n");

			dwExportDirectory = RVAToOffset(lpFileBase, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			imExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpFileBase + dwExportDirectory);

			
			printf("Name of the module: %s\n", (PCHAR)((DWORD)lpFileBase + RVAToOffset(lpFileBase, imExportDir->Name)));
			printf("Number of Functions:%d\n", imExportDir->NumberOfFunctions);
			printf("Number of Names: %d\n", imExportDir->NumberOfNames);
			printf("Base:%d\n", imExportDir->Base);
			printf("Characteristics:%d\n", imExportDir->Characteristics);
			printf("Major Version:%d\n", imExportDir->MajorVersion);
			printf("Minor Version:%d\n", imExportDir->MinorVersion);
			printf("TimeDateStamp:%d\n\n", imExportDir->TimeDateStamp);
			
			dwBase = imExportDir->Base;
			dwFunctions = RVAToOffset(lpFileBase, imExportDir->AddressOfFunctions);
			dwNamesOfFunctions = RVAToOffset(lpFileBase, imExportDir->AddressOfNames);
			dwFunctionOrdinals = RVAToOffset(lpFileBase, imExportDir->AddressOfNameOrdinals);

			pdwNamesOfFunctions = (PDWORD*)((DWORD)lpFileBase + dwNamesOfFunctions);
			pdwFunctionAddresses = (PDWORD*)((DWORD)lpFileBase + dwFunctions);
			pdwFunctionOrdinals = (PDWORD*)((DWORD)lpFileBase + dwFunctionOrdinals);
			
			wTempFunctionOrdinals = (WORD*)pdwFunctionOrdinals;
			
			for(i = 0; i < imExportDir->NumberOfNames; i++)
			{
				
				printf("Ordinal Number:%d,\tRVA of the Function:%x,\tFunction Name:%s\n", wTempFunctionOrdinals[i]+dwBase, pdwFunctionAddresses[wTempFunctionOrdinals[i]], (char*)((DWORD)lpFileBase + RVAToOffset(lpFileBase,(DWORD)pdwNamesOfFunctions[i])));
								
			}

			printf("\n\n");



			

		}

		if(imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
		{
			printf("\nImport Function Details\n\n");

			dwImportDirectory = RVAToOffset(lpFileBase, imNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			imImportDescript = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpFileBase + dwImportDirectory);
			
			while(imImportDescript->Name != NULL)
			{
				libname = (PCHAR)((DWORD)lpFileBase +RVAToOffset(lpFileBase, imImportDescript->Name));
				
				printf("Following Functions imported from dll %s, its RVA is %x, TimeDateStamp is %d, ForwordChain = %d   \n", libname, imImportDescript->Name, imImportDescript->TimeDateStamp, imImportDescript->ForwarderChain);
				
				if(imImportDescript->OriginalFirstThunk != NULL)
				{
					imThunkData = (PIMAGE_THUNK_DATA)((DWORD)lpFileBase + RVAToOffset(lpFileBase, imImportDescript->OriginalFirstThunk));
					while(imThunkData->u1.AddressOfData != NULL)
					{
						if(IMAGE_ORDINAL_FLAG32 == ((DWORD)imThunkData->u1.AddressOfData & IMAGE_ORDINAL_FLAG32))
						{
							
							printf("\tOrdinalNumber=%d\n",((DWORD)imThunkData->u1.AddressOfData & 0x7FFFFFFF));

						}
						else
						{
							imFunNameImport = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpFileBase + RVAToOffset(lpFileBase, imThunkData->u1.Function));
							
							printf("\t%s\n", imFunNameImport->Name);

						}

						imThunkData++;
					}


				}
				else
				{
					imThunkData = (PIMAGE_THUNK_DATA)((DWORD)lpFileBase + RVAToOffset(lpFileBase, imImportDescript->FirstThunk));
					while(imThunkData->u1.AddressOfData != NULL)
					{
						if(IMAGE_ORDINAL_FLAG32 == ((DWORD)imThunkData->u1.AddressOfData & IMAGE_ORDINAL_FLAG32))
						{
							
							printf("\tOrdinalNumber=%d\n",((DWORD)imThunkData->u1.AddressOfData & 0x7FFFFFFF));

						}
						else
						{
							imFunNameImport = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpFileBase + RVAToOffset(lpFileBase, imThunkData->u1.Function));
							
							printf("\t%s\n", imFunNameImport->Name);

						}

						imThunkData++;
					}

				}
				imImportDescript++;
				
			}

			

		}

		printf("\n************************************************************************************************************************************************************************************\n");
		printf("\n***************************************************************************************END OF PARSING PE FILE***********************************************************************\n");
		printf("\n************************************************************************************************************************************************************************************\n");

	}
	else
	{
		//Unrecognized format cannot parse the file
		printf("Unrecognized format cannot parese the file\n");
		nReturnValue = -5;
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return nReturnValue;
	}

	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	return nReturnValue;
}




/*
Name: RVAToOffset
Parameters: lpFileBase - This is the image base, usually got when you map the file to memory. I think this is the actual memory location where the file starts.
			dwRVA - Relative Virtual Address which needs to be converted to offset.
ReturnValue:	Offset of the dwRVA
Description:	This function will convert the relative virtual address to an offset from lpFileBase i.e. image base [starting memory location of the file]
*/

DWORD RVAToOffset(LPVOID lpFileBase, DWORD dwRVA)
{

	DWORD _offset = 0;
	int j = 0;
	PIMAGE_SECTION_HEADER imsectionHeader = NULL;
	PIMAGE_NT_HEADERS imNTHeader = NULL;
	PIMAGE_DOS_HEADER imdosHeader = NULL;

	imdosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	imNTHeader = (PIMAGE_NT_HEADERS)((DWORD)imdosHeader + imdosHeader->e_lfanew);
	imsectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileBase + imdosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for(j = 0; j< imNTHeader->FileHeader.NumberOfSections; j++)
	{
		if(dwRVA >= imsectionHeader->VirtualAddress && (dwRVA < (imsectionHeader->VirtualAddress+imsectionHeader->SizeOfRawData)))
		{
			_offset = dwRVA + imsectionHeader->PointerToRawData - imsectionHeader->VirtualAddress;
			break;
		}
		imsectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)imsectionHeader + sizeof(IMAGE_SECTION_HEADER));

	}

	return _offset;
}

/*
*Name: GetAnInstruction
*Description: This is an initialization code of Instruction struction.
*Parameter: byOpcode - Opcode whose instruction being created
*			nPrefixSize - Number of prefix
*			byarPrefix - array of prefix bytes
*ReturnValue: returns the created instruction structure.
*/
Instruction* GetAnInstruction(BYTE byOpcode, int nPrefixSize, BYTE* byarPrefix)
{
	int nReturnValue = 0;
	BYTE* byarTempOpcode = NULL;
	Instruction* pInst = NULL;

	pInst = (Instruction*)malloc(sizeof(Instruction));
	byarTempOpcode = (BYTE*)malloc(sizeof(BYTE)*1);
	byarTempOpcode[0] = byOpcode;
	pInst->OpcodePart = byarTempOpcode;
	pInst->OpcodeSize = 1;
	pInst->PrefixSize = nPrefixSize;
	pInst->PrefixPart = byarPrefix;
	pInst->bmodRMExists = false;
	pInst->bSibExists = false;
	pInst->Displacement = 0;
	pInst->DisplacementSize = 0;
	pInst->Immediate = 0;
	pInst->ImmediateSize = 0;
	pInst->sibpart = 0;
	pInst->LengthOfInstruction = pInst->PrefixSize + 1;

	return pInst;
}

/*
Name: DisAssembleBytes32
Parameters: pbyCode - this is an array containing raw code section
			nSize - Size of the pbyCode array
ReturnValue: 0 for success else -1
Description: This function recieves an array of bytes and converts them into a assembly instructions. This is only for 32 bit applications or PE files
*/
int DisAssembleBytes32(BYTE* pbyCode, int nSize)
{
	int nReturnValue = 0;
	int i = 0;
	int iterator = 0;
	bool bFoundGroup1prefix = false, bFoundGroup2prefix = false, bFoundGroup3prefix = false, bFoundGroup4prefix = false;
	bool bTimeToGetOutOfPrefixSearch = false;
	bool bModRMByteRequired = false;
	bool bSIBBytesRequired = false;
	bool bDisplacementRequired = false;
	bool bImmediateRequired = false;
	bool bPossible2Or3ByteOpCodes = false;
	bool bFound0FOpcode = false;
	BYTE byPrefix[4] = {0x00};
	

	while(i < nSize)
	{
		/*if(pbyCode[i] != 0x00)
		{


		}*/

		//Get the prefix
		bFoundGroup1prefix = false;
		bFoundGroup2prefix = false;
		bFoundGroup3prefix = false;
		bFoundGroup4prefix = false;
		bTimeToGetOutOfPrefixSearch = false;

		for(iterator = 0; iterator < 4; iterator++)
		{
			byPrefix[iterator] = 0x00;
		}
		iterator = 0;

		while(iterator < 4 && i+iterator < nSize && nReturnValue == 0)		//prefix can have at most 4 bytes
		{
			switch(pbyCode[i+iterator])
			{
			case 0xF0:
				{
					if(!bFoundGroup1prefix)
					{
						bFoundGroup1prefix = true;
						byPrefix[iterator] = 0xF0;
					}
					else
					{
						nReturnValue = -1;	//Already group1 prefix found so another one is present something wrong

					}
					break;
				}
			case 0xF2:
				{
					if(!bFoundGroup1prefix)
					{
						bFoundGroup1prefix = true;
						bPossible2Or3ByteOpCodes = true;
						byPrefix[iterator] = 0xF2;
					}
					else
					{
						nReturnValue = -1;	//Already group1 prefix found so another one is present something wrong

					}
					break;
				}
			case 0xF3:
				{
					if(!bFoundGroup1prefix)
					{
						bFoundGroup1prefix = true;
						bPossible2Or3ByteOpCodes = true;
						byPrefix[iterator] = 0xF3;
					}
					else
					{
						nReturnValue = -1;	//Already group1 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x2E:
				{
					if(!bFoundGroup2prefix)
					{
						bFoundGroup2prefix = true;
						byPrefix[iterator] = 0x2E;
					}
					else
					{
						nReturnValue = -1;	//Already group2 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x36:
				{
					if(!bFoundGroup2prefix)
					{
						bFoundGroup2prefix = true;
						byPrefix[iterator] = 0x36;
					}
					else
					{
						nReturnValue = -1;	//Already group2 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x3E:
				{
					if(!bFoundGroup2prefix)
					{
						bFoundGroup2prefix = true;
						byPrefix[iterator] = 0x3E;
					}
					else
					{
						nReturnValue = -1;	//Already group2 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x26:
				{
					if(!bFoundGroup2prefix)
					{
						bFoundGroup2prefix = true;
						byPrefix[iterator] = 0x26;
					}
					else
					{
						nReturnValue = -1;	//Already group2 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x64:
				{
					if(!bFoundGroup2prefix)
					{
						bFoundGroup2prefix = true;
					}
					else
					{
						nReturnValue = -1;	//Already group2 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x65:
				{
					if(!bFoundGroup2prefix)
					{
						bFoundGroup2prefix = true;
						byPrefix[iterator] = 0x65;
					}
					else
					{
						nReturnValue = -1;	//Already group2 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x66:
				{
					if(!bFoundGroup3prefix)
					{
						bFoundGroup3prefix = true;
						bPossible2Or3ByteOpCodes = true;
						byPrefix[iterator] = 0x66;
					}
					else
					{
						nReturnValue = -1;	//Already group3 prefix found so another one is present something wrong

					}
					break;
				}
			case 0x67:
				{
					if(!bFoundGroup4prefix)
					{
						bFoundGroup4prefix = true;
						byPrefix[iterator] = 0x67;
					}
					else
					{
						nReturnValue = -1;	//Already group4 prefix found so another one is present something wrong

					}
					break;
				}
			default:
				{

					bTimeToGetOutOfPrefixSearch = true;
					break;
				}
				
			}

			if(!bTimeToGetOutOfPrefixSearch)
			{
				iterator++;
			}
			else
			{
				i += iterator;
				break;
			}
		}


		iterator = 0;

		while(iterator < 3 && i+iterator < nSize && nReturnValue == 0)
		{
			if(iterator == 0 && pbyCode[i+iterator] == 0x0F)
			{
				iterator++;
				bPossible2Or3ByteOpCodes = true;
				bFound0FOpcode = true;
				//Either 2 or 3 byte opcode
			}
			else if(bFound0FOpcode && iterator == 1 && pbyCode[i+iterator] == 0x38 || pbyCode[i+iterator] == 0x3A)
			{
				iterator++;
				//This is a 3 byte opcode;

			}
			else
			{
				GetAnInstruction(pbyCode[i], iterator, byPrefix);
				//This is a 1 byte opcode
				switch(iterator)
				{
				case 0:
					{
						break;
					}
				case 1:
					{
						break;
					}
				case 2:
					{
						break;
					}
				default:
					{
						break;
					}
				}

			}


		}





	}


	return nReturnValue;
}



/*
*Name: InitializeDissassemblyEngine
*Description: This function initializes the dissassembly engine. It files the function pointer array which will be used during dissassembling code sections
*Return: 0 For success, else some error has occurred
*/
int InitializeDissassemblyEngine()
{
	int nReturnValue = 0;

	/*pt2Function DecodeFunctions[256] = {NULL};
	pt2Function DecodeFunctions_2[256] = {NULL};
	pt2Function DecodeFunctions_3[256] = {NULL};*/

	DecodeFunctions[0] = &DecodeADD;


	/*char** archREGFields_8 = {NULL};
	char** archREGFields_16 = {NULL};
	char** archREGFields_32 = {NULL};
	char** archREGFields_mm = {NULL};
	char** archREGFields_xmm = {NULL};*/

	/*char** archMODRMFields_16 = {NULL};
	char** archMODRMFields_32 = {NULL};*/

	archREGFields_8 = (char**)malloc(sizeof(char*)*8);
	archREGFields_16 = (char**)malloc(sizeof(char*)*8);
	archREGFields_32 = (char**)malloc(sizeof(char*)*8);
	archREGFields_mm = (char**)malloc(sizeof(char*)*8);
	archREGFields_xmm = (char**)malloc(sizeof(char*)*8);

	archMODRMFields_16 = (char**)malloc(sizeof(char*)*8);
	archMODRMFields_32 = (char**)malloc(sizeof(char*)*8);
	//archMODRMFields_2 = (char**)malloc(sizeof(char*)*8);

	archSIBIndex = (char**)malloc(sizeof(char*)*8);
	archSIBBase = (char**)malloc(sizeof(char*)*8);

	for(int i = 0; i < 8; i++)
	{
		archREGFields_8[i] = (char*)malloc(sizeof(char)*8);
		archREGFields_16[i] = (char*)malloc(sizeof(char)*8);
		archREGFields_32[i] = (char*)malloc(sizeof(char)*8);
		archREGFields_mm[i] = (char*)malloc(sizeof(char)*8);
		archREGFields_xmm[i] = (char*)malloc(sizeof(char)*8);

		archMODRMFields_16[i] = (char*)malloc(sizeof(char)*8);
		archMODRMFields_32[i] = (char*)malloc(sizeof(char)*8);
		//archMODRMFields_2[i] = (char*)malloc(sizeof(char)*8);

		archSIBIndex[i] = (char*)malloc(sizeof(char)*8);
		archSIBBase[i] = (char*)malloc(sizeof(char)*8);

		memset(archREGFields_8[i], '\0', 8);
		memset(archREGFields_16[i], '\0', 8);
		memset(archREGFields_32[i], '\0', 8);
		memset(archREGFields_mm[i], '\0', 8);
		memset(archREGFields_xmm[i], '\0', 8);

		memset(archSIBIndex[i], '\0', 8);
		memset(archSIBBase[i], '\0', 8);

		memset(archMODRMFields_16[i], '\0', 8);
		memset(archMODRMFields_32[i], '\0', 8);
		//memset(archMODRMFields_2[i], '\0', 8);

	}

	sprintf_s(archREGFields_8[0],sizeof(char)*8, "AL");
	sprintf_s(archREGFields_8[1],sizeof(char)*8, "CL");
	sprintf_s(archREGFields_8[2],sizeof(char)*8, "DL");
	sprintf_s(archREGFields_8[3],sizeof(char)*8, "BL");
	sprintf_s(archREGFields_8[4],sizeof(char)*8, "AH");
	sprintf_s(archREGFields_8[5],sizeof(char)*8, "CH");
	sprintf_s(archREGFields_8[6],sizeof(char)*8, "DH");
	sprintf_s(archREGFields_8[7],sizeof(char)*8, "BH");

	sprintf_s(archREGFields_16[0],sizeof(char)*8, "AX");
	sprintf_s(archREGFields_16[1],sizeof(char)*8, "CX");
	sprintf_s(archREGFields_16[2],sizeof(char)*8, "DX");
	sprintf_s(archREGFields_16[3],sizeof(char)*8, "BX");
	sprintf_s(archREGFields_16[4],sizeof(char)*8, "SP");
	sprintf_s(archREGFields_16[5],sizeof(char)*8, "BP");
	sprintf_s(archREGFields_16[6],sizeof(char)*8, "SI");
	sprintf_s(archREGFields_16[7],sizeof(char)*8, "DI");

	sprintf_s(archREGFields_32[0],sizeof(char)*8, "EAX");
	sprintf_s(archREGFields_32[1],sizeof(char)*8, "ECX");
	sprintf_s(archREGFields_32[2],sizeof(char)*8, "EDX");
	sprintf_s(archREGFields_32[3],sizeof(char)*8, "EBX");
	sprintf_s(archREGFields_32[4],sizeof(char)*8, "ESP");
	sprintf_s(archREGFields_32[5],sizeof(char)*8, "EBP");
	sprintf_s(archREGFields_32[6],sizeof(char)*8, "ESI");
	sprintf_s(archREGFields_32[7],sizeof(char)*8, "EDI");

	sprintf_s(archREGFields_mm[0],sizeof(char)*8, "MM0");
	sprintf_s(archREGFields_mm[1],sizeof(char)*8, "MM1");
	sprintf_s(archREGFields_mm[2],sizeof(char)*8, "MM2");
	sprintf_s(archREGFields_mm[3],sizeof(char)*8, "MM3");
	sprintf_s(archREGFields_mm[4],sizeof(char)*8, "MM4");
	sprintf_s(archREGFields_mm[5],sizeof(char)*8, "MM5");
	sprintf_s(archREGFields_mm[6],sizeof(char)*8, "MM6");
	sprintf_s(archREGFields_mm[7],sizeof(char)*8, "MM7");

	sprintf_s(archREGFields_xmm[0],sizeof(char)*8, "XMM0");
	sprintf_s(archREGFields_xmm[1],sizeof(char)*8, "XMM1");
	sprintf_s(archREGFields_xmm[2],sizeof(char)*8, "XMM2");
	sprintf_s(archREGFields_xmm[3],sizeof(char)*8, "XMM3");
	sprintf_s(archREGFields_xmm[4],sizeof(char)*8, "XMM4");
	sprintf_s(archREGFields_xmm[5],sizeof(char)*8, "XMM5");
	sprintf_s(archREGFields_xmm[6],sizeof(char)*8, "XMM6");
	sprintf_s(archREGFields_xmm[7],sizeof(char)*8, "XMM7");

	sprintf_s(archMODRMFields_16[0],sizeof(char)*8, "BX+SI");
	sprintf_s(archMODRMFields_16[1],sizeof(char)*8, "BX+DI");
	sprintf_s(archMODRMFields_16[2],sizeof(char)*8, "BP+SI");
	sprintf_s(archMODRMFields_16[3],sizeof(char)*8, "BP+DI");
	sprintf_s(archMODRMFields_16[4],sizeof(char)*8, "SI");
	sprintf_s(archMODRMFields_16[5],sizeof(char)*8, "DI");
	sprintf_s(archMODRMFields_16[6],sizeof(char)*8, "***");
	sprintf_s(archMODRMFields_16[7],sizeof(char)*8, "BX");

	sprintf_s(archMODRMFields_32[0],sizeof(char)*8, "EAX");
	sprintf_s(archMODRMFields_32[1],sizeof(char)*8, "ECX");
	sprintf_s(archMODRMFields_32[2],sizeof(char)*8, "EDX");
	sprintf_s(archMODRMFields_32[3],sizeof(char)*8, "EBX");
	sprintf_s(archMODRMFields_32[4],sizeof(char)*8, "***");
	sprintf_s(archMODRMFields_32[5],sizeof(char)*8, "***");
	sprintf_s(archMODRMFields_32[6],sizeof(char)*8, "ESI");
	sprintf_s(archMODRMFields_32[7],sizeof(char)*8, "EDI");

	sprintf_s(archSIBIndex[0], sizeof(char)*8, "EAX");
	sprintf_s(archSIBIndex[1], sizeof(char)*8, "ECX");
	sprintf_s(archSIBIndex[2], sizeof(char)*8, "EDX");
	sprintf_s(archSIBIndex[3], sizeof(char)*8, "EBX");
	sprintf_s(archSIBIndex[4], sizeof(char)*8, "---");
	sprintf_s(archSIBIndex[5], sizeof(char)*8, "EBP");
	sprintf_s(archSIBIndex[6], sizeof(char)*8, "ESI]");
	sprintf_s(archSIBIndex[7], sizeof(char)*8, "EDI");

	sprintf_s(archSIBBase[0], sizeof(char)*8, "EAX");
	sprintf_s(archSIBBase[1], sizeof(char)*8, "ECX");
	sprintf_s(archSIBBase[2], sizeof(char)*8, "EDX");
	sprintf_s(archSIBBase[3], sizeof(char)*8, "EBX");
	sprintf_s(archSIBBase[4], sizeof(char)*8, "ESP");
	sprintf_s(archSIBBase[5], sizeof(char)*8, "disp");
	sprintf_s(archSIBBase[6], sizeof(char)*8, "ESI");
	sprintf_s(archSIBBase[7], sizeof(char)*8, "EDI");


	DecodeFunctions[0x00] = &DecodeADD;
	DecodeFunctions[0x01] = &DecodeADD;
	DecodeFunctions[0x02] = &DecodeADD;
	DecodeFunctions[0x03] = &DecodeADD;
	DecodeFunctions[0x04] = &DecodeADD;
	DecodeFunctions[0x05] = &DecodeADD;

	DecodeFunctions[0x06] = &DecodePushPoP;
	DecodeFunctions[0x07] = &DecodePushPoP;
	DecodeFunctions[0x0E] = &DecodePushPoP;
	DecodeFunctions[0x16] = &DecodePushPoP;
	DecodeFunctions[0x17] = &DecodePushPoP;
	DecodeFunctions[0x1E] = &DecodePushPoP;
	DecodeFunctions[0x1F] = &DecodePushPoP;
	DecodeFunctions[0x50] = &DecodePushPoP;
	DecodeFunctions[0x51] = &DecodePushPoP;
	DecodeFunctions[0x52] = &DecodePushPoP;
	DecodeFunctions[0x53] = &DecodePushPoP;
	DecodeFunctions[0x54] = &DecodePushPoP;
	DecodeFunctions[0x55] = &DecodePushPoP;
	DecodeFunctions[0x56] = &DecodePushPoP;
	DecodeFunctions[0x57] = &DecodePushPoP;
	DecodeFunctions[0x58] = &DecodePushPoP;
	DecodeFunctions[0x59] = &DecodePushPoP;
	DecodeFunctions[0x5A] = &DecodePushPoP;
	DecodeFunctions[0x5B] = &DecodePushPoP;
	DecodeFunctions[0x5C] = &DecodePushPoP;
	DecodeFunctions[0x5D] = &DecodePushPoP;
	DecodeFunctions[0x5E] = &DecodePushPoP;
	DecodeFunctions[0x5F] = &DecodePushPoP;
	DecodeFunctions[0x60] = &DecodePushPoP;
	DecodeFunctions[0x61] = &DecodePushPoP;
	DecodeFunctions[0x68] = &DecodePushPoP;
	DecodeFunctions[0x6A] = &DecodePushPoP;
	DecodeFunctions[0x9C] = &DecodePushPoP;
	DecodeFunctions[0x9D] = &DecodePushPoP;

	DecodeFunctions[0x08] = &DecodeOR;
	DecodeFunctions[0x09] = &DecodeOR;
	DecodeFunctions[0x0A] = &DecodeOR;
	DecodeFunctions[0x0B] = &DecodeOR;
	DecodeFunctions[0x0C] = &DecodeOR;
	DecodeFunctions[0x0D] = &DecodeOR;

	DecodeFunctions[0x10] = &DecodeADC;
	DecodeFunctions[0x11] = &DecodeADC;
	DecodeFunctions[0x12] = &DecodeADC;
	DecodeFunctions[0x13] = &DecodeADC;
	DecodeFunctions[0x14] = &DecodeADC;
	DecodeFunctions[0x15] = &DecodeADC;

	DecodeFunctions[0x18] = &DecodeSBB;
	DecodeFunctions[0x19] = &DecodeSBB;
	DecodeFunctions[0x1A] = &DecodeSBB;
	DecodeFunctions[0x1B] = &DecodeSBB;
	DecodeFunctions[0x1C] = &DecodeSBB;
	DecodeFunctions[0x1D] = &DecodeSBB;

	DecodeFunctions[0x20] = &DecodeAND;
	DecodeFunctions[0x21] = &DecodeAND;
	DecodeFunctions[0x22] = &DecodeAND;
	DecodeFunctions[0x23] = &DecodeAND;
	DecodeFunctions[0x24] = &DecodeAND;
	DecodeFunctions[0x25] = &DecodeAND;

	DecodeFunctions[0x27] = &DecodeDAA;

	DecodeFunctions[0x28] = &DecodeSUB;
	DecodeFunctions[0x29] = &DecodeSUB;
	DecodeFunctions[0x2A] = &DecodeSUB;
	DecodeFunctions[0x2B] = &DecodeSUB;
	DecodeFunctions[0x2C] = &DecodeSUB;
	DecodeFunctions[0x2D] = &DecodeSUB;

	DecodeFunctions[0x2F] = &DecodeDAS;

	DecodeFunctions[0x30] = &DecodeXOR;
	DecodeFunctions[0x31] = &DecodeXOR;
	DecodeFunctions[0x32] = &DecodeXOR;
	DecodeFunctions[0x33] = &DecodeXOR;
	DecodeFunctions[0x34] = &DecodeXOR;
	DecodeFunctions[0x35] = &DecodeXOR;

	DecodeFunctions[0x37] = &DecodeAAA;

	DecodeFunctions[0x38] = &DecodeCMP;
	DecodeFunctions[0x39] = &DecodeCMP;
	DecodeFunctions[0x3A] = &DecodeCMP;
	DecodeFunctions[0x3B] = &DecodeCMP;
	DecodeFunctions[0x3C] = &DecodeCMP;
	DecodeFunctions[0x3D] = &DecodeCMP;
	DecodeFunctions[0xA6] = &DecodeCMP;
	DecodeFunctions[0xA7] = &DecodeCMP;

	DecodeFunctions[0x3F] = &DecodeAAS;

	DecodeFunctions[0x40] = &DecodeINC;
	DecodeFunctions[0x41] = &DecodeINC;
	DecodeFunctions[0x42] = &DecodeINC;
	DecodeFunctions[0x43] = &DecodeINC;
	DecodeFunctions[0x44] = &DecodeINC;
	DecodeFunctions[0x45] = &DecodeINC;
	DecodeFunctions[0x46] = &DecodeINC;
	DecodeFunctions[0x47] = &DecodeINC;

	DecodeFunctions[0x48] = &DecodeDEC;
	DecodeFunctions[0x49] = &DecodeDEC;
	DecodeFunctions[0x4A] = &DecodeDEC;
	DecodeFunctions[0x4B] = &DecodeDEC;
	DecodeFunctions[0x4C] = &DecodeDEC;
	DecodeFunctions[0x4D] = &DecodeDEC;
	DecodeFunctions[0x4E] = &DecodeDEC;
	DecodeFunctions[0x4F] = &DecodeDEC;

	DecodeFunctions[0x62] = &DecodeBOUND;

	DecodeFunctions[0x63] = &DecodeMOV;

	return nReturnValue;
}




/*
*Name:GetBinValueFromHex
*Description:	This function will convert a byte to its binary value. Remember binary value is in char* which is created using malloc. So needs to be freed once its work is done.
*Parameters:	bValue - Byte which needs to be converted
*Return:	binary value of bye as string. If Error its NULL. 
*/
char* GetBinValueFromHex(BYTE bValue)
{
	char strValue[16] = {0};
	char* strBinValue = NULL;
	int i = 0, j = 0;

	strBinValue = (char*)malloc(sizeof(char)*9);
	memset(strValue, '\0', 16);
	memset(strBinValue, '\0', sizeof(char)*9);

	sprintf(strValue, "%x", bValue);

	while(strValue[i])
	{
		switch(strValue[i])
		{
			case '0':
				{
					//printf("0000"); 
					sprintf_s(&strBinValue[j],sizeof(char)*9, "0000");

					break;
				}
 
             case '1':
				 {
					 //printf("0001"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0001");
					 break;
				 }
 
             case '2':
				 {
					 //printf("0010");
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0010");
					 break;
				 }
 
             case '3':
				 {
					 //printf("0011"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0011");
					 break;
				 }
 
             case '4':
				 {
					 //printf("0100");
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0100");
					 break;
				 }
 
             case '5':
				 {
					 //printf("0101"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0101");
					 break;
				 }
 
             case '6': 
				 {
					 //printf("0110"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0110");
					 break;
				 }
 
             case '7': 
				 {
					 //printf("0111"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "0111");
					 break;
				 }
 
             case '8': 
				 {
					 //printf("1000"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1000");
					 break;
				 }
 
             case '9': 
				 {
					 //printf("1001"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1001");
					 break;
				 }
 
             case 'A': 
				 {
					 //printf("1010"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1010");
					 break;
				 }
 
             case 'B': 
				 {
					 //printf("1011"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1011");
					 break;
				 }
 
             case 'C': 
				 {
					 //printf("1100"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1100");
					 break;
				 }
 
             case 'D': 
				 {
					 //printf("1101"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1101");
					 break;
				 }
 
             case 'E': 
				 {
					 //printf("1110"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1110");
					 break;
				 }
 
             case 'F': 
				 {
					 //printf("1111"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1111");
					 break;
				 }
 
             case 'a': 
				 {
					 //printf("1010"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1010");
					 break;
				 }
 
             case 'b': 
				 {
					 //printf("1011"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1011");
					 break;
				 }
 
             case 'c': 
				 {
					 //printf("1100"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1100");
					 break;
				 }
 
             case 'd': 
				 {
					 //printf("1101"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1101");
					 break;
				 }
 
             case 'e': 
				 {
					 //printf("1110"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1110");
					 break;
				 }
 
             case 'f': 
				 {
					 //printf("1111"); 
					 sprintf_s(&strBinValue[j],sizeof(char)*9, "1111");
					 break;
				 }
 
             default:  
				 {
					 
					 return NULL;
				 }
			}
 
       
		 j = strlen(strBinValue);
         i++;
	}

	return strBinValue;


}

/*
*Name: GetDecimalValueFromBinary
*Description: This function will return you decimal value for Binary value. Binary value should have size 3 bits
*Parameter: strBinValue - 3 bit size binary value
*ReturnValue: Decimal value of the binary string. If cannot find then -1.
*/
int GetDecimalValueFromBinary(char* strBinValue)
{
	int nRetVal = -1;

	if(strlen(strBinValue) != 3)
	{
		return nRetVal;
	}

	if(strBinValue[0] == '0' && strBinValue[1] =='0' && strBinValue[2] == '0')
	{
		nRetVal = 0;
	}
	else if(strBinValue[0] == '0' && strBinValue[1] =='0' && strBinValue[2] == '1')
	{
		nRetVal = 1;
	}
	else if(strBinValue[0] == '0' && strBinValue[1] =='1' && strBinValue[2] == '0')
	{
		nRetVal =  2;
	}
	else if(strBinValue[0] == '0' && strBinValue[1] =='1' && strBinValue[2] == '1')
	{
		nRetVal =  3;
	}
	else if(strBinValue[0] == '1' && strBinValue[1] =='0' && strBinValue[2] == '0')
	{
		nRetVal =  4;
	}
	else if(strBinValue[0] == '1' && strBinValue[1] =='0' && strBinValue[2] == '1')
	{
		nRetVal =  5;
	}
	else if(strBinValue[0] == '1' && strBinValue[1] =='1' && strBinValue[2] == '0')
	{
		nRetVal =  6;
	}
	else if(strBinValue[0] == '1' && strBinValue[1] =='1' && strBinValue[2] == '1')
	{
		nRetVal =  7;
	}
	else 
	{
		nRetVal =  -1;
	}

	return nRetVal;
}

/*
*Name: HexCharToInt
*Description: This function converts a hex character to integer value;
*Parameter: ch - Hex character which needs to be converted 
*Return: integer value of the hexadecimal character
*/

int HexCharToInt(char ch)
{
	int nRetVal = -1;

	switch(ch)
	{
	case '0':
		{
			nRetVal = 0;
			break;
		}
	case '1':
		{
			nRetVal = 1;
			break;
		}
	case '2':
		{
			nRetVal = 2;
			break;
		}
	case '3':
		{
			nRetVal = 3;
			break;
		}
	case '4':
		{
			nRetVal = 4;
			break;
		}
	case '5':
		{
			nRetVal = 5;
			break;
		}
	case '6':
		{
			nRetVal = 6;
			break;
		}
	case '7':
		{
			nRetVal = 7;
			break;
		}
	case '8':
		{
			nRetVal = 8;
			break;
		}
	case '9':
		{
			nRetVal = 9;
			break;
		}
	case 'a':
		{
			nRetVal = 10;
			break;
		}
	case 'A':
		{
			nRetVal = 10;
			break;
		}
	case 'b':
		{
			nRetVal = 11;
			break;
		}
	case 'B':
		{
			nRetVal = 11;
			break;
		}
	case 'c':
		{
			nRetVal = 12;
			break;
		}
	case 'C':
		{
			nRetVal = 12;
			break;
		}
	case 'd':
		{
			nRetVal = 13;
			break;
		}
	case 'D':
		{
			nRetVal = 13;
			break;
		}
	case 'e':
		{
			nRetVal = 14;
			break;
		}
	case 'E':
		{
			nRetVal = 14;
			break;
		}
	case 'f':
		{
			nRetVal = 15;
			break;
		}
	case 'F':
		{
			nRetVal = 15;
			break;
		}
	default:
		{
			nRetVal = -2;
			break;
		}

	}

	return nRetVal;
}

/*
*Name: GetDisplacementOfInstruction
*Description: This function will get you the displacement value in the instruction;
*Parameter: Buffer - byte array containing instructions
*			index - Current index where displacement value starts
*			nSize - Size of the displacement to be retrieved
*			pInst - Instruction whose displacement we are trying to retrieve
*Return: 0 for success else error
*/

int GetDisplacementOfInstruction(BYTE* Buffer, int index, int nSize, Instruction* pInst)
{
	int nRetVal = 0;
	char arTemp1[5] = {0};
	char arTemp2[5] = {0};
	char arTemp3[5] = {0};
	char arTemp4[5] = {0};

	//pInst->bDisplacementExists = true;
	pInst->DisplacementSize = nSize;
	pInst->Displacement = 0;

	if(pInst->DisplacementSize == 1)
	{
		sprintf_s(arTemp1,sizeof(char)*5, "%x", Buffer[index]);
		if(strlen(arTemp1) == 1)
		{
			arTemp1[1] = arTemp1[0];
			arTemp1[0] = '0';
		}
		pInst->Displacement = HexCharToInt(arTemp1[1])*1+ HexCharToInt(arTemp1[0])*16;

		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index]);
	}
	else if(pInst->DisplacementSize == 2)
	{
		sprintf_s(arTemp1,sizeof(char)*5, "%x", Buffer[index]);
		if(strlen(arTemp1) == 1)
		{
			arTemp1[1] = arTemp1[0];
			arTemp1[0] = '0';
		}
		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index]);
		sprintf_s(arTemp2,sizeof(char)*5, "%x", Buffer[index+1]);
		if(strlen(arTemp2) == 1)
		{
			arTemp2[1] = arTemp2[0];
			arTemp2[0] = '0';
		}
		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index+1]);

		pInst->Displacement = HexCharToInt(arTemp1[1])*1 + HexCharToInt(arTemp1[0])*16 + HexCharToInt(arTemp2[1])*256 + HexCharToInt(arTemp2[0])*4096; 
	}
	else if(pInst->DisplacementSize == 4)
	{
		sprintf_s(arTemp1,sizeof(char)*5, "%x", Buffer[index]);
		if(strlen(arTemp1) == 1)
		{
			arTemp1[1] = arTemp1[0];
			arTemp1[0] = '0';
		}
		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index]);
		sprintf_s(arTemp2,sizeof(char)*5, "%x", Buffer[index+1]);
		if(strlen(arTemp2) == 1)
		{
			arTemp2[1] = arTemp2[0];
			arTemp2[0] = '0';
		}
		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index+1]);
		sprintf_s(arTemp3,sizeof(char)*5, "%x", Buffer[index+2]);
		if(strlen(arTemp3) == 1)
		{
			arTemp3[1] = arTemp3[0];
			arTemp3[0] = '0';
		}
		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index+2]);
		sprintf_s(arTemp4,sizeof(char)*5, "%x", Buffer[index+3]);
		if(strlen(arTemp4) == 1)
		{
			arTemp4[1] = arTemp4[0];
			arTemp4[0] = '0';
		}
		//sprintf(strRawInstruction, "%s%x ",strRawInstruction, Buffer[index+3]);
		

		pInst->Displacement = HexCharToInt(arTemp1[1])*1 + HexCharToInt(arTemp1[0])*16 + HexCharToInt(arTemp2[1])*256 + HexCharToInt(arTemp2[0])*4096 + HexCharToInt(arTemp3[1])*65536 + HexCharToInt(arTemp3[0])*1048576 + HexCharToInt(arTemp4[1])*16777216 + HexCharToInt(arTemp4[0])*268435456;
	}

	return nRetVal;
}

/*
*Name: GetImmediateOfInstruction
*Description: This will get the actual value of the immediate value of the instruction.
*Parameters: Buffer - the raw byte array containing instructions
*			 index - Current index where the immediate value is going to start
*			 pInst - Instruction structure where I am storing it
*ReturnValue: 0 for success else error
*/
int GetImmediateOfInstruction(BYTE* Buffer, int index, int nSize, Instruction* pInst)
{
	int nRetVal = 0;
	char arTemp1[5] = {0};
	char arTemp2[5] = {0};
	char arTemp3[5] = {0};
	char arTemp4[5] = {0};

	//pInst->bImmediateExists = true;

	pInst->ImmediateSize = nSize;
	pInst->Immediate = 0;

	if(pInst->ImmediateSize == 1)
	{
		sprintf_s(arTemp1,sizeof(char)*5, "%x", Buffer[index]);
		if(strlen(arTemp1) == 1)
		{
			arTemp1[1] = arTemp1[0];
			arTemp1[0] = '0';
		}
		pInst->Immediate = HexCharToInt(arTemp1[1])*1+ HexCharToInt(arTemp1[0])*16;
	}
	else if(pInst->ImmediateSize == 2)
	{
		sprintf_s(arTemp1,sizeof(char)*5, "%x", Buffer[index]);
		if(strlen(arTemp1) == 1)
		{
			arTemp1[1] = arTemp1[0];
			arTemp1[0] = '0';
		}
		sprintf_s(arTemp2,sizeof(char)*5, "%x", Buffer[index+1]);
		if(strlen(arTemp2) == 1)
		{
			arTemp2[1] = arTemp2[0];
			arTemp2[0] = '0';
		}

		pInst->Immediate = HexCharToInt(arTemp1[1])*1 + HexCharToInt(arTemp1[0])*16 + HexCharToInt(arTemp2[1])*256 + HexCharToInt(arTemp2[0])*4096; 
	}
	else if(pInst->ImmediateSize == 4)
	{
		sprintf_s(arTemp1,sizeof(char)*5, "%x", Buffer[index]);
		if(strlen(arTemp1) == 1)
		{
			arTemp1[1] = arTemp1[0];
			arTemp1[0] = '0';
		}
		sprintf_s(arTemp2,sizeof(char)*5, "%x", Buffer[index+1]);
		if(strlen(arTemp2) == 1)
		{
			arTemp2[1] = arTemp2[0];
			arTemp2[0] = '0';
		}
		sprintf_s(arTemp3,sizeof(char)*5, "%x", Buffer[index+2]);
		if(strlen(arTemp3) == 1)
		{
			arTemp3[1] = arTemp3[0];
			arTemp3[0] = '0';
		}
		sprintf_s(arTemp4,sizeof(char)*5, "%x", Buffer[index+3]);
		if(strlen(arTemp4) == 1)
		{
			arTemp4[1] = arTemp4[0];
			arTemp4[0] = '0';
		}

		pInst->Immediate = HexCharToInt(arTemp1[1])*1 + HexCharToInt(arTemp1[0])*16 + HexCharToInt(arTemp2[1])*256 + HexCharToInt(arTemp2[0])*4096 + HexCharToInt(arTemp3[1])*65536 + HexCharToInt(arTemp3[0])*1048576 + HexCharToInt(arTemp4[1])*16777216 + HexCharToInt(arTemp4[0])*268435456;
	}

	return nRetVal;
}

/*
*Name: ParseModRegRMByte
*Description: This function decodes the moderegbyte and gives the subsequent values of it;
*Parameter: byModeRegRM - actual ModRegRM byte
*			pModRegRM - pointer to the ModRegRM structure which will be allocated in this function.
*Return: 0 For success else error has occured
*/
int ParseModRegRMByte(BYTE byModeRegRM, ModRegRM* pModRegRM)
{

	int nReturnValue = 0;
	char* strModRMValueInBinary = NULL;
	char strTempRegValue[4] = {0};
	char strTempRMValue[4] = {0};


	
	strModRMValueInBinary = GetBinValueFromHex(byModeRegRM);
	if(NULL != strModRMValueInBinary)
	{

		pModRegRM = (ModRegRM*)malloc(sizeof(ModRegRM));
		pModRegRM->actualModeRegRM = byModeRegRM;

		strTempRegValue[0] = strModRMValueInBinary[2];
		strTempRegValue[1] = strModRMValueInBinary[3];
		strTempRegValue[2] = strModRMValueInBinary[4];
		strTempRegValue[3] = '\0';

		strTempRMValue[0] = strModRMValueInBinary[5];
		strTempRMValue[1] = strModRMValueInBinary[6];
		strTempRMValue[2] = strModRMValueInBinary[7];
		strTempRMValue[3] = '\0';

		pModRegRM->rm = GetDecimalValueFromBinary(strTempRMValue);
		pModRegRM->reg = GetDecimalValueFromBinary(strTempRegValue);

		if(strModRMValueInBinary[0] == '0' && strModRMValueInBinary[1] == '0')
		{
			pModRegRM->mode = 0;
		}
		else if(strModRMValueInBinary[0] == '0' && strModRMValueInBinary[1] == '1')
		{
			pModRegRM->mode = 1;
		}
		else if(strModRMValueInBinary[0] == '1' && strModRMValueInBinary[1] == '0')
		{
			pModRegRM->mode = 2;
		}
		else
		{
			pModRegRM->mode = 3;
		}


	}
	else
	{
		nReturnValue = -1;
	}
	free(strModRMValueInBinary);
	return nReturnValue;
}

/*
*Name: ParseSIBByte
*Description: This function decodes the SIB and gives the subsequent values of it;
*Parameter: bySIB - actual ModRegRM byte
*			pSIB - pointer to the SIB structure which will be allocated in this function.
*Return: 0 For success else error has occured
*/
int ParseSIBByte(BYTE bySIB, SIB* pSIB)
{
	int nReturnValue = 0;
	char* strSIBValueInBinary = NULL;
	char strTempIndexValue[4] = {NULL};
	char strTempBaseValue[4] = {NULL};

	

	strSIBValueInBinary = GetBinValueFromHex(bySIB);
	if(NULL != strSIBValueInBinary)
	{

		pSIB = (SIB*)malloc(sizeof(SIB));

		pSIB->actualSIB = bySIB;

		if(strSIBValueInBinary[0] == 0 && strSIBValueInBinary[1] == 0)
		{
			pSIB->scale = 1;

		}
		else if(strSIBValueInBinary[0] == 0 && strSIBValueInBinary[1] == 1)
		{
			pSIB->scale = 2;
		}
		else if(strSIBValueInBinary[1] == 0 && strSIBValueInBinary[1] == 0)
		{
			pSIB->scale = 4;
		}
		else
		{
			pSIB->scale = 8;
		}

		strTempIndexValue[0] = strSIBValueInBinary[2];
		strTempIndexValue[1] = strSIBValueInBinary[3];
		strTempIndexValue[2] = strSIBValueInBinary[4];
		strTempIndexValue[3] = '\0';

		strTempBaseValue[0] = strSIBValueInBinary[5];
		strTempBaseValue[1] = strSIBValueInBinary[6];
		strTempBaseValue[2] = strSIBValueInBinary[7];
		strTempBaseValue[3] = '\0';

		pSIB->index = GetDecimalValueFromBinary(strTempIndexValue);
		pSIB->base = GetDecimalValueFromBinary(strTempBaseValue);

	}
	else
	{
		nReturnValue = -1;
	}
	free(strSIBValueInBinary);
	return nReturnValue;
}

/*
*Name: GetActualInstruction
*Description: This will create the string of the actual human readable instruciton
*Parameter: strCompInstruction - This will have the actual instruction in an array
*Return: string copied to heap from the array [strCompInstruction]
*/
char* GetActualInstruction(char* strCompInstruction)
{
	char* strInstruction = NULL;

	strInstruction = (char*)malloc(sizeof(char)*strlen(strCompInstruction)+1);
	memset(strInstruction, '\0', strlen(strCompInstruction)+1);

	strcpy_s(strInstruction, strlen(strCompInstruction), strCompInstruction);

	return strInstruction;
}

/*
*Name: DecodeADD
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of ADD instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeADD(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {0};
	
	//int i = 0;

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x00:
		{
			//ADD Eb, Gb
			//pInst = GetAnInstruction(byOpcode, nPrefixSize, byarPrefix);
			pInst->bmodRMExists = true;

			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);
				if(pModRegRM != NULL)
				{
					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits
											
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;
											
											if(4 != pSIB->index)
												sprintf(strCompInstruction, "ADD byte ptr [%x+%d*%s], ", pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "ADD byte ptr [%x], ", pInst->Displacement);
										}
										else
										{
											if(4 != pSIB->index)
												sprintf(strCompInstruction, "ADD byte ptr [%d*%s+%s], ", pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "ADD byte ptr [%s], ", archSIBBase[pSIB->base]);
										}
										free(pSIB);

									}
								}

							}
							else if(5 == pModRegRM->rm)
							{
								//Get Displacement 32 bits
								
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;
											

								sprintf(strCompInstruction, "ADD byte ptr [%x], ", pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "ADD byte ptr [%s], ",archMODRMFields_32[pModRegRM->rm]); 

							}
							break;
						}
					case 1:
						{
							
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									//GetDisplacement 8 bits
									GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
									pInst->LengthOfInstruction+= 1;
									nCurrentIndex+=1;

									if(pSIB != NULL)
									{
										if(5 == pSIB->base)
										{
											

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "ADD byte ptr [%x+%d*%s+EBP], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "ADD byte ptr [%x+EBP], ", pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "ADD byte ptr [%x+%d*%s+%s], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "ADD byte ptr [%x+%s], ", pInst->Displacement, archSIBBase[pSIB->base]);

										}
										free(pSIB);

									}

									
									

								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "ADD byte ptr [%s+%x], ", archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 2:
						{
							
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
									pInst->LengthOfInstruction+= 4;
									nCurrentIndex+=4;

									if(pSIB != NULL)
									{
										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "ADD byte ptr [%x+%d*%s+EBP], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "ADD byte ptr [%x+EBP], ", pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "ADD byte ptr [%x+%d*%s+%s], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "ADD byte ptr [%x+%s], ", pInst->Displacement, archSIBBase[pSIB->base]);
										}
										free(pSIB);

									}

								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "ADD byte ptr [%s+%x], ", archMODRMFields_32[pModRegRM->rm], pInst->Displacement);
							}
							break;
						}
					case 3:
						{
							
							sprintf(strCompInstruction, "ADD %s, ", archREGFields_8[pModRegRM->rm]);
							break;
						}
					default:
						{
							break;
						}
					}

					//Gb
					
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_8[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);
				}


				



			}
			else
			{
				nReturnValue = -2;
				//Error scenario - Exceeded raw code but still instruction is incomplete
			}

			break;
		}
	case 0x01:
		{
			//ADD Ev,Gv
			//pInst = GetAnInstruction(byOpcode, nPrefixSize, byarPrefix);
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%d*%s], ", pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%s], ", archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%d*%s+%s], ", pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%s], ", archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "ADD WORD ptr [%x], ", pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "ADD WORD ptr [%s], ",archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%d*%s+EBP], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%x+EBP], ", pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%d*%s+%s], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%s], ", pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "ADD WORD ptr [%s+%x], ", archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%d*%s+EBP], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "ADD WORD ptr [%x+EBP], ", pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%d*%s+%s], ",pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "ADD WORD ptr [%x+%s], ", pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "ADD WORD ptr [%s+%x], ", archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "ADD %s, ", archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}

			break;
		}
	case 0x02:
		{
			//Gb,Eb
			//pInst = GetAnInstruction(byOpcode, nPrefixSize, byarPrefix);
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "ADD %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);





				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}

			break;
		}
	case 0x03:
		{
			//Gv,Ev
			//pInst = GetAnInstruction(byOpcode, nPrefixSize, byarPrefix);
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "ADD %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);





				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x04:
		{
			//AL,lb
			//pInst = GetAnInstruction(byOpcode, nPrefixSize, byarPrefix);

			//Get the immediate value
			//nCurrentIndex++;
			
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "ADD AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}

			break;
		}
	case 0x05:
		{
			//rAX, lz
			//pInst = GetAnInstruction(byOpcode, nPrefixSize, byarPrefix);

			
			
			if(nCurrentIndex+4 < nSize)
			{
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
				nCurrentIndex+=4;
				pInst->LengthOfInstruction+=4;

				sprintf(strCompInstruction, "ADD EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			}
			else
			{
				//Error Size of the index has exceeded
			}

			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodePushPoP
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of PUSH and POP instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodePushPoP(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {0};

	switch(byOpcode)
	{
	case 0x06:
		{
			//PUSH ES i64
			sprintf(strCompInstruction, "PUSH ES");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);

			break;
		}
	case 0x07:
		{
			//POP ES i64
			sprintf(strCompInstruction, "POP ES");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x0E:
		{
			//PUSH CS i64
			sprintf(strCompInstruction, "PUSH CS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x16:
		{
			//PUSH SS i64
			sprintf(strCompInstruction, "PUSH SS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x17:
		{
			//POP SS i64
			sprintf(strCompInstruction, "POP SS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x1E:
		{
			//PUSH DS i64
			sprintf(strCompInstruction, "PUSH DS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x1F:
		{
			//POP DS i64
			sprintf(strCompInstruction, "POP DS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x50:
		{
			//PUSH rAX/r8
			sprintf(strCompInstruction, "PUSH EAX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x51:
		{
			//PUSH rCX/r9
			sprintf(strCompInstruction, "PUSH ECX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x52:
		{
			//PUSH rDX/r10
			sprintf(strCompInstruction, "PUSH EDX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x53:
		{
			//PUSH rBX/r11
			sprintf(strCompInstruction, "PUSH EBX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x54:
		{
			//PUSH rSP/r12
			sprintf(strCompInstruction, "PUSH ESP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x55:
		{
			//PUSH rBP/r13
			sprintf(strCompInstruction, "PUSH EBP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x56:
		{
			//PUSH rSI/r14
			sprintf(strCompInstruction, "PUSH ESI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x57:
		{
			//PUSH rDI/r15
			sprintf(strCompInstruction, "PUSH EDI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x58:
		{
			//POP rAX/r8
			sprintf(strCompInstruction, "POP EAX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x59:
		{
			//POP rCX/r9
			sprintf(strCompInstruction, "POP ECX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x5A:
		{
			//POP rDX/r10
			sprintf(strCompInstruction, "POP EDX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x5B:
		{
			//POP rBX/r11
			sprintf(strCompInstruction, "POP EBX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x5C:
		{
			//POP rSP/r12
			sprintf(strCompInstruction, "POP ESP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x5D:
		{
			//POP rBP/r13
			sprintf(strCompInstruction, "POP EBP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x5E:
		{
			//POP rSI/r14
			sprintf(strCompInstruction, "POP ESI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x5F:
		{
			//POP rDI/r15
			sprintf(strCompInstruction, "POP EDI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x60:
		{
			//PUSHA / PUSHAD
			sprintf(strCompInstruction, "PUSHAD");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x61:
		{
			//POPA / POPAD
			sprintf(strCompInstruction, "POPAD");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x68:
		{
			//PUSH d64 Iz
			if(nCurrentIndex+4 < nSize)
			{
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
				nCurrentIndex+=4;
				pInst->LengthOfInstruction+=4;

				sprintf(strCompInstruction, "PUSH %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x6A:
		{
			//PUSH d64 Ib
			if(nCurrentIndex+1 < nSize)
			{
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
				nCurrentIndex+=1;
				pInst->LengthOfInstruction+=1;

				sprintf(strCompInstruction, "PUSH %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x9C:
		{
			//PUSHF/D/Q d64 Fv
			sprintf(strCompInstruction, "PUSHFD");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x9D:
		{
			//POPF/D/Q d64 Fv
			sprintf(strCompInstruction, "POPFD");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			//ERROR
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeOR
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of OR instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeOR(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;
	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x08:
		{
			//OR Eb,Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"OR ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x09:
		{
			//OR Ev, Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"OR ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x0A:
		{
			//OR Gb,Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "OR %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x0B:
		{
			//OR Gv, Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "OR %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x0C:
		{
			//OR AL, Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "OR AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x0D:
		{
			//OR rAX, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "OR EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeADC
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of ADC instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeADC(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x10:
		{
			//ADC Eb,Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"ADC ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x11:
		{
			//ADC Ev,Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"ADC ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x12:
		{
			//ADC Gb, Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "ADC %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x13:
		{
			//ADC Gv, Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "ADC %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x14:
		{
			//ADC AL, Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "ADC AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x15:
		{
			//ADC rAX, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "ADC EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeSBB
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of SBB instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeSBB(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;
	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x18:
		{
			//SBB Eb,Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"SBB ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x19:
		{
			//SBB Ev,Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"SBB ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x1A:
		{
			//SBB Gb,Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "SBB %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x1B:
		{
			//SBB Gv,Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "SBB %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x1C:
		{
			//SBB AL, Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "SBB AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x1D:
		{
			//SBB rAX, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "SBB EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	default:
		{
			break;
		}

	}

	return nReturnValue;
}

/*
*Name: DecodeAND
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of AND instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeAND(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x20:
		{
			//AND Eb, Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"AND ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x21:
		{
			//AND Ev, Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"AND ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x22:
		{
			//AND Gb, Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "AND %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x23:
		{
			//AND Gv, Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "AND %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			
			break;
		}
	case 0x24:
		{
			//AND AL, Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "AND AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x25:
		{
			//AND rAX, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "AND EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeDAA
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of DAA instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeDAA(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char* strCompInstruction[1024] = {'\0'};

	switch(byOpcode)
	{
	case 0x27:
		{
			//DAA i64
			sprintf(strCompInstruction, "DAA");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			//ERROR
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeSUB
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of SUB instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeSUB(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;
	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x28:
		{
			//SUB Eb,Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"SUB ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_8[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gb
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_8[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x29:
		{
			//SUB Ev,Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"SUB ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x2A:
		{
			//SUB Gb,Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "SUB %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x2B:
		{
			//SUB Gv,Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "SUB %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x2C:
		{
			//SUB AL,Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "SUB AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x2D:
		{
			//SUB rAZ, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "SUB EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeDAS
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of DAS instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeDAS(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	switch(byOpcode)
	{
	case 0x2F:
		{
			//DAS i64
			sprintf(strCompInstruction, "DAS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeXOR
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of XOR instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeXOR(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x30:
		{
			//XOR Eb,Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"XOR ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_8[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gb
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_8[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x31:
		{
			//XOR Ev,Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"XOR ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x32:
		{
			//XOR Gb,Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "XOR %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x33:
		{
			//XOR Gv,Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "XOR %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x34:
		{
			//XOR AL,Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "XOR AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x35:
		{
			//XOR rAX, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "XOR EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeAAA
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of AAA instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeAAA(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	switch(byOpcode)
	{
	case 0x37:
		{
			//AAA i64
			sprintf(strCompInstruction,"AAA");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeCMP
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of CMP instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeCMP(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x38:
		{
			//CMP Eb,Gb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"CMP ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sbyte ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sbyte ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_8[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gb
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_8[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x39:
		{
			//CMP Ev,Gv
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					//Ev
					sprintf(strCompInstruction,"CMP ");
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(pModRegRM->rm == 4)
							{
								//Get SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										if(pSIB->base == 5)
										{
											//Get the Displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%d*%s+%s], ",strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction,archSIBBase[pSIB->base]);
											}

										}
									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else if(pModRegRM->rm == 5)
							{
								//Get the displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%x], ",strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ",strCompInstruction ,archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);
									if(pSIB != NULL)
									{
										//Get the Displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction += 1;
										nCurrentIndex+=1;

										if(pSIB->base == 5)
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ",strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ",strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(pSIB->index != 4)
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ", strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
											}

										}

									}
									else
									{
										//Error
									}


								}
								else
								{
									//ERROR
								}
							}
							else
							{
								//Get Displacement 8 bits
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;


								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ",strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(pModRegRM->rm == 4)
							{
								//Get the SIB BYTE
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);



									if(pSIB != NULL)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											//Get Displacement 32 bits

											if(4 != pSIB->index)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+EBP], ", strCompInstruction,pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+EBP], ", strCompInstruction, pInst->Displacement);
										}
										else
										{
											if(pSIB->index != 4)
												sprintf(strCompInstruction, "%sWORD ptr [%x+%d*%s+%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											else
												sprintf(strCompInstruction, "%sWORD ptr [%x+%s], ",strCompInstruction, pInst->Displacement, archSIBBase[pSIB->base]);
										}

										free(pSIB);

									}
									else
									{
										//ERROR
									}

								}
								else
								{
									//ERROR
								}
							}
							else
							{

								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}
					
					//Gv
					sprintf(strCompInstruction, "%s%s",strCompInstruction, archREGFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//Error
				}
			}
			else
			{
				//Error
			}
			break;
		}
	case 0x3A:
		{
			//CMP Gb,Eb
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "CMP %s, ",archREGFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sbyte ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);

				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x3B:
		{
			//CMP Gv,Ev
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			pInst->LengthOfInstruction++;

			if(nCurrentIndex < nSize)
			{
				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gv
					sprintf(strCompInstruction, "CMP %s, ",archREGFields_32[pModRegRM->reg]);

					//Ev
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s]",strCompInstruction, archSIBBase[pSIB->base]);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%x]",strCompInstruction,pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr[%s]",strCompInstruction,archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
											pInst->LengthOfInstruction+= 1;
											nCurrentIndex+=1;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);


							}

							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								pInst->LengthOfInstruction++;
								if(nCurrentIndex < nSize)
								{
									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+%d*%s+EBP]",strCompInstruction,pInst->Displacement,pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sWORD ptr[%x+EBP]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sWORD ptr[%s+%d*%s+%x]",strCompInstruction,archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index], pInst->Displacement);
											}
											else
											{
												sprintf(strCompInstruction,"%sWORD ptr[%s+%x]",strCompInstruction, archSIBBase[pSIB->base]+pInst->Displacement);
											}

										}


										free(pSIB);

									}
									else
									{
										//ERROR SIB is NULL
									}
								}
								else
								{
									//Error exceeded byte array limit
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sWORD ptr[%s+%x]", strCompInstruction, archMODRMFields_32[pModRegRM->rm], pInst->Displacement);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s",strCompInstruction,archREGFields_32[pModRegRM->reg]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}

					}

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);


				}
				else
				{
					//ERROR PModRegRM is null
				}

			}
			else
			{
				//ERROR size exceeded
			}
			break;
		}
	case 0x3C:
		{
			//CMP AL, Ib
			if(nCurrentIndex+1 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 1, pInst);
				pInst->LengthOfInstruction++;
				nCurrentIndex++;

				sprintf(strCompInstruction, "CMP AL, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0x3D:
		{
			//CMP rAz, Iz
			if(nCurrentIndex+4 < nSize)
			{
				
				GetImmediateOfInstruction(byarRawCode, nCurrentIndex, 4, pInst);
				pInst->LengthOfInstruction += 4;
				nCurrentIndex += 4;

				sprintf(strCompInstruction, "CMP EAX, %x", pInst->Immediate);

				pInst->actualInstruction = GetActualInstruction(strCompInstruction);


			}
			else
			{
				//Error Size of the index has exceeded
			}
			break;
		}
	case 0xA6:
		{
			//CMPS/B Xb,Yb
			sprintf(strCompInstruction, "CMPSB byte ptr [DS:SI], byte ptr [ES:DI]");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0xA7:
		{
			//CMPS/W/D Xv,Yv
			sprintf(strCompInstruction, "CMPSD WORD ptr [DS:SI], WORD ptr [ES:DI]");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeAAS
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of AAS instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeAAS(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	switch(byOpcode)
	{
	case 0x3F:
		{
			//AAS i64
			sprintf(strCompInstruction, "AAS");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}

	}

	return nReturnValue;
}

/*
*Name: DecodeINC
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of INC instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeINC(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	switch(byOpcode)
	{
	case 0x40:
		{
			//INC eAX
			sprintf(strCompInstruction, "INC EAX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x41:
		{
			//INC eCX
			sprintf(strCompInstruction, "INC ECX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x42:
		{
			//INC eDX
			sprintf(strCompInstruction, "INC EDX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x43:
		{
			//INC eBX
			sprintf(strCompInstruction, "INC EBX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x44:
		{
			//INC eSP
			sprintf(strCompInstruction, "INC ESP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x45:
		{
			//INC eBP
			sprintf(strCompInstruction, "INC EBP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x46:
		{
			//INC eSI
			sprintf(strCompInstruction, "INC ESI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x47:
		{
			//INC eDI
			sprintf(strCompInstruction, "INC EDI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}
	}
	
	return nReturnValue;

}

/*
*Name: DecodeDEC
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of DEC instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeDEC(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	switch(byOpcode)
	{
	case 0x48:
		{
			//DEC eAX
			sprintf(strCompInstruction, "DEC EAX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x49:
		{
			//DEC eCX
			sprintf(strCompInstruction, "DEC ECX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x4A:
		{
			//DEC eDX
			sprintf(strCompInstruction, "DEC EDX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x4B:
		{
			//DEC eBX
			sprintf(strCompInstruction, "DEC EBX");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x4C:
		{
			//DEC eSP
			sprintf(strCompInstruction, "DEC ESP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x4D:
		{
			//DEC eBP
			sprintf(strCompInstruction, "DEC EBP");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x4E:
		{
			//DEC eSI
			sprintf(strCompInstruction, "DEC ESI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x4F:
		{
			//DEC eDI
			sprintf(strCompInstruction, "DEC EDI");
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeBOUND
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of BOUND instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeBOUND(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x62:
		{
			//BOUND i64 Gv, Ma
			pInst->bmodRMExists = true;
			
			nCurrentIndex++;
			

			if(nCurrentIndex < nSize)
			{
				pInst->LengthOfInstruction++;

				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(pModRegRM != NULL)
				{
					sprintf(strCompInstruction, "BOUND %s, ", archREGFields_32[pModRegRM->reg]);

					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;
								
								if(nCurrentIndex < nSize)
								{
									//GET SIB Byte
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;
											
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sqword ptr [%x+%d*%s]",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sqword ptr [%x]",strCompInstruction, pInst->Displacement );
											}

										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sqword ptr [%d*%s+%s]", strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}
											else
											{
												sprintf(strCompInstruction, "%sqword ptr [%d*%s+%s]", strCompInstruction, pSIB->scale, archSIBIndex[pSIB->index], archSIBBase[pSIB->base]);
											}

										}

										free(pSIB);
										pSIB = NULL;

									}
									else
									{
										//SIB is null Error

									}
								}
								else
								{
									//ERROR due to exceeding the byte array
								}

							}
							else if(5 == pModRegRM->rm)
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sqword ptr [%x]", strCompInstruction, pInst->Displacement);
							}
							else
							{
								sprintf(strCompInstruction, "%sqword ptr [%s]", strCompInstruction, archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;

								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										//Get displacement 8 bits
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction+= 1;
										nCurrentIndex+=1;

										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sqword ptr[EBP+%x+%d*%s]", strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sqword ptr[EBP+%x]", strCompInstruction, pInst->Displacement);

											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sqword ptr[%s+%x+%d*%s]", strCompInstruction, archSIBBase[pSIB->base], pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);

											}
											else
											{
												sprintf(strCompInstruction, "%sqword ptr[%s+%x]", strCompInstruction, archSIBBase[pSIB->base], pInst->Displacement);

											}

										}

										free(pSIB);
										pSIB = NULL;

									}
									else
									{
										//ERROR SIB byte is null
									}
								}
								else
								{
									//Error exceeded byte array
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sqword ptr[%x+%s]", strCompInstruction, pInst->Displacement, archMODRMFields_32[pModRegRM->rm]);


							}
							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								nCurrentIndex++;

								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									

									if(NULL != pSIB)
									{

										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sqword ptr [EBP+%x+%d*%s]", strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sqword ptr [EBP+%x]", strCompInstruction, pInst->Displacement);
											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sqword ptr [%s+%x+%d*%s]", strCompInstruction, archSIBBase[pSIB->base], pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sqword ptr [%s+%x]", strCompInstruction, archSIBBase[pSIB->base], pInst->Displacement);
											}
										}
										free(pSIB);
									}
									else
									{
										//ERROR in allocating SIB byte
									}
								}
								else
								{
									//ERROR exceeded byte array
								}

							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sqword ptr[%x+%s]", strCompInstruction, pInst->Displacement, archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%sqword ptr[%s]",strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR
							break;
						}
					}

					free(pModRegRM);
					pModRegRM = NULL;
				}
				else
				{
					//ERROR ModRegRM is NULL
				}
			}
			else
			{
				//Error current index exceeded size of byte array
			}

			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

/*
*Name: DecodeMOV
*Description: This function decode all the opcodes which are pertaining to single byte OPCODE of MOV instruction.
*Parameters: byOpcode - Actual opcode,
			 byarRawCode - Byte array of raw instruction
			 nCurrentIndex - Current index of the byOpcode in byarRawCode
			 nSize - Total size of byarRawCode
			 pInst - Instruction where decode instruction will be stored
*Return: 0 For success else some error has occured.
*/
int DecodeMOV(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst)
{
	int nReturnValue = 0;

	char strCompInstruction[1024] = {'\0'};

	SIB* pSIB = NULL;
	ModRegRM* pModRegRM = NULL;

	switch(byOpcode)
	{
	case 0x63:
		{
			//ARPL i64 Ew, Gw :: MOVSXD o64 Gv, Ev
			sprintf(strCompInstruction, "ARPL ");
			//Ew
			//Get the ModRegRM byte
			nCurrentIndex++;
			if(nCurrentIndex < nSize)
			{
				pInst->LengthOfInstruction++;

				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(6 == pModRegRM->rm)
							{
								//Get Displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 2, pInst);
								pInst->LengthOfInstruction+= 2;
								nCurrentIndex+=2;

								sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction, pInst->Displacement);

							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s], ", strCompInstruction, archMODRMFields_16[pModRegRM->rm]);
							}
							break;
						}
					case 1:
						{
							GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
							pInst->LengthOfInstruction+= 1;
							nCurrentIndex+=1;

							if(6 == pModRegRM->rm)
							{
								sprintf(strCompInstruction, "%sWORD ptr [BP+%x], ",pInst->Displacement);
							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", archMODRMFields_16[pModRegRM->rm], pInst->Displacement);
							}
							break;
						}
					case 2:
						{
							GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 2, pInst);
							pInst->LengthOfInstruction+= 2;
							nCurrentIndex+=2;

							if(6 == pModRegRM->rm)
							{
								sprintf(strCompInstruction, "%sWORD ptr [BP+%x], ",pInst->Displacement);
							}
							else
							{
								sprintf(strCompInstruction, "%sWORD ptr [%s+%x], ", archMODRMFields_16[pModRegRM->rm], pInst->Displacement);
							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_16[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR invalid mode
							break;
						}

					}

					free(pModRegRM);
					pModRegRM = NULL;
				}
				else
				{
					//ERROR pModRegRM is NULL
				}
				
			}
			else
			{
				//Error current index exceeded Byte Array
			}

			//Gw
			sprintf(strCompInstruction, "%s%s", strCompInstruction, archREGFields_16[pModRegRM->reg])
			pInst->actualInstruction = GetActualInstruction(strCompInstruction);
			break;
		}
	case 0x88:
		{
			//Mov Eb,Gb
			sprintf(strCompInstruction, "MOV ");
			//Get ModRegRM
			nCurrentIndex++;
			if(nCurrentIndex < nSize)
			{
				pInst->LengthOfInstruction++;

				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);
				
				//Eb
				if(NULL != pModRegRM)
				{
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								//GET SIB byte
								nCurrentIndex++;

								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											//Get the displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x], ", strCompInstruction, pInst->Displacement);
											}

										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s+%d*%s], ",strCompInstruction, archSIBBase[pSIB->base], pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}
										}
										free(pSIB);
										pSIB = NULL;
									}
									else
									{
										//ERROR SIB byte is NULL
									}

								}
								else
								{
									//Error current index is exceeding the byte array
								}
							}
							else if(5 == pModRegRM->reg)
							{
								//Get displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr [%x], ", strCompInstruction, pInst->Displacement);
							}
							else
							{
								sprintf(strCompInstruction, "%sbyte ptr [%s], ", strCompInstruciton, archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								//GET SIB byte
								nCurrentIndex++;
								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction+= 1;
										nCurrentIndex+=1;

										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[EBP+%x+%d*%s], ",strCompInstruciton, pInst->Displacemnt, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[EBP+%x], ",strCompInstruciton, pInst->Displacemnt);
											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%s+%d*%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base]);

											}

										}

										free(pSIB);
										pSIB = NULL;

									}
									else
									{
										//ERROR SIB byte is null
									}
									
								}
								else
								{
									//ERROR exceeding the byte array index
								}
							}
							else if(5 == pModRegRM->rm)
							{
								//Get displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[EBP+%x], ", strCompInstruction, pInst->Displacement);
							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sbyte ptr[%x+%s], ", strCompInstruction, pInst->Displacement, archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								//GET SIB byte
								nCurrentIndex++;
								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[EBP+%x+%d*%s], ",strCompInstruciton, pInst->Displacemnt, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[EBP+%x], ",strCompInstruciton, pInst->Displacemnt);
											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%s+%d*%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sbyte ptr[%x+%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base]);

											}

										}

										free(pSIB);
										pSIB = NULL;

									}
									else
									{
										//ERROR SIB byte is null
									}
									
								}
								else
								{
									//ERROR exceeding the byte array index
								}
							}
							else if(5 == pModRegRM->rm)
							{
								//GET displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[EBP+%x], ", strCompInstruction, pInst->Displacement);
							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sbyte ptr[%x+%s], ", strCompInstruction, pInst->Displacement, archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_8[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR invalid mode
							break;
						}

					}

					sprintf(strCompInstruction, "%s%s", strCompInstruction, archRegFields_8[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);
					pModRegRM = NULL;
				}
				else
				{
					//ERROR ModRegRM is NULL
				}
			}
			else
			{
				//Error currentIndex is exceeding the byte array
			}
			


			break;
		}
	case 0x89:
		{
			//Mov Ev,Gv
			sprintf(strCompInstruction, "MOV ");
			//Get ModRegRM
			nCurrentIndex++;
			if(nCurrentIndex < nSize)
			{
				pInst->LengthOfInstruction++;

				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);
				
				//Eb
				if(NULL != pModRegRM)
				{
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								//GET SIB byte
								nCurrentIndex++;

								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											//Get the displacement
											GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
											pInst->LengthOfInstruction+= 4;
											nCurrentIndex+=4;

											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sdword ptr[%x+%d*%s], ",strCompInstruction, pInst->Displacement, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sdword ptr[%x], ", strCompInstruction, pInst->Displacement);
											}

										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sdword ptr[%s+%d*%s], ",strCompInstruction, archSIBBase[pSIB->base], pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sdword ptr[%s], ",strCompInstruction, archSIBBase[pSIB->base]);
											}
										}
										free(pSIB);
										pSIB = NULL;
									}
									else
									{
										//ERROR SIB byte is NULL
									}

								}
								else
								{
									//Error current index is exceeding the byte array
								}
							}
							else if(5 == pModRegRM->reg)
							{
								//Get displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sdword ptr [%x], ", strCompInstruction, pInst->Displacement);
							}
							else
							{
								sprintf(strCompInstruction, "%sdword ptr [%s], ", strCompInstruciton, archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
								//GET SIB byte
								nCurrentIndex++;
								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
										pInst->LengthOfInstruction+= 1;
										nCurrentIndex+=1;

										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sdword ptr[EBP+%x+%d*%s], ",strCompInstruciton, pInst->Displacemnt, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sdword ptr[EBP+%x], ",strCompInstruciton, pInst->Displacemnt);
											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sdword ptr[%x+%s+%d*%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sdword ptr[%x+%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base]);

											}

										}

										free(pSIB);
										pSIB = NULL;

									}
									else
									{
										//ERROR SIB byte is null
									}
									
								}
								else
								{
									//ERROR exceeding the byte array index
								}
							}
							else if(5 == pModRegRM->rm)
							{
								//Get displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sdword ptr[EBP+%x], ", strCompInstruction, pInst->Displacement);
							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 1, pInst);
								pInst->LengthOfInstruction+= 1;
								nCurrentIndex+=1;

								sprintf(strCompInstruction, "%sdword ptr[%x+%s], ", strCompInstruction, pInst->Displacement, archMODRMFields_32[pModRegRM->rm]);
							}
							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
								//GET SIB byte
								nCurrentIndex++;
								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;

									pInst->bSibExists = true;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									
									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
										pInst->LengthOfInstruction+= 4;
										nCurrentIndex+=4;

										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sdword ptr[EBP+%x+%d*%s], ",strCompInstruciton, pInst->Displacemnt, pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sdword ptr[EBP+%x], ",strCompInstruciton, pInst->Displacemnt);
											}
										}
										else
										{
											if(4 != pSIB->index)
											{
												sprintf(strCompInstruction, "%sdword ptr[%x+%s+%d*%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base],pSIB->scale, archSIBIndex[pSIB->index]);
											}
											else
											{
												sprintf(strCompInstruction, "%sdword ptr[%x+%s], ",strCompInstruciton, pInst->Displacemnt, archSIBBase[pSIB->base]);

											}

										}

										free(pSIB);
										pSIB = NULL;

									}
									else
									{
										//ERROR SIB byte is null
									}
									
								}
								else
								{
									//ERROR exceeding the byte array index
								}
							}
							else if(5 == pModRegRM->rm)
							{
								//GET displacement
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sdword ptr[EBP+%x], ", strCompInstruction, pInst->Displacement);
							}
							else
							{
								GetDisplacementOfInstruction(byarRawCode, nCurrentIndex+1, 4, pInst);
								pInst->LengthOfInstruction+= 4;
								nCurrentIndex+=4;

								sprintf(strCompInstruction, "%sdword ptr[%x+%s], ", strCompInstruction, pInst->Displacement, archMODRMFields_32[pModRegRM->rm]);

							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archREGFields_32[pModRegRM->rm]);
							break;
						}
					default:
						{
							//ERROR invalid mode
							break;
						}

					}

					sprintf(strCompInstruction, "%s%s", strCompInstruction, archRegFields_32[pModRegRM->reg]);

					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);
					pModRegRM = NULL;
				}
				else
				{
					//ERROR ModRegRM is NULL
				}
			}
			else
			{
				//Error currentIndex is exceeding the byte array
			}
			break;
		}
	case 0x8A:
		{
			//Mov Gb,Eb
			sprintf(strCompInstruciton,"MOV ");
			//Get ModRegRM
			nCurrentIndex++;

			if(nCurrentIndex < nSize)
			{
				pInst->LengthOfInstruction++;

				pInst->modrmpart = byarRawCode[nCurrentIndex];
				
				pInst->bmodRMExists = true;
				ParseModRegRMByte(pInst->modrmpart, pModRegRM);

				if(NULL != pModRegRM)
				{
					//Gb
					sprintf(strCompInstruction, "%s%s, ", strCompInstruction, archRegFields_8[pModRegRM->reg]);

					//Eb
					switch(pModRegRM->mode)
					{
					case 0:
						{
							if(4 == pModRegRM->rm)
							{
								//Get SIB byte
								nCurrentIndex++;
								if(nCurrentIndex < nSize)
								{
									pInst->LengthOfInstruction++;
									pInst->sibpart = byarRawCode[nCurrentIndex];
									pInst->bSibExists = true;

									ParseSIBByte(pInst->sibpart, pSIB);

									if(NULL != pSIB)
									{
										if(5 == pSIB->base)
										{
											if(4 != pSIB->index)
											{

											}
											else
											{

											}
										}
										else
										{
											if(4 != pSIB->index)
											{

											}
											else
											{

											}
										}

										free(pSIB);
										pSIB = NULL;
									}
									else
									{
										//Error SIB byte is NULL
									}

									
								}
								else
								{
									//Error Exceeded byte array
								}
							}
							else if(5 == pModRegRM->rm)
							{

							}
							else
							{

							}
							break;
						}
					case 1:
						{
							if(4 == pModRegRM->rm)
							{
							}
							else if(5 == pModRegRM->rm)
							{
							}
							else
							{
							}
							break;
						}
					case 2:
						{
							if(4 == pModRegRM->rm)
							{
							}
							else if(5 == pModRegRM->rm)
							{
							}
							else
							{
							}
							break;
						}
					case 3:
						{
							sprintf(strCompInstruction, "%s%s", strCompInstruction, archRegFields_8[pModRegRM->reg]);
							break;
						}
					default:
						{
							//Error Invalid mode
						}
					}
					
					pInst->actualInstruction = GetActualInstruction(strCompInstruction);

					free(pModRegRM);
					pModRegRM = NULL;
				}
				else
				{
					//ERROR ModRegRM byte is null
				}
			}
			else
			{
				//ERROR currentindex exceeding the size of byte array
			}
			break;
		}
	case 0x8B:
		{
			//Mov Gv,Ev
			break;
		}
	case 0x8C:
		{
			//Mov Ev,Sw
			break;
		}
	case 0x8E:
		{
			//MOV Sw,Ew
			break;
		}
	case 0xA0:
		{
			//MOV AL,Ob
			break;
		}
	case 0xA1:
		{
			//MOV rAX, Ov
			break;
		}
	case 0xA2:
		{
			//MOV Ob, AL
			break;
		}
	case 0xA3:
		{
			//MOV Ov, rAX
			break;
		}
	case 0xA4:
		{
			//MOVS/B Yb,Xb
			break;
		}
	case 0xA5:
		{
			//MOVS/W/D/Q Yv,Xv
			break;
		}
	case 0xB0:
		{
			//MOV immediate byte into byte register AL/R8L, Ib
			break;
		}
	case 0xB1:
		{
			//MOV immediate byte into byte register CL/R9L, Ib
			break;
		}
	case 0xB2:
		{
			//MOV immediate byte into byte register DL/R10L, Ib
			break;
		}
	case 0xB3:
		{
			//MOV immediate byte into byte register BL/R11L, Ib
			break;
		}
	case 0xB4:
		{
			//MOV immediate byte into byte register AH/R12L, Ib
			break;
		}
	case 0xB5:
		{
			//MOV immediate byte into byte register CH/R13L, Ib
			break;
		}
	case 0xB6:
		{
			//MOV immediate byte into byte register DH/R14L, Ib
			break;
		}
	case 0xB7:
		{
			//MOV immediate byte into byte register BH/R15L, Ib
			break;
		}
	case 0xB8:
		{
			//MOV immediate word or double into word, double, or quad register rAX/r8, Iv
			break;
		}
	case 0xB9:
		{
			//MOV immediate word or double into word, double, or quad register rCX/r9, Iv
			break;
		}
	case 0xBA:
		{
			//MOV immediate word or double into word, double, or quad register rDX/r10, Iv
			break;
		}
	case 0xBB:
		{
			//MOV immediate word or double into word, double, or quad register rBX/r11, Iv
			break;
		}
	case 0xBC:
		{
			//MOV immediate word or double into word, double, or quad register rSP/r12, Iv
			break;
		}
	case 0xBD:
		{
			//MOV immediate word or double into word, double, or quad register rBP/r13, Iv
			break;
		}
	case 0xBE:
		{
			//MOV immediate word or double into word, double, or quad register rSI/r14, Iv
			break;
		}
	case 0xBF:
		{
			//MOV immediate word or double into word, double, or quad register rDI/r15, Iv
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeMUL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x69:
		{
			break;
		}
	case 0x6B:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeINS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x6C:
		{
			break;
		}
	case 0x6D:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeOUTS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x6E:
		{
			break;
		}
	case 0x6F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeJMP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x70:
		{
			break;
		}
	case 0x71:
		{
			break;
		}
	case 0x72:
		{
			break;
		}
	case 0x73:
		{
			break;
		}
	case 0x74:
		{
			break;
		}
	case 0x75:
		{
			break;
		}
	case 0x76:
		{
			break;
		}
	case 0x77:
		{
			break;
		}
	case 0x78:
		{
			break;
		}
	case 0x79:
		{
			break;
		}
	case 0x7A:
		{
			break;
		}
	case 0x7B:
		{
			break;
		}
	case 0x7C:
		{
			break;
		}
	case 0x7D:
		{
			break;
		}
	case 0x7E:
		{
			break;
		}
	case 0x7F:
		{
			break;
		}
	case 0xE3:
		{
			break;
		}
	case 0xE9:
		{
			break;
		}
	case 0xEA:
		{
			break;
		}
	case 0xEB:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeGRP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x80:
		{
			break;
		}
	case 0x81:
		{
			break;
		}
	case 0x82:
		{
			break;
		}
	case 0x83:
		{
			break;
		}
	case 0x8F:
		{
			break;
		}
	case 0xC0:
		{
			break;
		}
	case 0xC1:
		{
			break;
		}
	case 0xC6:
		{
			break;
		}
	case 0xC7:
		{
			break;
		}
	case 0xD0:
		{
			break;
		}
	case 0xD1:
		{
			break;
		}
	case 0xD2:
		{
			break;
		}
	case 0xD3:
		{
			break;
		}
	case 0xF6:
		{
			break;
		}
	case 0xF7:
		{
			break;
		}
	case 0xFE:
		{
			break;
		}
	case 0xFF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeTEST(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x84:
		{
			break;
		}
	case 0x85:
		{
			break;
		}
	case 0xA8:
		{
			break;
		}
	case 0xA9:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeXCHG(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x86:
		{
			break;
		}
	case 0x87:
		{
			break;
		}
	case 0x90:
		{
			break;
		}
	case 0x91:
		{
			break;
		}
	case 0x92:
		{
			break;
		}
	case 0x93:
		{
			break;
		}
	case 0x94:
		{
			break;
		}
	case 0x95:
		{
			break;
		}
	case 0x96:
		{
			break;
		}
	case 0x97:
		{
			break;
		}

	default:
		{
			break;
		}

	}

	return nReturnValue;
}

int DecodeLEA(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x8D:
		{
			break;
		}
	default:
		{
			break;
		}
		
	}

	return nReturnValue;
}

int DecodeCDQ(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x98:
		{
			break;
		}
	case 0x99:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeCALL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x9A:
		{
			break;
		}
	case 0xE8:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int DecodeWAIT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x9B:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}



int DecodeSAHF(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x9E:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeLAHF(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x9F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeSTOS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xAA:
		{
			break;
		}
	case 0xAB:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeLODS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xAC:
		{
			break;
		}
	case 0xAD:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeSCAS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xAE:
		{
			break;
		}
	case 0xAF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeRET(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC2:
		{
			break;
		}
	case 0xC3:
		{
			break;
		}
	case 0xCA:
		{
			break;
		}
	case 0xCB:
		{
			break;
		}
	case 0xCF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeLES(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeLDS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int DecodeENTER(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC8:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeLEAVE(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC9:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeINT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xCC:
		{
			break;
		}
	case 0xCD:
		{
			break;
		}
	case 0xCE:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeAAM(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xD4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeAAD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xD5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}


int DecodeSingeReserved(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xD6:
		{
			break;
		}
	case 0xF1:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeXLAT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xD7:
		{
			break;
		}
	default:
		{
			break;
		}
	}


	return nReturnValue;
}

int DecodeEsc(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xD8:
		{
			break;
		}
	case 0xD9:
		{
			break;
		}
	case 0xDA:
		{
			break;
		}
	case 0xDB:
		{
			break;
		}
	case 0xDC:
		{
			break;
		}
	case 0xDD:
		{
			break;
		}
	case 0xDE:
		{
			break;
		}
	case 0xDF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeLoop(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xE0:
		{
			break;
		}
	case 0xE1:
		{
			break;
		}
	case 0xE2:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeIN(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xE4:
		{
			break;
		}
	case 0xE5:
		{
			break;
		}
	case 0xEC:
		{
			break;
		}
	case 0xED:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeOUT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xE6:
		{
			break;
		}
	case 0xE7:
		{
			break;
		}
	case 0xEE:
		{
			break;
		}
	case 0xEF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeHLT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeCMC(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeCL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF8:
		{
			break;
		}
	case 0xFA:
		{
			break;
		}
	case 0xFC:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int DecodeST(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF9:
		{
			break;
		}
	case 0xFB:
		{
			break;
		}
	case 0xFD:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2Grp(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x00:
		{
			break;
		}
	case 0x01:
		{
			break;
		}
	case 0x18:
		{
			break;
		}
	case 0x71:
		{
			break;
		}
	case 0x72:
		{
			break;
		}
	case 0x73:
		{
			break;
		}
	case 0xAE:
		{
			break;
		}
	case 0xB9:
		{
			break;
		}
	case 0xBA:
		{
			break;
		}
	case 0xC7:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2LAR(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x02:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2LSL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x03:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2Reserved(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x04:
		{
			break;
		}
	case 0x0A:
		{
			break;
		}
	case 0x0B:
		{
			break;
		}
	case 0x0C:
		{
			break;
		}
	case 0x0E:
		{
			break;
		}
	case 0x0F:
		{
			break;
		}
	case 0x19:
		{
			break;
		}
	case 0x1A:
		{
			break;
		}
	case 0x1B:
		{
			break;
		}
	case 0x1C:
		{
			break;
		}
	case 0x1D:
		{
			break;
		}
	case 0x1E:
		{
			break;
		}
	case 0x24:
		{
			break;
		}
	case 0x25:
		{
			break;
		}
	case 0x26:
		{
			break;
		}
	case 0x27:
		{
			break;
		}
	case 0x36:
		{
			break;
		}
	case 0x39:
		{
			break;
		}
	case 0x3B:
		{
			break;
		}
	case 0x3C:
		{
			break;
		}
	case 0x3D:
		{
			break;
		}
	case 0x3E:
		{
			break;
		}
	case 0x3F:
		{
			break;
		}
	case 0x7A:
		{
			break;
		}
	case 0x7B:
		{
			break;
		}
	case 0xA6:
		{
			break;
		}
	case 0xA7:
		{
			break;
		}
	case 0xFF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2SYSCALL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x05:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2CLTS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x06:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2SYSRET(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x07:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2INVD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x08:
		{
			break;
		}
	case 0x09:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2PREFETCH(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x0D:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}



int Decode2VUNPCK(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x14:
		{
			break;
		}
	case 0x15:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2NOP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x1F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2MOV(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
		case 0x10:
		{
			break;
		}
	case 0x11:
		{
			break;
		}
	case 0x12:
		{
			break;
		}	
	case 0x13:
		{
			break;
		}
	case 0x16:
		{
			break;
		}
	case 0x17:
		{
			break;
		}
	case 0x28:
		{
			break;
		}
	case 0x29:
		{
			break;
		}
	case 0x2B:
		{
			break;
		}
	case 0x50:
		{
			break;
		}
	case 0x20:
		{
			break;
		}
	case 0x21:
		{
			break;
		}
	case 0x22:
		{
			break;
		}
	case 0x23:
		{
			break;
		}
	case 0x6E:
		{
			break;
		}
	case 0x6F:
		{
			break;
		}
	case 0x7E:
		{
			break;
		}
	case 0x7F:
		{
			break;
		}
	case 0xB6:
		{
			break;
		}
	case 0xB7:
		{
			break;
		}
	case 0xBE:
		{
			break;
		}
	case 0xBF:
		{
			break;
		}
	case 0xC3:
		{
			break;
		}
	case 0xD6:
		{
			break;
		}
	case 0xD7:
		{
			break;
		}
	case 0xE7:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}


int Decode2CVT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x2A:
		{
			break;
		}
	case 0x2C:
		{
			break;
		}
	case 0x2D:
		{
			break;
		}
	case 0x5A:
		{
			break;
		}
	case 0x5B:
		{
			break;
		}
	case 0xE6:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}


int Decode2VUCOMIS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x2E:
		{
			break;
		}
	default:
		{
			break;
		}
	}


	return nReturnValue;
}

int Decode2VCOMIS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
		case 0x2F:
		{
			break;
		}
		default:
			{
				break;
			}
	}

	return nReturnValue;
}

int Decode2WRMSR(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x30:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2RDTSC(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x31:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2RDMSR(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x32:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2RDPMC(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x33:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2SYSENTER(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x34:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2SYSEXIT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x35:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;
}

int Decode2GETSEC(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x37:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2CMOV(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x40:
		{
			break;
		}
	case 0x41:
		{
			break;
		}
	case 0x42:
		{
			break;
		}
	case 0x43:
		{
			break;
		}
	case 0x44:
		{
			break;
		}
	case 0x45:
		{
			break;
		}
	case 0x46:
		{
			break;
		}
	case 0x47:
		{
			break;
		}
	case 0x48:
		{
			break;
		}
	case 0x49:
		{
			break;
		}
	case 0x4A:
		{
			break;
		}
	case 0x4B:
		{
			break;
		}
	case 0x4C:
		{
			break;
		}
	case 0x4D:
		{
			break;
		}
	case 0x4E:
		{
			break;
		}
	case 0x4F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode2VSQRT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x51:
		{
			break;
		}
	case 0x52:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2VRCP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x53:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2AND(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x54:
		{
			break;
		}
	case 0x55:
		{
			break;
		}
	case 0xDB:
		{
			break;
		}
	case 0xDF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2OR(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x56:
		{
			break;
		}
	case 0x57:
		{
			break;
		}
	case 0xEB:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2ADD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x58:
		{
			break;
		}
	case 0x7C:
		{
			break;
		}
	case 0xC0:
		{
			break;
		}
	case 0xC1:
		{
			break;
		}
	case 0xD0:
		{
			break;
		}
	case 0xD4:
		{
			break;
		}
	case 0xDC:
		{
			break;
		}
	case 0xDD:
		{
			break;
		}
	case 0xEC:
		{
			break;
		}
	case 0xED:
		{
			break;
		}
	case 0xF5:
		{
			break;
		}
	case 0xFC:
		{
			break;
		}
	case 0xFD:
		{
			break;
		}
	case 0xFE:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}




int Decode2MUL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x59:
		{
			break;
		}
	case 0xAF:
		{
			break;
		}
	case 0xD5:
		{
			break;
		}
	case 0xE4:
		{
			break;
		}
	case 0xE5:
		{
			break;
		}
	case 0xF4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode2SUB(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x5C:
		{
			break;
		}
	case 0x7D:
		{
			break;
		}
	case 0xD8:
		{
			break;
		}
	case 0xD9:
		{
			break;
		}
	case 0xE8:
		{
			break;
		}
	case 0xE9:
		{
			break;
		}
	case 0xF8:
		{
			break;
		}
	case 0xF9:
		{
			break;
		}
	case 0xFA:
		{
			break;
		}
	case 0xFB:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2MIN(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x5D:
		{
			break;
		}
	case 0xDA:
		{
			break;
		}
	case 0xEA:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2DIV(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x5E:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2MAX(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x5F:
		{
			break;
		}
	case 0xDE:
		{
			break;
		}
	case 0xEE:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode2PUNPCK(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x60:
		{
			break;
		}
	case 0x61:
		{
			break;
		}
	case 0x62:
		{
			break;
		}
	case 0x68:
		{
			break;
		}
	case 0x69:
		{
			break;
		}
	case 0x6A:
		{
			break;
		}
	case 0x6C:
		{
			break;
		}
	case 0x6D:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2PACK(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x63:
		{
			break;
		}
	case 0x67:
		{
			break;
		}
	case 0x6B:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode2PCMP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x64:
		{
			break;
		}
	case 0x65:
		{
			break;
		}
	case 0x66:
		{
			break;
		}
	case 0x74:
		{
			break;
		}
	case 0x75:
		{
			break;
		}
	case 0x76:
		{
			break;
		}
	case 0xC2:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2VPSHU(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x70:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2EMMS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x77:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode2VMREAD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x78:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2VMWRITE(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x79:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2JMP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x80:
		{
			break;
		}
	case 0x81:
		{
			break;
		}
	case 0x82:
		{
			break;
		}
	case 0x83:
		{
			break;
		}
	case 0x84:
		{
			break;
		}
	case 0x85:
		{
			break;
		}
	case 0x86:
		{
			break;
		}
	case 0x87:
		{
			break;
		}
	case 0x88:
		{
			break;
		}
	case 0x89:
		{
			break;
		}
	case 0x8A:
		{
			break;
		}
	case 0x8B:
		{
			break;
		}
	case 0x8C:
		{
			break;
		}
	case 0x8D:
		{
			break;
		}
	case 0x8E:
		{
			break;
		}
	case 0x8F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SET(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x90:
		{
			break;
		}
	case 0x91:
		{
			break;
		}
	case 0x92:
		{
			break;
		}
	case 0x93:
		{
			break;
		}
	case 0x94:
		{
			break;
		}
	case 0x95:
		{
			break;
		}
	case 0x96:
		{
			break;
		}
	case 0x97:
		{
			break;
		}
	case 0x98:
		{
			break;
		}
	case 0x99:
		{
			break;
		}
	case 0x9A:
		{
			break;
		}
	case 0x9B:
		{
			break;
		}
	case 0x9C:
		{
			break;
		}
	case 0x9D:
		{
			break;
		}
	case 0x9E:
		{
			break;
		}
	case 0x9F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode2PUSH(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xA0:
		{
			break;
		}
	case 0xA8:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2POP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xA1:
		{
			break;
		}
	case 0xA9:
		{
			break;
		}
	case 0xB8:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2CPUID(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xA2:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2BT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xA3:
		{
			break;
		}
	case 0xAB:
		{
			break;
		}
	case 0xB3:
		{
			break;
		}
	case 0xBB:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SHLD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xA4:
		{
			break;
		}
	case 0xA5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2RSM(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xAA:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SHRD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xAC:
		{
			break;
		}
	case 0xAD:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2CMPXCHG(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xB0:
		{
			break;
		}
	case 0xB1:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2LSS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xB2:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2LFS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xB4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2LGS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xB5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2BS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xBC:
		{
			break;
		}
	case 0xBD:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2INSRW(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2EXTRW(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SHUF(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC6:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2BSWAP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xC8:
		{
			break;
		}
	case 0xC9:
		{
			break;
		}
	case 0xCA:
		{
			break;
		}
	case 0xCB:
		{
			break;
		}
	case 0xCC:
		{
			break;
		}
	case 0xCD:
		{
			break;
		}
	case 0xCE:
		{
			break;
		}
	case 0xCF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SRL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xD1:
		{
			break;
		}
	case 0xD2:
		{
			break;
		}
	case 0xD3:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2AVG(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xE0:
		{
			break;
		}
	case 0xE3:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SRA(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xE1:
		{
			break;
		}
	case 0xE2:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2XOR(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xEF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2LDD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF0:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SLL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF1:
		{
			break;
		}
	case 0xF2:
		{
			break;
		}
	case 0xF3:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2SAD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF6:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode2MASK(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF7:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1PSHU(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x00:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1ADD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x01:
		{
			break;
		}
	case 0x02:
		{
			break;
		}
	case 0x03:
		{
			break;
		}
	case 0x04:
		{
			break;
		}
	case 0x96:
		{
			break;
		}
	case 0x98:
		{
			break;
		}
	case 0x99:
		{
			break;
		}
	case 0x9C:
		{
			break;
		}
	case 0x9D:
		{
			break;
		}
	case 0xA6:
		{
			break;
		}
	case 0xB6:
		{
			break;
		}
	case 0xA8:
		{
			break;
		}
	case 0xA9:
		{
			break;
		}
	case 0xB8:
		{
			break;
		}
	case 0xB9:
		{
			break;
		}
	case 0xAC:
		{
			break;
		}
	case 0xAD:
		{
			break;
		}
	case 0xBC:
		{
			break;
		}
	case 0xBD:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1SUB(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x05:
		{
			break;
		}
	case 0x06:
		{
			break;
		}
	case 0x07:
		{
			break;
		}
	case 0x97:
		{
			break;
		}
	case 0x9A:
		{
			break;
		}
	case 0x9B:
		{
			break;
		}
	case 0x9E:
		{
			break;
		}
	case 0x9F:
		{
			break;
		}
	case 0xA7:
		{
			break;
		}
	case 0xB7:
		{
			break;
		}
	case 0xAA:
		{
			break;
		}
	case 0xAB:
		{
			break;
		}
	case 0xBA:
		{
			break;
		}
	case 0xBB:
		{
			break;
		}
	case 0xBE:
		{
			break;
		}
	case 0xBF:
		{
			break;
		}
	case 0xAE:
		{
			break;
		}
	case 0xAF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1SIGN(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x08:
		{
			break;
		}
	case 0x09:
		{
			break;
		}
	case 0x0A:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1MUL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x0B:
		{
			break;
		}
	case 0x28:
		{
			break;
		}
	case 0x40:
		{
			break;
		}
	case 0xF6:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1MIL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x0C:
		{
			break;
		}
	case 0x0D:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}



int Decode3_1TEST(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x0E:
		{
			break;
		}
	case 0x0F:
		{
			break;
		}
	case 0x17:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1BLEND(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x10:
		{
			break;
		}
	case 0x14:
		{
			break;
		}
	case 0x15:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1RESERVED(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x11:
		{
			break;
		}
	case 0x12:
		{
			break;
		}
	case 0x1B:
		{
			break;
		}
	case 0x1F:
		{
			break;
		}
	case 0x26:
		{
			break;
		}
	case 0x27:
		{
			break;
		}
	case 0x42:
		{
			break;
		}
	case 0x43:
		{
			break;
		}
	case 0x44:
		{
			break;
		}
	case 0x48:
		{
			break;
		}
	case 0x49:
		{
			break;
		}
	case 0x4A:
		{
			break;
		}
	case 0x4B:
		{
			break;
		}
	case 0x4C:
		{
			break;
		}
	case 0x4D:
		{
			break;
		}
	case 0x4E:
		{
			break;
		}
	case 0x4F:
		{
			break;
		}
	case 0x50:
		{
			break;
		}
	case 0x51:
		{
			break;
		}
	case 0x52:
		{
			break;
		}
	case 0x53:
		{
			break;
		}
	case 0x54:
		{
			break;
		}
	case 0x55:
		{
			break;
		}
	case 0x56:
		{
			break;
		}
	case 0x57:
		{
			break;
		}
	case 0x5B:
		{
			break;
		}
	case 0x5C:
		{
			break;
		}
	case 0x5D:
		{
			break;
		}
	case 0x5E:
		{
			break;
		}
	case 0x5F:
		{
			break;
		}
	case 0x60:
		{
			break;
		}
	case 0x61:
		{
			break;
		}
	case 0x62:
		{
			break;
		}
	case 0x63:
		{
			break;
		}
	case 0x64:
		{
			break;
		}
	case 0x65:
		{
			break;
		}
	case 0x66:
		{
			break;
		}
	case 0x67:
		{
			break;
		}
	case 0x68:
		{
			break;
		}
	case 0x69:
		{
			break;
		}
	case 0x6A:
		{
			break;
		}
	case 0x6B:
		{
			break;
		}
	case 0x6C:
		{
			break;
		}
	case 0x6D:
		{
			break;
		}
	case 0x6E:
		{
			break;
		}
	case 0x6F:
		{
			break;
		}
	case 0x70:
		{
			break;
		}
	case 0x71:
		{
			break;
		}
	case 0x72:
		{
			break;
		}
	case 0x73:
		{
			break;
		}
	case 0x74:
		{
			break;
		}
	case 0x75:
		{
			break;
		}
	case 0x76:
		{
			break;
		}
	case 0x77:
		{
			break;
		}
	case 0x7A:
		{
			break;
		}
	case 0x7B:
		{
			break;
		}
	case 0x7C:
		{
			break;
		}
	case 0x7D:
		{
			break;
		}
	case 0x7E:
		{
			break;
		}
	case 0x7F:
		{
			break;
		}
	case 0x83:
		{
			break;
		}
	case 0x84:
		{
			break;
		}
	case 0x85:
		{
			break;
		}
	case 0x86:
		{
			break;
		}
	case 0x87:
		{
			break;
		}
	case 0x88:
		{
			break;
		}
	case 0x89:
		{
			break;
		}
	case 0x8A:
		{
			break;
		}
	case 0x8B:
		{
			break;
		}
	case 0x8D:
		{
			break;
		}
	case 0x8F:
		{
			break;
		}
	case 0x94:
		{
			break;
		}
	case 0x95:
		{
			break;
		}
	case 0xA0:
		{
			break;
		}
	case 0xA1:
		{
			break;
		}
	case 0xA2:
		{
			break;
		}
	case 0xA3:
		{
			break;
		}
	case 0xA4:
		{
			break;
		}
	case 0xA5:
		{
			break;
		}
	case 0xB0:
		{
			break;
		}
	case 0xB1:
		{
			break;
		}
	case 0xB2:
		{
			break;
		}
	case 0xB3:
		{
			break;
		}
	case 0xB4:
		{
			break;
		}
	case 0xB5:
		{
			break;
		}
	case 0xC0:
		{
			break;
		}
	case 0xC1:
		{
			break;
		}
	case 0xC2:
		{
			break;
		}
	case 0xC3:
		{
			break;
		}
	case 0xC4:
		{
			break;
		}
	case 0xC5:
		{
			break;
		}
	case 0xC6:
		{
			break;
		}
	case 0xC7:
		{
			break;
		}
	case 0xD0:
		{
			break;
		}
	case 0xD1:
		{
			break;
		}
	case 0xD2:
		{
			break;
		}
	case 0xD3:
		{
			break;
		}
	case 0xD4:
		{
			break;
		}
	case 0xD5:
		{
			break;
		}
	case 0xD6:
		{
			break;
		}
	case 0xD7:
		{
			break;
		}
	case 0xE0:
		{
			break;
		}
	case 0xE1:
		{
			break;
		}
	case 0xE2:
		{
			break;
		}
	case 0xE3:
		{
			break;
		}
	case 0xE4:
		{
			break;
		}
	case 0xE5:
		{
			break;
		}
	case 0xE6:
		{
			break;
		}
	case 0xE7:
		{
			break;
		}
	case 0xC8:
		{
			break;
		}
	case 0xC9:
		{
			break;
		}
	case 0xCA:
		{
			break;
		}
	case 0xCB:
		{
			break;
		}
	case 0xCC:
		{
			break;
		}
	case 0xCD:
		{
			break;
		}
	case 0xCE:
		{
			break;
		}
	case 0xCF:
		{
			break;
		}
	case 0xE8:
		{
			break;
		}
	case 0xE9:
		{
			break;
		}
	case 0xEA:
		{
			break;
		}
	case 0xEB:
		{
			break;
		}
	case 0xEC:
		{
			break;
		}
	case 0xED:
		{
			break;
		}
	case 0xEE:
		{
			break;
		}
	case 0xEF:
		{
			break;
		}
	case 0xD8:
		{
			break;
		}
	case 0xD9:
		{
			break;
		}
	case 0xDA:
		{
			break;
		}
	case 0xF8:
		{
			break;
		}
	case 0xF9:
		{
			break;
		}
	case 0xFA:
		{
			break;
		}
	case 0xFB:
		{
			break;
		}
	case 0xFC:
		{
			break;
		}
	case 0xFD:
		{
			break;
		}
	case 0xFE:
		{
			break;
		}
	case 0xFF:
		{
			break;
		}
	case 0xF4:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1CVT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x13:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode3_1RMP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x16:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1BROADCAST(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x18:
		{
			break;
		}
	case 0x19:
		{
			break;
		}
	case 0x1A:
		{
			break;
		}
	case 0x58:
		{
			break;
		}
	case 0x59:
		{
			break;
		}
	case 0x5A:
		{
			break;
		}
	case 0x78:
		{
			break;
		}
	case 0x79:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1ABS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x1C:
		{
			break;
		}
	case 0x1D:
		{
			break;
		}
	case 0x1E:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1MOV(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x20:
		{
			break;
		}
	case 0x21:
		{
			break;
		}
	case 0x22:
		{
			break;
		}
	case 0x23:
		{
			break;
		}
	case 0x24:
		{
			break;
		}
	case 0x25:
		{
			break;
		}
	case 0x2A:
		{
			break;
		}
	case 0x2C:
		{
			break;
		}
	case 0x2D:
		{
			break;
		}
	case 0x2E:
		{
			break;
		}
	case 0x2F:
		{
			break;
		}
	case 0x30:
		{
			break;
		}
	case 0x31:
		{
			break;
		}
	case 0x32:
		{
			break;
		}
	case 0x33:
		{
			break;
		}
	case 0x34:
		{
			break;
		}
	case 0x35:
		{
			break;
		}
	case 0x8C:
		{
			break;
		}
	case 0x8E:
		{
			break;
		}
	case 0xF0:
		{
			break;
		}
	case 0xF1:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1CMP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x37:
		{
			break;
		}
	case 0x29:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1PACK(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x2B:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1RMD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x36:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1MIN(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x38:
		{
			break;
		}
	case 0x39:
		{
			break;
		}
	case 0x3A:
		{
			break;
		}
	case 0x3B:
		{
			break;
		}
	case 0x41:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1MAX(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x3C:
		{
			break;
		}
	case 0x3D:
		{
			break;
		}
	case 0x3E:
		{
			break;
		}
	case 0x3F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1SRUnique(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x45:
		{
			break;
		}
	case 0x46:
		{
			break;
		}
	case 0x47:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1INV(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x80:
		{
			break;
		}
	case 0x81:
		{
			break;
		}
	case 0x82:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1GATHER(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x90:
		{
			break;
		}
	case 0x91:
		{
			break;
		}
	case 0x92:
		{
			break;
		}
	case 0x93:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1AES(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xDB:
		{
			break;
		}
	case 0xDC:
		{
			break;
		}
	case 0xDD:
		{
			break;
		}
	case 0xDE:
		{
			break;
		}
	case 0xDF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1AND(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF2:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1GRP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF3:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}


int Decode3_1BZH(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF5:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_1BEXT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF7:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2PERM(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x00:
		{
			break;
		}
	case 0x01:
		{
			break;
		}
	case 0x04:
		{
			break;
		}
	case 0x05:
		{
			break;
		}
	case 0x06:
		{
			break;
		}
	case 0x46:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2BLEND(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x02:
		{
			break;
		}
	case 0x0C:
		{
			break;
		}
	case 0x0D:
		{
			break;
		}
	case 0x0E:
		{
			break;
		}
	case 0x4A:
		{
			break;
		}
	case 0x4B:
		{
			break;
		}
	case 0x4C:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2RESERVED(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x03:
		{
			break;
		}
	case 0x07:
		{
			break;
		}
	case 0x10:
		{
			break;
		}
	case 0x11:
		{
			break;
		}
	case 0x12:
		{
			break;
		}
	case 0x13:
		{
			break;
		}
	case 0x1A:
		{
			break;
		}
	case 0x1B:
		{
			break;
		}
	case 0x1C:
		{
			break;
		}
	case 0x1E:
		{
			break;
		}
	case 0x1F:
		{
			break;
		}
	case 0x23:
		{
			break;
		}
	case 0x24:
		{
			break;
		}
	case 0x25:
		{
			break;
		}
	case 0x26:
		{
			break;
		}
	case 0x27:
		{
			break;
		}
	case 0x28:
		{
			break;
		}
	case 0x29:
		{
			break;
		}
	case 0x2A:
		{
			break;
		}
	case 0x2B:
		{
			break;
		}
	case 0x2C:
		{
			break;
		}
	case 0x2D:
		{
			break;
		}
	case 0x2E:
		{
			break;
		}
	case 0x2F:
		{
			break;
		}
	case 0x30:
		{
			break;
		}
	case 0x31:
		{
			break;
		}
	case 0x32:
		{
			break;
		}
	case 0x33:
		{
			break;
		}
	case 0x34:
		{
			break;
		}
	case 0x35:
		{
			break;
		}
	case 0x36:
		{
			break;
		}
	case 0x37:
		{
			break;
		}
	case 0x3A:
		{
			break;
		}
	case 0x3B:
		{
			break;
		}
	case 0x3C:
		{
			break;
		}
	case 0x3D:
		{
			break;
		}
	case 0x3E:
		{
			break;
		}
	case 0x3F:
		{
			break;
		}
	case 0x43:
		{
			break;
		}
	case 0x45:
		{
			break;
		}
	case 0x47:
		{
			break;
		}
	case 0x48:
		{
			break;
		}
	case 0x49:
		{
			break;
		}
	case 0x4D:
		{
			break;
		}
	case 0x4E:
		{
			break;
		}
	case 0x4F:
		{
			break;
		}
	case 0x50:
		{
			break;
		}
	case 0x51:
		{
			break;
		}
	case 0x52:
		{
			break;
		}
	case 0x53:
		{
			break;
		}
	case 0x54:
		{
			break;
		}
	case 0x55:
		{
			break;
		}
	case 0x56:
		{
			break;
		}
	case 0x57:
		{
			break;
		}
	case 0x58:
		{
			break;
		}
	case 0x59:
		{
			break;
		}
	case 0x5A:
		{
			break;
		}
	case 0x5B:
		{
			break;
		}
	case 0x5C:
		{
			break;
		}
	case 0x5D:
		{
			break;
		}
	case 0x5E:
		{
			break;
		}
	case 0x5F:
		{
			break;
		}
	case 0x64:
		{
			break;
		}
	case 0x65:
		{
			break;
		}
	case 0x66:
		{
			break;
		}
	case 0x67:
		{
			break;
		}
	case 0x68:
		{
			break;
		}
	case 0x69:
		{
			break;
		}
	case 0x6A:
		{
			break;
		}
	case 0x6B:
		{
			break;
		}
	case 0x6C:
		{
			break;
		}
	case 0x6D:
		{
			break;
		}
	case 0x6E:
		{
			break;
		}
	case 0x6F:
		{
			break;
		}
	case 0x70:
		{
			break;
		}
	case 0x71:
		{
			break;
		}
	case 0x72:
		{
			break;
		}
	case 0x73:
		{
			break;
		}
	case 0x74:
		{
			break;
		}
	case 0x75:
		{
			break;
		}
	case 0x76:
		{
			break;
		}
	case 0x77:
		{
			break;
		}
	case 0x78:
		{
			break;
		}
	case 0x79:
		{
			break;
		}
	case 0x7A:
		{
			break;
		}
	case 0x7B:
		{
			break;
		}
	case 0x7C:
		{
			break;
		}
	case 0x7D:
		{
			break;
		}
	case 0x7E:
		{
			break;
		}
	case 0x7F:
		{
			break;
		}
	case 0x80:
		{
			break;
		}
	case 0x81:
		{
			break;
		}
	case 0x82:
		{
			break;
		}
	case 0x83:
		{
			break;
		}
	case 0x84:
		{
			break;
		}
	case 0x85:
		{
			break;
		}
	case 0x86:
		{
			break;
		}
	case 0x87:
		{
			break;
		}
	case 0x88:
		{
			break;
		}
	case 0x89:
		{
			break;
		}
	case 0x8A:
		{
			break;
		}
	case 0x8B:
		{
			break;
		}
	case 0x8C:
		{
			break;
		}
	case 0x8D:
		{
			break;
		}
	case 0x8E:
		{
			break;
		}
	case 0x8F:
		{
			break;
		}
	case 0x90:
		{
			break;
		}
	case 0x91:
		{
			break;
		}
	case 0x92:
		{
			break;
		}
	case 0x93:
		{
			break;
		}
	case 0x94:
		{
			break;
		}
	case 0x95:
		{
			break;
		}
	case 0x96:
		{
			break;
		}
	case 0x97:
		{
			break;
		}
	case 0x98:
		{
			break;
		}
	case 0x99:
		{
			break;
		}
	case 0x9A:
		{
			break;
		}
	case 0x9B:
		{
			break;
		}
	case 0x9C:
		{
			break;
		}
	case 0x9D:
		{
			break;
		}
	case 0x9E:
		{
			break;
		}
	case 0x9F:
		{
			break;
		}
	case 0xA0:
		{
			break;
		}
	case 0xA1:
		{
			break;
		}
	case 0xA2:
		{
			break;
		}
	case 0xA3:
		{
			break;
		}
	case 0xA4:
		{
			break;
		}
	case 0xA5:
		{
			break;
		}
	case 0xA6:
		{
			break;
		}
	case 0xA7:
		{
			break;
		}
	case 0xA8:
		{
			break;
		}
	case 0xA9:
		{
			break;
		}
	case 0xAA:
		{
			break;
		}
	case 0xAB:
		{
			break;
		}
	case 0xAC:
		{
			break;
		}
	case 0xAD:
		{
			break;
		}
	case 0xAE:
		{
			break;
		}
	case 0xAF:
		{
			break;
		}
	case 0xB0:
		{
			break;
		}
	case 0xB1:
		{
			break;
		}
	case 0xB2:
		{
			break;
		}
	case 0xB3:
		{
			break;
		}
	case 0xB4:
		{
			break;
		}
	case 0xB5:
		{
			break;
		}
	case 0xB6:
		{
			break;
		}
	case 0xB7:
		{
			break;
		}
	case 0xB8:
		{
			break;
		}
	case 0xB9:
		{
			break;
		}
	case 0xBA:
		{
			break;
		}
	case 0xBB:
		{
			break;
		}
	case 0xBC:
		{
			break;
		}
	case 0xBD:
		{
			break;
		}
	case 0xBE:
		{
			break;
		}
	case 0xBF:
		{
			break;
		}
	case 0xC0:
		{
			break;
		}
	case 0xC1:
		{
			break;
		}
	case 0xC2:
		{
			break;
		}
	case 0xC3:
		{
			break;
		}
	case 0xC4:
		{
			break;
		}
	case 0xC5:
		{
			break;
		}
	case 0xC6:
		{
			break;
		}
	case 0xC7:
		{
			break;
		}
	case 0xC8:
		{
			break;
		}
	case 0xC9:
		{
			break;
		}
	case 0xCA:
		{
			break;
		}
	case 0xCB:
		{
			break;
		}
	case 0xCC:
		{
			break;
		}
	case 0xCD:
		{
			break;
		}
	case 0xCE:
		{
			break;
		}
	case 0xCF:
		{
			break;
		}
	case 0xD0:
		{
			break;
		}
	case 0xD1:
		{
			break;
		}
	case 0xD2:
		{
			break;
		}
	case 0xD3:
		{
			break;
		}
	case 0xD4:
		{
			break;
		}
	case 0xD5:
		{
			break;
		}
	case 0xD6:
		{
			break;
		}
	case 0xD7:
		{
			break;
		}
	case 0xD8:
		{
			break;
		}
	case 0xD9:
		{
			break;
		}
	case 0xDA:
		{
			break;
		}
	case 0xDB:
		{
			break;
		}
	case 0xDC:
		{
			break;
		}
	case 0xDD:
		{
			break;
		}
	case 0xDE:
		{
			break;
		}
	case 0xE0:
		{
			break;
		}
	case 0xE1:
		{
			break;
		}
	case 0xE2:
		{
			break;
		}
	case 0xE3:
		{
			break;
		}
	case 0xE4:
		{
			break;
		}
	case 0xE5:
		{
			break;
		}
	case 0xE6:
		{
			break;
		}
	case 0xE7:
		{
			break;
		}
	case 0xE8:
		{
			break;
		}
	case 0xE9:
		{
			break;
		}
	case 0xEA:
		{
			break;
		}
	case 0xEB:
		{
			break;
		}
	case 0xEC:
		{
			break;
		}
	case 0xED:
		{
			break;
		}
	case 0xEE:
		{
			break;
		}
	case 0xEF:
		{
			break;
		}
	case 0xF1:
		{
			break;
		}
	case 0xF2:
		{
			break;
		}
	case 0xF3:
		{
			break;
		}
	case 0xF4:
		{
			break;
		}
	case 0xF5:
		{
			break;
		}
	case 0xF6:
		{
			break;
		}
	case 0xF7:
		{
			break;
		}
	case 0xF8:
		{
			break;
		}
	case 0xF9:
		{
			break;
		}
	case 0xFA:
		{
			break;
		}
	case 0xFB:
		{
			break;
		}
	case 0xFC:
		{
			break;
		}
	case 0xFD:
		{
			break;
		}
	case 0xFE:
		{
			break;
		}
	case 0xFF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2ROUND(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x08:
		{
			break;
		}
	case 0x09:
		{
			break;
		}
	case 0x0A:
		{
			break;
		}
	case 0x0B:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2ALIGN(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x0F:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2EXT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x14:
		{
			break;
		}
	case 0x15:
		{
			break;
		}
	case 0x16:
		{
			break;
		}
	case 0x17:
		{
			break;
		}
	case 0x19:
		{
			break;
		}
	case 0x39:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2INS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x18:
		{
			break;
		}
	case 0x20:
		{
			break;
		}
	case 0x21:
		{
			break;
		}
	case 0x22:
		{
			break;
		}
	case 0x38:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2CVT(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x1D:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2PPS(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x40:
		{
			break;
		}
	case 0x41:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2SAD(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x42:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2MUL(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x44:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2CMP(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0x60:
		{
			break;
		}
	case 0x61:
		{
			break;
		}
	case 0x62:
		{
			break;
		}
	case 0x63:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2VAESKEYGEN(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xDF:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

int Decode3_2ROR(BYTE byOpcode, BYTE* byarPrefix)
{
	int nReturnValue = 0;

	switch(byOpcode)
	{
	case 0xF0:
		{
			break;
		}
	default:
		{
			break;
		}
	}

	return nReturnValue;

}

















