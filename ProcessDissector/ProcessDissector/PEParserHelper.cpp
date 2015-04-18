/*
*	This file contains various functions which will help to parse a PE file. Functions which will help to retrive complete information about PE File, functions which will help to retrieve only export table, import table, different sections, etc.
*	Idea is to this will help to simulate the DumpBin utility.
*
*/


#include "PEParserHelper.h"



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

