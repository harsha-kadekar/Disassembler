#ifndef PEPARSERHELPER_H
#define PEPARSERHELPER_H

#include <windows.h>
#include <stdio.h>

DWORD RVAToOffset(LPVOID lpFileBase, DWORD dwRVA);

extern "C" __declspec(dllexport) int ParsePEFile(char* lpstrFileName);

typedef struct structInstruction
{
	BYTE* PrefixPart;
	BYTE* OpcodePart;
	BYTE modrmpart;
	BYTE sibpart;
	bool bmodRMExists;
	bool bSibExists;
	int DisplacementSize;
	int ImmediateSize;
	int PrefixSize;
	int OpcodeSize;
	DWORD Displacement;
	DWORD Immediate;
	int LengthOfInstruction;
	char* actualInstruction;
	char* encodedInstruction;
	DWORD beginingAddress;
}Instruction;

typedef struct structModRegRM
{
	BYTE actualModeRegRM;
	int mode;
	int reg;
	int rm;
}ModRegRM;

typedef struct structSIB
{
	BYTE actualSIB;
	int scale;
	int index;
	int base;
}SIB;

int DecodeADD(BYTE byOpcode, BYTE* byarPrefix);

#endif