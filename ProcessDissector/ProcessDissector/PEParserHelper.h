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

int DecodeADD(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodePushPoP(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeOR(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeADC(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeSBB(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeAND(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeDAA(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeSUB(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeDAS(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeXOR(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeAAA(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeCMP(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeAAS(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeINC(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeDEC(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeBOUND(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);
int DecodeMOV(BYTE byOpcode, BYTE* byarRawCode, int nCurrentIndex, int nSize, Instruction* pInst);

#endif