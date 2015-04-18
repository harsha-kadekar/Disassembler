#ifndef PEPARSERHELPER_H
#define PEPARSERHELPER_H

#include <windows.h>
#include <stdio.h>

DWORD RVAToOffset(LPVOID lpFileBase, DWORD dwRVA);

extern "C" __declspec(dllexport) int ParsePEFile(char* lpstrFileName);

#endif