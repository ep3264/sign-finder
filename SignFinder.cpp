// SignFinder.cpp: определяет точку входа для консольного приложения.
//
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#include "stdafx.h"
#include <string.h>
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <psapi.h>//информация о памяти процесса
#include <fstream>//для вывода в документ адресов и значений по ним
using namespace std;
#pragma comment(lib, "psapi.lib")
typedef struct _tagThreadInfo
{
	FILETIME ftCreationTime;
	DWORD dwUnknown1;
	DWORD dwStartAddress;
	DWORD dwOwningPID;
	DWORD dwThreadID;
	DWORD dwCurrentPriority;
	DWORD dwBasePriority;
	DWORD dwContextSwitches;
	DWORD dwThreadState;
	DWORD dwWaitReason;
	DWORD dwUnknown2[5];
} THREADINFO, *PTHREADINFO;

#pragma warning(disable:4200)
typedef struct _tagProcessInfo
{
	DWORD dwOffset;
	DWORD dwThreadCount;
	DWORD dwUnknown1[6];
	FILETIME ftCreationTime;
	DWORD dwUnknown2[5];
	WCHAR* pszProcessName;
	DWORD dwBasePriority;
	DWORD dwProcessID;
	DWORD dwParentProcessID;
	DWORD dwHandleCount;
	DWORD dwUnknown3;
	DWORD dwUnknown4;
	DWORD dwVirtualBytesPeak;
	DWORD dwVirtualBytes;
	DWORD dwPageFaults;
	DWORD dwWorkingSetPeak;
	DWORD dwWorkingSet;
	DWORD dwUnknown5;
	DWORD dwPagedPool;
	DWORD dwUnknown6;
	DWORD dwNonPagedPool;
	DWORD dwPageFileBytesPeak;
	DWORD dwPrivateBytes;
	DWORD dwPageFileBytes;
	DWORD dwUnknown7[4];
	THREADINFO ti[0];
} _PROCESSINFO, *PPROCESSINFO;
#pragma warning( default:4200 )
long(__stdcall *NtQuerySystemInformation)(ULONG, PVOID, ULONG, ULONG) = NULL;

DWORD m_PID;

boolean GetPriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;
	BOOL res=false;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE)
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug) != FALSE)
		{
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL) != FALSE)
			{
				res = true;
				// Always successful, even in the cases which lead to OpenProcess failure
				//cout << "SUCCESSFULLY CHANGED TOKEN PRIVILEGES" << endl;
			}
			else
			{
				cout << "FAILED TO CHANGE TOKEN PRIVILEGES, CODE: " << GetLastError() << endl;
			}
		}
	}
	CloseHandle(hToken);
	return res;
}
boolean TestSign(PBYTE buff, PBYTE sign, PBYTE mask)
{
	while (*mask)
	{
		if (*mask != '?') { 
			if (*buff != *sign) {
				return false;
			}			 
		}	
		mask++; buff++; sign++;
			
	}
	return true;
}
BOOL ReadMemory(DWORD64 addr, PBYTE buffer, int size, HANDLE hProcess)
{
	BOOL result = false;
	SIZE_T b_read;
	result = ReadProcessMemory(hProcess,LPCVOID(addr),buffer,size,&b_read);
	DWORD err=GetLastError();
	
	return result;
}
DWORD64 ScanSign(DWORD64 baseAdress, PBYTE sign, DWORD64 scanSize, PBYTE mask)
{
	MEMORY_BASIC_INFORMATION mbi = {0};
	DWORD64 offset = 0;
	PBYTE buffer;
	if (GetPriv()){
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, m_PID);
		if (hProcess){
			while (offset < scanSize)
			{
				VirtualQueryEx(hProcess, (LPVOID)(baseAdress + offset), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				//if (mbi.State != MEM_FREE)
				if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_READONLY && mbi.Protect != PAGE_GUARD && mbi.Protect != PAGE_NOACCESS)
				{
					buffer = new byte[mbi.RegionSize];
					if (ReadMemory((DWORD64)mbi.BaseAddress, buffer, mbi.RegionSize, hProcess)){
						for (DWORD64 i = 0; i < mbi.RegionSize; i++)
						{
							if ((mbi.RegionSize - i) >= sizeof(sign)){
								if (TestSign(buffer + i, sign, mask))
								{
									CloseHandle(hProcess);
									delete(buffer);
									return (DWORD64)mbi.BaseAddress + i;

								}
							}
						}
					}

					delete(buffer);
				}
				offset += mbi.RegionSize;
			}
			CloseHandle(hProcess);
		}
		else{
			DWORD error = GetLastError();
			printf("Cannot open process %d, id error: %d\n", m_PID, error);
		}
	}
	return 0;
}
//получить базовый адрес процесса
LPVOID GetBaseAddress(HANDLE hProc)
{
	//структура с информацией о процессе
	MODULEINFO miInfo;

	//получаем базовый адрес процесса
	if (GetModuleInformation(hProc, NULL, &miInfo, sizeof(miInfo)))
		return miInfo.EntryPoint;
	else
		return NULL;
}

//получить размер используемой памяти приложения(в байтах)
DWORD GetMemorySize(HANDLE hProc)
{
	//структура с информацией о процессе
	PROCESS_MEMORY_COUNTERS pmcInfo;

	//получаем информацию о процессе
	if (GetProcessMemoryInfo(hProc, &pmcInfo, sizeof(pmcInfo)))
		return (DWORD)pmcInfo.WorkingSetSize;
	else
		return 0;
}

void main()
{
	setlocale(LC_ALL, "Russian");//устанавливаем русский язык для вывода
	byte sign[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0xA4, 0xFF,
		0x15, 0x00, 0x00, 0x00, 0x00, 0x50, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00 };
	byte mask[] = "x????x????xxx????xxx????x????";
	DWORD curProcId = GetCurrentProcessId();
	BOOL bLast = FALSE;
	PBYTE pbyInfo = NULL;
	DWORD cInfoSize = 0x2000;
	PPROCESSINFO pProcessInfo = { 0 };
	char buff[MAX_PATH];
	char szProcessName[MAX_PATH] = { 0 };
	char  buffer[MAX_PATH];
	if (!(pbyInfo = (PBYTE)malloc(cInfoSize))){
		strerror_s(buffer, GetLastError());
		printf("Allocation memory error %s\n", buffer);
	}
	else
		NtQuerySystemInformation =
		(long(__stdcall *)(ULONG, PVOID, ULONG, ULONG))
		GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
	if (!NtQuerySystemInformation){
		strerror_s(buffer, GetLastError());
		printf("Error updating NtQueryInfo pointer %s\n", buffer);
	}
	else
	{
		printf(" PROCID | PARENT| PROCESS_NAME\n");
		while (NtQuerySystemInformation(/*SYSTEM_PROCESS_INFORMATION*/5, pbyInfo, cInfoSize, 0) == STATUS_INFO_LENGTH_MISMATCH)
		{
			cInfoSize += 0x2000;
			pbyInfo = (PBYTE)realloc(pbyInfo, cInfoSize);
		}
		pProcessInfo = (PPROCESSINFO)pbyInfo;
		while (!bLast)
		{
			if (pProcessInfo->dwOffset == 0) // 
				bLast = TRUE;
			else
			{
				if
					(
					!WideCharToMultiByte
					(
					CP_ACP,
					0,
					pProcessInfo->pszProcessName,
					-1,
					szProcessName,
					MAX_PATH,
					NULL,
					NULL
					)//
					){

					strerror_s(buff, GetLastError());
					sprintf_s(szProcessName, "%s", buff);
				}
				CharToOem(szProcessName, szProcessName);
				if (pProcessInfo->dwProcessID){ // ignore system idle
					printf
						(
						" %03u\t| %03u\t| %s\n",
						pProcessInfo->dwProcessID,
						pProcessInfo->dwParentProcessID,
						szProcessName
						);
					m_PID = pProcessInfo->dwProcessID;
					SYSTEM_INFO msi;
					GetSystemInfo(&msi); //тут я получаю состояние системы.

					//получаем минимальный адрес поиска
					DWORD64 dwStart = (DWORD64)msi.lpMinimumApplicationAddress;

					//получаем максимальный адрес поиска
					DWORD64 dwMemSize = (DWORD64)msi.lpMaximumApplicationAddress;

				
					DWORD res = ScanSign(dwStart, sign, dwMemSize - dwStart, mask);
					
						if (res > 0){							
							printf("Address: %x\n", res);
							/*
							HANDLE ProcessHandle = OpenProcess(PROCESS_TERMINATE, FALSE, m_PID);
							TerminateProcess(ProcessHandle, 0);*/
							break; 
						}
				
				}
				pProcessInfo = (PPROCESSINFO)((PBYTE)pProcessInfo + pProcessInfo->dwOffset); // next
			}

		}
	}
	/*
	if (HWND bot = FindWindow(NULL, "WinTest"))
	{
		
		GetWindowThreadProcessId(bot, &m_PID);
		SYSTEM_INFO msi;
		GetSystemInfo(&msi); //тут я получаю состояние системы.

		//получаем минимальный адрес поиска
		DWORD64 dwStart = (DWORD64)msi.lpMinimumApplicationAddress;

		//получаем максимальный адрес поиска
		DWORD64 dwMemSize =(DWORD64)msi.lpMaximumApplicationAddress;

		
		DWORD res = ScanSign(dwStart, sign, dwMemSize - dwStart, mask);
		printf("Adress: %x\n", res);
	
	}
	*/
	system("pause");
	return ;
}

