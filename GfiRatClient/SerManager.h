#pragma once


#include "Manager.h"

class CSerManager : public CManager
{
public:
	CSerManager(CClientSocket* pClient);
	virtual ~CSerManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);

private:
	LPBYTE getServicesList();
	void SendServicesList();

	void StartStopService(LPBYTE lpBuffer, UINT nSize, BOOL strp);
	//	void CreatService(LPBYTE lpBuffer, UINT nSize);
	void DeleteService(LPBYTE lpBuffer, UINT nSize);
	void DisableService(LPBYTE lpBuffer, UINT nSize, UCHAR strn);
};
