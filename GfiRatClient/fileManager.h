// FileManager.h: interface for the CFileManager class.
//
//////////////////////////////////////////////////////////////////////
#pragma once


#include <winsock2.h>


#include <list>
#include <string>

#include "Manager.h"
using namespace std;

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

typedef struct 
{
	UINT	nFileSize;	// �ļ���С
	UINT	nSendSize;	// �ѷ��ʹ�С
}SENDFILEPROGRESS, *PSENDFILEPROGRESS;


class CFileManager : public CManager
{
public:
	void OnReceive(LPBYTE lpBuffer, UINT nSize);
	UINT SendDriveList();
	CFileManager(CClientSocket *pClient);
	virtual ~CFileManager();
private:
	list <string> m_UploadList;
	UINT m_nTransferMode;
	char m_strCurrentProcessFileName[MAX_PATH]; // ��ǰ���ڴ�����ļ�
	__int64 m_nCurrentProcessFileLength; // ��ǰ���ڴ�����ļ��ĳ���
	bool MakeSureDirectoryPathExists(LPCTSTR pszDirPath);
	bool UploadToRemote(LPBYTE lpBuffer);
	bool FixedUploadList(LPCTSTR lpszDirectory);
	void StopTransfer();
	UINT SendFilesList(LPCTSTR lpszDirectory);
	bool DeleteDirectory(LPCTSTR lpszDirectory);
	UINT SendFileSize(LPCTSTR lpszFileName);
	UINT SendFileData(LPBYTE lpBuffer);
	void CreateFolder(LPBYTE lpBuffer);
	void Rename(LPBYTE lpBuffer);
	int	SendToken(BYTE bToken);
	HANDLE ImpersonateLoggedOnUserWrapper();
	void CreateLocalRecvFile(LPBYTE lpBuffer);
	void SetTransferMode(LPBYTE lpBuffer);
	void GetFileData();
	void WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize);
	void UploadNext();
	bool OpenFile(LPCTSTR lpFile, INT nShowCmd);
	void ExeCompress(BYTE* lpBuffer);
};

