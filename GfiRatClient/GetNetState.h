
#pragma once
#include <WINSOCK2.H>   
#include <Windows.h>
#include <Iphlpapi.h>     
#include <tlhelp32.h>     

 

#pragma comment(lib, "Iphlpapi.lib")     
#pragma comment(lib, "WS2_32.lib")     

typedef struct
{
	DWORD   dwState;          // ����״̬     
	DWORD   dwLocalAddr;      // ���ص�ַ     
	DWORD   dwLocalPort;      // ���ض˿�     
	DWORD   dwRemoteAddr;     // Զ�̵�ַ     
	DWORD   dwRemotePort;     // Զ�̶˿�     
	DWORD   dwProcessId;      // ����ID��     
} MIB_TCPEXROW, * PMIB_TCPEXROW;

typedef struct
{
	DWORD           dwNumEntries;
	MIB_TCPEXROW    table[ANY_SIZE];
} MIB_TCPEXTABLE, * PMIB_TCPEXTABLE;

typedef struct
{
	DWORD   dwLocalAddr;      // ���ص�ַ     
	DWORD   dwLocalPort;      // ���ض˿�     
	DWORD   dwProcessId;      // ����ID��     
} MIB_UDPEXROW, * PMIB_UDPEXROW;

typedef struct
{
	DWORD           dwNumEntries;
	MIB_UDPEXROW    table[ANY_SIZE];
} MIB_UDPEXTABLE, * PMIB_UDPEXTABLE;


// ��չ����ԭ��     
typedef DWORD(WINAPI* PFNAllocateAndGetTcpExTableFromStack)(
	PMIB_TCPEXTABLE* pTcpTable,
	BOOL bOrder,
	HANDLE heap,
	DWORD zero,
	DWORD flags
	);

typedef DWORD(WINAPI* PFNAllocateAndGetUdpExTableFromStack)(
	PMIB_UDPEXTABLE* pUdpTable,
	BOOL bOrder,
	HANDLE heap,
	DWORD zero,
	DWORD flags
	);


typedef struct {
	DWORD dwState;      //����״̬
	DWORD dwLocalAddr;  //���ص�ַ
	DWORD dwLocalPort;  //���ض˿�
	DWORD dwRemoteAddr; //Զ�̵�ַ
	DWORD dwRemotePort; //Զ�̶˿�
	DWORD dwProcessId;  //���̱�ʶ
	DWORD Unknown;      //������ʶ
}MIB_TCPEXROW_VISTA, * PMIB_TCPEXROW_VISTA;

typedef struct {
	DWORD dwNumEntries;
	MIB_TCPEXROW_VISTA table[ANY_SIZE];
}MIB_TCPEXTABLE_VISTA, * PMIB_TCPEXTABLE_VISTA;

typedef DWORD(WINAPI* _InternalGetTcpTable2)(
	PMIB_TCPEXTABLE_VISTA* pTcpTable_Vista,
	HANDLE heap,
	DWORD flags
	);


typedef DWORD(WINAPI* PFNInternalGetUdpTableWithOwnerPid)(
	PMIB_UDPEXTABLE* pUdpTable,
	HANDLE heap,
	DWORD flags
	);


PCHAR ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, PCHAR ProcessName);

LPBYTE getNetStateList();
