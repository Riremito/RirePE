#ifndef __PACKET_TV_H__
#define __PACKET_TV_H__

#include<Windows.h>


enum TenviRegion {
	TENVI_JP,
	TENVI_KR,
	TENVI_KRX,
	TENVI_HK,
	TENVI_CN,
};

typedef struct {
	HINSTANCE hinstDLL;
	TenviRegion region;
	bool debug_mode;
	ULONG_PTR uSendPacket;
	ULONG_PTR uOutPacket;
	ULONG_PTR uEncode1;
	ULONG_PTR uEncode2;
	ULONG_PTR uEncode4;
	ULONG_PTR uEncode8;
	ULONG_PTR uEncodeFloat;
	ULONG_PTR uEncodeStrW1;
	ULONG_PTR uEncodeStrW2;
	ULONG_PTR uProcessPacket;
	ULONG_PTR uDecodeHeader;
	ULONG_PTR uDecode1;
	ULONG_PTR uDecode2;
	ULONG_PTR uDecode4;
	ULONG_PTR uDecode8;
	ULONG_PTR uDecodeFloat;
	ULONG_PTR uDecodeStrW1;
	ULONG_PTR uDecodeStrW2;
	ULONG_PTR uClientSocketBase;
	ULONG_PTR uClientSocketOffset;
} TenviHookConfig;


#endif