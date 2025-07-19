#include"TV_PacketHook.h"
#include"TV_PacketLogging.h"


void (__thiscall *_SendPacket)(void *, TV_OutPacket *);
void (__thiscall *_COutPacket)(TV_OutPacket *, BYTE, void *);
void (__thiscall *_Encode1)(TV_OutPacket *, BYTE);
void (__thiscall *_Encode2)(TV_OutPacket *, WORD);
void (__thiscall *_Encode4)(TV_OutPacket *, DWORD);
void (__thiscall *_EncodeStr)(TV_OutPacket *, char *);
void (__thiscall *_EncodeBuffer)(TV_OutPacket *, BYTE *, DWORD);
void (__thiscall *_EncodeFloat)(TV_OutPacket *, float);
void (__thiscall *_EncodeStrW1)(TV_OutPacket *, WCHAR *);
void (__thiscall *_ProcessPacket)(void *, void*, TV_InPacket *, DWORD);
BYTE (__thiscall *_DecodeHeader)(TV_InPacket *);
BYTE (__thiscall *_Decode1)(TV_InPacket *);
WORD (__thiscall *_Decode2)(TV_InPacket *);
DWORD (__thiscall *_Decode4)(TV_InPacket *);
ULONGLONG (__thiscall *_Decode8)(TV_InPacket *);
char** (__thiscall *_DecodeStr)(TV_InPacket *, char **);
void (__thiscall *_DecodeBuffer)(TV_InPacket *, BYTE*, DWORD);
float (__thiscall *_DecodeFloat)(TV_InPacket *);
WCHAR** (__thiscall *_DecodeStrW1)(TV_InPacket *, WCHAR **);
WCHAR** (__thiscall *_DecodeStrW2)(TV_InPacket *, WCHAR **);


// 先にフォーマット情報は送信される
void __fastcall SendPacket_Hook(void *ecx, void *edx, TV_OutPacket *oPacket) {
	bool bBlock = false;
	AddSendPacket(oPacket, (DWORD)_ReturnAddress(), bBlock);
	if (bBlock) {
		return;
	}
	return _SendPacket(ecx, oPacket);
}

void __fastcall COutPacket_Hook(TV_OutPacket *oPacket, void *edx, BYTE b, void *v) {
	PacketExtraInformation pxi = { get_packet_id_out(), (ULONG_PTR)_ReturnAddress(), TV_ENCODEHEADER, 0, sizeof(BYTE) };
	AddExtra(pxi);
	return _COutPacket(oPacket, b, v);
}

void __fastcall Encode1_Hook(TV_OutPacket *oPacket, void *edx, BYTE b) {
	if (oPacket->encoded) {
		PacketExtraInformation pxi = { get_packet_id_out(), (ULONG_PTR)_ReturnAddress(), ENCODE1, oPacket->encoded, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Encode1(oPacket, b);
}

void __fastcall Encode2_Hook(TV_OutPacket *oPacket, void *edx, WORD w) {
	PacketExtraInformation pxi = { get_packet_id_out(), (ULONG_PTR)_ReturnAddress(), ENCODE2, oPacket->encoded, sizeof(WORD) };
	AddExtra(pxi);
	return _Encode2(oPacket, w);

}

void __fastcall Encode4_Hook(TV_OutPacket *oPacket, void *edx, DWORD dw) {
	PacketExtraInformation pxi = { get_packet_id_out(), (ULONG_PTR)_ReturnAddress(), ENCODE4, oPacket->encoded, sizeof(DWORD) };
	AddExtra(pxi);
	return _Encode4(oPacket, dw);
}

void __fastcall EncodeStr_Hook(TV_OutPacket *oPacket, void *edx, char *s) {
	PacketExtraInformation pxi = { get_packet_id_out(), (DWORD)_ReturnAddress(), ENCODESTR, oPacket->encoded, sizeof(WORD) + strlen(s) };
	AddExtra(pxi);
	return _EncodeStr(oPacket, s);
}

void __fastcall EncodeBuffer_Hook(TV_OutPacket *oPacket, void *edx, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { get_packet_id_out(), (ULONG_PTR)_ReturnAddress(), ENCODEBUFFER, oPacket->encoded, len };
	AddExtra(pxi);
	return _EncodeBuffer(oPacket, b, len);
}


void __fastcall EncodeFloat_Hook(TV_OutPacket *oPacket, void *edx, float f) {
	PacketExtraInformation pxi = { get_packet_id_out(), (ULONG_PTR)_ReturnAddress(), ENCODE4, oPacket->encoded, sizeof(float) };
	AddExtra(pxi);
	return _EncodeFloat(oPacket, f);
}

void __fastcall EncodeStrW1_Hook(TV_OutPacket *oPacket, void *edx, WCHAR *wc) {
	BYTE len = 0;
	while (wc[len] && len < 0xFF) {
		len++;
	}
	PacketExtraInformation pxi = { get_packet_id_out(), (DWORD)_ReturnAddress(), TV_ENCODESTRW1, oPacket->encoded, sizeof(BYTE) + len * sizeof(WORD) };
	AddExtra(pxi);
	return _EncodeStrW1(oPacket, wc);
}
void __fastcall ProcessPacket_Hook(void *pCClientSocket, void *edx, void *v1, TV_InPacket *iPacket, DWORD v3) {
	bool bBlock = false;
	AddRecvPacket(iPacket, (ULONG_PTR)_ReturnAddress(), bBlock);
	if (!bBlock) {
		_ProcessPacket(pCClientSocket, v1, iPacket, v3);
	}
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)0, DECODE_END, iPacket->decoded - 4, 0 };
	AddExtra(pxi);
}

WORD __fastcall DecodeHeader_Hook(TV_InPacket *iPacket, void *edx) {
	if (iPacket->decoded != 0x04) {
		//DEBUG(L"S - " + DWORDtoString((DWORD)_ReturnAddress()));
		// second decoding (same packet)
		PacketExtraInformation pxi_end = { get_packet_id_in(), (ULONG_PTR)0, DECODE_END, iPacket->decoded - 4, 0 };
		AddExtra(pxi_end);
		// restart
		bool bBlock = false;
		AddRecvPacket(iPacket, (ULONG_PTR)_ReturnAddress(), bBlock); // test
	}
	else {
		//DEBUG(L"F - " + DWORDtoString((DWORD)_ReturnAddress()));
	}

	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), TV_DECODEHEADER, 0, sizeof(BYTE) };
	AddExtra(pxi);
	return _DecodeHeader(iPacket);
}

BYTE __fastcall Decode1_Hook(TV_InPacket *iPacket, void *edx) {
	if (iPacket->decoded != 0x04) {
		PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), DECODE1, iPacket->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Decode1(iPacket);
}

WORD __fastcall Decode2_Hook(TV_InPacket *iPacket, void *edx) {
		PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), DECODE2, iPacket->decoded - 4, sizeof(WORD) };
		AddExtra(pxi);
	return _Decode2(iPacket);
}

DWORD __fastcall Decode4_Hook(TV_InPacket *iPacket, void *edx) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), DECODE4, iPacket->decoded - 4, sizeof(DWORD) };
	AddExtra(pxi);
	return _Decode4(iPacket);
}

ULONGLONG __fastcall Decode8_Hook(TV_InPacket *iPacket) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), DECODE8, iPacket->decoded - 4, sizeof(ULONGLONG) };
	AddExtra(pxi);
	return _Decode8(iPacket);
}


char** __fastcall DecodeStr_Hook(TV_InPacket *iPacket, void *edx, char **s) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), DECODESTR, iPacket->decoded - 4, sizeof(WORD) + *(WORD *)&iPacket->packet[iPacket->decoded] };
	AddExtra(pxi);
	return _DecodeStr(iPacket, s);
}

void __fastcall DecodeBuffer_Hook(TV_InPacket *iPacket, void *edx, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), DECODEBUFFER, iPacket->decoded - 4, len };
	AddExtra(pxi);
	return _DecodeBuffer(iPacket, b, len);
}

float __fastcall DecodeFloat_Hook(TV_InPacket *iPacket) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), TV_DECODEFLOAT, iPacket->decoded - 4, sizeof(float) };
	AddExtra(pxi);
	return _DecodeFloat(iPacket);
}

WCHAR** __fastcall DecodeStrW1_Hook(TV_InPacket *iPacket, void *edx, WCHAR **wc) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), TV_DECODESTRW1, iPacket->decoded - 4, sizeof(BYTE) + iPacket->packet[iPacket->decoded] * 2 };
	AddExtra(pxi);
	return _DecodeStrW1(iPacket, wc);
}

WCHAR** __fastcall DecodeStrW2_Hook(TV_InPacket *iPacket, void *edx, WCHAR **wc) {
	PacketExtraInformation pxi = { get_packet_id_in(), (ULONG_PTR)_ReturnAddress(), TV_DECODESTRW2, iPacket->decoded - 4, sizeof(WORD) + *(WORD *)&iPacket->packet[iPacket->decoded] * 2 };
	AddExtra(pxi);
	return _DecodeStrW2(iPacket, wc);
}

ULONG_PTR gClientSocketBase = 0;
ULONG_PTR gClientSocketOffset = 0;
ULONG_PTR getTV_ClientSocketPtr() {
	if (!gClientSocketBase || !gClientSocketOffset) {
		return 0;
	}

	return *(ULONG_PTR *)gClientSocketBase + gClientSocketOffset;
}

bool PacketHookConf_TV(TenviHookConfig &thc) {
	Rosemary r;
	/*
	SHookFunction(SendPacket, thc.uSendPacket);
	SHookFunction(COutPacket, thc.uOutPacket);
	SHookFunction(Encode1, thc.uEncode1);
	SHookFunction(Encode2, thc.uEncode2);
	SHookFunction(Encode4, thc.uEncode4);
	SHookFunction(EncodeStrW1, thc.uEncodeStrW1);
	*/
	SHookFunction(ProcessPacket, thc.uProcessPacket);
	SHookFunction(DecodeHeader, thc.uDecodeHeader);
	SHookFunction(Decode1, thc.uDecode1);
	SHookFunction(Decode2, thc.uDecode2);
	SHookFunction(Decode4, thc.uDecode4);
	SHookFunction(DecodeStrW1, thc.uDecodeStrW1);
	SHookFunction(DecodeStrW2, thc.uDecodeStrW2);
	SHookFunction(Decode8, thc.uDecode8);
	SHookFunction(DecodeFloat, thc.uDecodeFloat);

	gClientSocketBase = thc.uClientSocketBase;
	gClientSocketOffset = thc.uClientSocketOffset;

	RunPacketSender();
	return true;
}
