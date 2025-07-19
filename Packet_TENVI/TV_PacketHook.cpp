#include"TV_PacketHook.h"
#include"TV_PacketLogging.h"


void (__thiscall *_SendPacket)(void *, TV_OutPacket *);
void (__thiscall *_COutPacket)(TV_OutPacket *, BYTE, void *);
void (__thiscall *_Encode1)(TV_OutPacket *, BYTE);
void (__thiscall *_Encode2)(TV_OutPacket *, WORD);
void (__thiscall *_Encode4)(TV_OutPacket *, DWORD);
void (__thiscall *_EncodeStr)(TV_OutPacket *, char *);
void (__thiscall *_EncodeStrW1)(TV_OutPacket *, WCHAR *);
void (__thiscall *_EncodeBuffer)(TV_OutPacket *, BYTE *, DWORD);
void (__thiscall *_ProcessPacket)(void *, TV_InPacket *);
BYTE (__thiscall *_DecodeHeader)(TV_InPacket *);
BYTE (__thiscall *_Decode1)(TV_InPacket *);
WORD (__thiscall *_Decode2)(TV_InPacket *);
DWORD (__thiscall *_Decode4)(TV_InPacket *);
ULONGLONG (__thiscall *_Decode8)(TV_InPacket *);
float (__thiscall *_DecodeFloat)(TV_InPacket *);
char** (__thiscall *_DecodeStr)(TV_InPacket *, char **);
WCHAR** (__thiscall *_DecodeStrW1)(TV_InPacket *, WCHAR **);
WCHAR** (__thiscall *_DecodeStrW2)(TV_InPacket *, WCHAR **);
void (__thiscall *_DecodeBuffer)(TV_InPacket *, BYTE*, DWORD);


extern DWORD packet_id_out, packet_id_in;


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
	packet_id_out++;
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), TENVI_ENCODE_HEADER_1, 0, sizeof(BYTE) };
	AddExtra(pxi);
	return _COutPacket(oPacket, b, v);
}

void __fastcall Encode1_Hook(TV_OutPacket *oPacket, void *edx, BYTE b) {
	if (oPacket->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE1, oPacket->encoded, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Encode1(oPacket, b);
}

void __fastcall Encode2_Hook(TV_OutPacket *oPacket, void *edx, WORD w) {
	if (oPacket->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE2, oPacket->encoded, sizeof(WORD) };
		AddExtra(pxi);
	}
	return _Encode2(oPacket, w);

}

void __fastcall Encode4_Hook(TV_OutPacket *oPacket, void *edx, DWORD dw) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE4, oPacket->encoded, sizeof(DWORD) };
	AddExtra(pxi);
	return _Encode4(oPacket, dw);
}

void __fastcall EncodeStr_Hook(TV_OutPacket *oPacket, void *edx, char *s) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODESTR, oPacket->encoded, sizeof(WORD) + strlen(s) };
	AddExtra(pxi);
	return _EncodeStr(oPacket, s);
}

void __fastcall EncodeStrW1_Hook(TV_OutPacket *oPacket, void *edx, WCHAR *wc) {
	BYTE len = 0;
	while (wc[len] && len < 0xFF) {
		len++;
	}
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), TENVI_ENCODE_WSTR_1, oPacket->encoded, sizeof(BYTE) + len * sizeof(WORD) };
	AddExtra(pxi);
	return _EncodeStrW1(oPacket, wc);
}

void __fastcall EncodeBuffer_Hook(TV_OutPacket *oPacket, void *edx, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEBUFFER, oPacket->encoded, len };
	AddExtra(pxi);
	return _EncodeBuffer(oPacket, b, len);
}

void __fastcall ProcessPacket_Hook(void *pCClientSocket, void *edx, TV_InPacket *iPacket) {
	bool bBlock = false;
	AddRecvPacket(iPacket, (ULONG_PTR)_ReturnAddress(), bBlock);
	if (!bBlock) {
		_ProcessPacket(pCClientSocket, iPacket);
	}
	PacketExtraInformation pxi = { packet_id_in++, (ULONG_PTR)0, DECODE_END, 0, 0 };
	AddExtra(pxi);
}

WORD __fastcall DecodeHeader_Hook(TV_InPacket *iPacket, void *edx) {
	if (iPacket->decoded == 0x04) {
		{
			PacketExtraInformation pxi = { packet_id_in++, (ULONG_PTR)0, DECODE_END, 0, 0 };
			AddExtra(pxi);

			packet_id_in++;
			bool bBlock = false;
			AddRecvPacket(iPacket, (ULONG_PTR)_ReturnAddress(), bBlock);
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), TENVI_DECODE_HEADER_1, iPacket->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _DecodeHeader(iPacket);
}

BYTE __fastcall Decode1_Hook(TV_InPacket *iPacket, void *edx) {
	if (iPacket->decoded != 0x04) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE1, iPacket->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Decode1(iPacket);
}

WORD __fastcall Decode2_Hook(TV_InPacket *iPacket, void *edx) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE2, iPacket->decoded - 4, sizeof(WORD) };
		AddExtra(pxi);
	return _Decode2(iPacket);
}

DWORD __fastcall Decode4_Hook(TV_InPacket *iPacket, void *edx) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE4, iPacket->decoded - 4, sizeof(DWORD) };
	AddExtra(pxi);
	return _Decode4(iPacket);
}

char** __fastcall DecodeStr_Hook(TV_InPacket *iPacket, void *edx, char **s) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODESTR, iPacket->decoded - 4, sizeof(WORD) + *(WORD *)&iPacket->packet[iPacket->decoded] };
	AddExtra(pxi);
	return _DecodeStr(iPacket, s);
}

WCHAR** __fastcall DecodeStrW1_Hook(TV_InPacket *iPacket, void *edx, WCHAR **wc) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), TENVI_DECODE_WSTR_1, iPacket->decoded - 4, sizeof(BYTE) + iPacket->packet[iPacket->decoded] * 2 };
	AddExtra(pxi);
	return _DecodeStrW1(iPacket, wc);
}

WCHAR** __fastcall DecodeStrW2_Hook(TV_InPacket *iPacket, void *edx, WCHAR **wc) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), TENVI_DECODE_WSTR_2, iPacket->decoded - 4, sizeof(WORD) + *(WORD *)&iPacket->packet[iPacket->decoded] * 2 };
	AddExtra(pxi);
	return _DecodeStrW2(iPacket, wc);
}

void __fastcall DecodeBuffer_Hook(TV_InPacket *iPacket, void *edx, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEBUFFER, iPacket->decoded - 4, len };
	AddExtra(pxi);
	return _DecodeBuffer(iPacket, b, len);
}

ULONGLONG __fastcall Decode8_Hook(TV_InPacket *iPacket) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE8, iPacket->decoded - 4, sizeof(ULONGLONG) };
	AddExtra(pxi);
	return _Decode8(iPacket);
}

float __fastcall DecodeFloat_Hook(TV_InPacket *iPacket) {
	PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE4, iPacket->decoded - 4, sizeof(DWORD) };
	AddExtra(pxi);
	return _DecodeFloat(iPacket);
}

bool PacketHookConf_TV(TenviHookConfig &thc) {
	Rosemary r;

	SHookFunction(SendPacket, thc.uSendPacket);
	SHookFunction(COutPacket, thc.uOutPacket);
	SHookFunction(Encode1, thc.uEncode1);
	SHookFunction(Encode2, thc.uEncode2);
	SHookFunction(Encode4, thc.uEncode4);
	SHookFunction(EncodeStrW1, thc.uEncodeStrW1);
	SHookFunction(DecodeHeader, thc.uDecodeHeader);
	SHookFunction(Decode1, thc.uDecode1);
	SHookFunction(Decode2, thc.uDecode2);
	SHookFunction(Decode4, thc.uDecode4);
	SHookFunction(DecodeStrW1, thc.uDecodeStrW1);
	SHookFunction(DecodeStrW2, thc.uDecodeStrW2);
	SHookFunction(Decode8, thc.uDecode8);
	SHookFunction(DecodeFloat, thc.uDecodeFloat);
	//RunPacketSender();
	return true;
}
