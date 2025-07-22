#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#include"../Packet/PacketHook.h"
#include"../Packet/AobList.h"
#include"../Packet/PacketLogging.h"
#include<vector>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

bool gDebugMode = false;
bool gHighVersionMode = false;
bool gHeader1Byte = false;

#ifdef _WIN64
void(*_SendPacket)(void *rcx, OutPacket *op) = NULL;
void(*_SendPacket_EH)(OutPacket *op) = NULL;
void* (*_CClientSocket)(void) = NULL;
void(*_COutPacket)(OutPacket *op, WORD w) = NULL;
void(*_Encode1)(OutPacket *op, BYTE b) = NULL;
void(*_Encode2)(OutPacket *op, WORD w) = NULL;
void(*_Encode4)(OutPacket *op, DWORD dw) = NULL;
void(*_Encode8)(OutPacket *op, ULONG_PTR u) = NULL;
void(*_EncodeStr)(OutPacket *op, void *s) = NULL;
void(*_EncodeBuffer)(OutPacket *op, BYTE *b, DWORD len) = NULL;

void(*_ProcessPacket)(void *rcx, InPacket *ip) = NULL;
BYTE(*_Decode1)(InPacket *ip) = NULL;
WORD(*_Decode2)(InPacket *ip) = NULL;
DWORD(*_Decode4)(InPacket *ip) = NULL;
ULONG_PTR(*_Decode8)(InPacket *ip) = NULL;
char** (*_DecodeStr)(InPacket *ip, char **s) = NULL;
void(*_DecodeBuffer)(InPacket *ip, BYTE *b, DWORD len) = NULL;
#else
void (__thiscall *_SendPacket)(void *ecx, OutPacket *op) = NULL;
void (__thiscall *_SendPacket_2)(void *ecx, OutPacket *op, DWORD v2) = NULL;
void (__thiscall *_COutPacket)(OutPacket *op, WORD w) = NULL;
void (__thiscall *_COutPacket_2)(OutPacket *op, WORD w, DWORD dw) = NULL;
void (__thiscall *_COutPacket_3)(OutPacket *op, WORD w, DWORD dw1, DWORD dw2) = NULL;
void (__thiscall *_Encode1)(OutPacket *op, BYTE b) = NULL;
void (__thiscall *_Encode2)(OutPacket *op, WORD w) = NULL;
void (__thiscall *_Encode4)(OutPacket *op, DWORD dw) = NULL;
void (__thiscall *_EncodeStr)(OutPacket *op, char *s) = NULL;
void (__thiscall *_EncodeBuffer)(OutPacket *op, BYTE *b, DWORD len) = NULL;

void (__thiscall *_ProcessPacket)(void *ecx, InPacket *ip) = NULL;
BYTE (__thiscall *_Decode1)(InPacket *ip) = NULL;
WORD (__thiscall *_Decode2)(InPacket *ip) = NULL;
DWORD (__thiscall *_Decode4)(InPacket *ip) = NULL;
char** (__thiscall *_DecodeStr)(InPacket *ip, char **s) = NULL;
void (__thiscall *_DecodeBuffer)(InPacket *ip, BYTE *b, DWORD len) = NULL;
#endif


#ifdef _WIN64
// SendPacket's Return Address Check and Memory Scan Bypass
#pragma comment(linker,"/SECTION:.text,ERW")
#pragma comment(linker,"/SECTION:.magic,ERW")
#pragma comment(linker, "/MERGE:.magic=.text")
ULONG_PTR uSendPacket_EH_Ret = 0;

#pragma data_seg(".magic")
//#pragma data_seg(push, magic, ".magic")
#pragma pack(push, 1)
BYTE bEnterSendPacket[] = {
	0x48,0x83,0xEC,0x28,						// sub rsp,28
	0x48,0xB8,									// mov rax,EncryptHeader+0x30
	0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
	0x50,										// push rax
	0x48,0xB8,									// mov rax,_SendPacket
	0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
	0x50,										// push rax
	0xC3										// ret
};
#pragma pack(pop)
//#pragma data_seg(pop, magic)

void(*_EnterSendPacket)(void *rcx, OutPacket *op) = (decltype(_EnterSendPacket))(ULONG_PTR)bEnterSendPacket;
void SendPacket_Hook(void *rcx, OutPacket *op) {
	// ヘッダが暗号化される場合は別のところでログを取るため無視する
	if (uSendPacket_EH_Ret != (ULONG_PTR)_ReturnAddress()) {
		bool bBlock = false;
		AddSendPacket(op, (ULONG_PTR)_ReturnAddress(), bBlock);
		// 一部パケットが正常に記録出来ないため送信済みなことを通知する
		packet_id_out++;
		if (!bBlock) {
			return _EnterSendPacket(rcx, op);
		}
		return;
	}
	return _EnterSendPacket(rcx, op);
}

void SendPacket_EH_Hook(OutPacket *op) {
	bool bBlock = false;
	AddSendPacket(op, (ULONG_PTR)_ReturnAddress(), bBlock);
	if (!bBlock) {
		return _SendPacket_EH(op);
	}
	return;
}

#else
// 先にフォーマット情報は送信される
void __fastcall SendPacket_Hook(void *ecx, void *edx, OutPacket *op) {
	if (uEnterSendPacket_ret != (ULONG_PTR)_ReturnAddress()) {
		bool bBlock = false;
		AddSendPacket(op, (DWORD)_ReturnAddress(), bBlock);
		if (bBlock) {
			return;
		}
	}
	return _SendPacket(ecx, op);
}

void __fastcall SendPacket_2_Hook(void *ecx, void *edx, OutPacket *op, DWORD v2) {
	if (uEnterSendPacket_ret != (ULONG_PTR)_ReturnAddress()) {
		bool bBlock = false;
		AddSendPacket(op, (DWORD)_ReturnAddress(), bBlock);
		if (bBlock) {
			return;
		}
	}
	return _SendPacket_2(ecx, op, v2);
}
#endif

#ifdef _WIN64
void COutPacket_Hook(OutPacket *op, WORD w) {
#else
void __fastcall  COutPacket_Hook(OutPacket *op, void *edx, WORD w) {
#endif
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD), 0, (ULONG_PTR)op };
	ClearQueue(op);
	AddQueue(pxi);

#ifndef _WIN64
	if (!_COutPacket && _COutPacket_2) {
		return _COutPacket_2(op, w, 0);
	}
#endif
	return _COutPacket(op, w);
}

#ifndef _WIN64
// JMS131, KMS55
void __fastcall  COutPacket_2_Hook(OutPacket *op, void *edx, WORD w, DWORD dw) {
	// KMS55
	if (gHeader1Byte) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEHEADER, 0, sizeof(BYTE), 0, (ULONG_PTR)op };
		ClearQueue(op);
		AddQueue(pxi);
	}
	// JMS131, KMS65
	else {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD), 0, (ULONG_PTR)op };
		ClearQueue(op);
		AddQueue(pxi);
	}
	return _COutPacket_2(op, w, dw);
}

// GMS v62.1
void __fastcall  COutPacket_3_Hook(OutPacket *op, void *edx, WORD w, DWORD dw1, DWORD dw2) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD), 0, (ULONG_PTR)op };
	ClearQueue(op);
	AddQueue(pxi);
	return _COutPacket_3(op, w, dw1, dw2);
}
#endif

#ifdef _WIN64
void Encode1_Hook(OutPacket *op, BYTE b) {
#else
void __fastcall Encode1_Hook(OutPacket *op, void *edx, BYTE b) {
#endif
	if (op->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE1, op->encoded, sizeof(BYTE), 0, (ULONG_PTR)op };
		AddQueue(pxi);
	}
	return _Encode1(op, b);
}

#ifdef _WIN64
void Encode2_Hook(OutPacket *op, WORD w) {
#else
void __fastcall Encode2_Hook(OutPacket *op, void *edx, WORD w) {
#endif
	if (op->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE2, op->encoded, sizeof(WORD), 0, (ULONG_PTR)op };
		AddQueue(pxi);
	}
	return _Encode2(op, w);

}

#ifdef _WIN64
void Encode4_Hook(OutPacket *op, DWORD dw) {
#else
void __fastcall Encode4_Hook(OutPacket *op, void *edx, DWORD dw) {
#endif
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE4, op->encoded, sizeof(DWORD), 0, (ULONG_PTR)op };
	AddQueue(pxi);
	return _Encode4(op, dw);
}

#ifdef _WIN64
void Encode8_Hook(OutPacket *op, ULONG_PTR u) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE8, op->encoded, sizeof(ULONG_PTR), 0, (ULONG_PTR)op };
	AddQueue(pxi);
	return _Encode8(op, u);
}
#endif

#ifdef _WIN64
void EncodeStr_Hook(OutPacket *op, void *s) {
#else
void __fastcall EncodeStr_Hook(OutPacket *op, void *edx, char *s) {
#endif
#ifdef _WIN64
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODESTR, op->encoded, sizeof(WORD) + *(DWORD *)(*(ULONG_PTR *)s - 0x04), 0, (ULONG_PTR)op };
#else
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODESTR, op->encoded, sizeof(WORD) + strlen(s), 0, (ULONG_PTR)op };
#endif
	AddQueue(pxi);
	return _EncodeStr(op, s);
}

#ifdef _WIN64
void EncodeBuffer_Hook(OutPacket *op, BYTE *b, DWORD len) {
#else
void __fastcall EncodeBuffer_Hook(OutPacket *op, void *edx, BYTE *b, DWORD len) {
#endif
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEBUFFER, op->encoded, len, 0, (ULONG_PTR)op };
	AddQueue(pxi);
	return _EncodeBuffer(op, b, len);
}

// 後からフォーマット情報は送信される
#ifdef _WIN64
void ProcessPacket_Hook(void *pCClientSocket, InPacket *ip) {
#else
void __fastcall ProcessPacket_Hook(void *pCClientSocket, void *edx, InPacket *ip) {
#endif
	if (ip->unk2 == 0x02) {
		CountUpPacketID(packet_id_in);
		if (gDebugMode) {
			DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- ProcessPacket start");
		}
		bool bBlock = false;
		AddRecvPacket(ip, (ULONG_PTR)_ReturnAddress(), bBlock);
		if (!bBlock) {
			_ProcessPacket(pCClientSocket, ip);
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)0, DECODE_END, ip->decoded - 4, 0 };
		AddExtra(pxi);
		if (gDebugMode) {
			DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- ProcessPacket end");
		}
	}
	else {
		_ProcessPacket(pCClientSocket, ip);
	}
}

#ifdef _WIN64
BYTE Decode1_Hook(InPacket *ip) {
#else
BYTE __fastcall Decode1_Hook(InPacket *ip) {
#endif
	if (ip->unk2 == 0x02) {
		if (gHeader1Byte && ip->decoded == 4) {
			if (gDebugMode) {
				DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- Decode1 (Header)");
			}
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEHEADER, ip->decoded - 4, sizeof(BYTE) };
			AddExtra(pxi);
			// update
			pxi.data = &ip->packet[ip->decoded];
			AddExtra(pxi);
		}
		else {
			if (gDebugMode) {
				DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- Decode1");
			}
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE1, ip->decoded - 4, sizeof(BYTE) };
			AddExtra(pxi);
			// update
			pxi.data = &ip->packet[ip->decoded];
			AddExtra(pxi);
		}
	}
	return _Decode1(ip);
}

#ifdef _WIN64
WORD Decode2_Hook(InPacket *ip) {
#else
WORD __fastcall Decode2_Hook(InPacket *ip) {
#endif
	if (ip->unk2 == 0x02) {
		if (!gHeader1Byte && ip->decoded == 4) {
			if (gDebugMode) {
				DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- Decode2 (Header)");
			}
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEHEADER, ip->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
			// update
			pxi.data = &ip->packet[ip->decoded];
			AddExtra(pxi);
		}
		else {
			if (gDebugMode) {
				DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- Decode2");
			}
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE2, ip->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
			// update
			pxi.data = &ip->packet[ip->decoded];
			AddExtra(pxi);
		}
	}
	return _Decode2(ip);
}

#ifdef _WIN64
DWORD Decode4_Hook(InPacket *ip) {
#else
DWORD __fastcall Decode4_Hook(InPacket *ip) {
#endif
	if (ip->unk2 == 0x02) {
		if (gDebugMode) {
			DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- Decode4");
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE4, ip->decoded - 4, sizeof(DWORD) };
		AddExtra(pxi);
		// update
		pxi.data = &ip->packet[ip->decoded];
		AddExtra(pxi);
	}
	return _Decode4(ip);
}

#ifdef _WIN64
ULONG_PTR Decode8_Hook(InPacket *ip) {
	if (ip->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE8, ip->decoded - 4, sizeof(ULONG_PTR) };
		AddExtra(pxi);
		// update
		pxi.data = &ip->packet[ip->decoded];
		AddExtra(pxi);
	}
	return _Decode8(ip);
}
#endif

#ifdef _WIN64
char** DecodeStr_Hook(InPacket *ip, char **s) {
#else
char** __fastcall DecodeStr_Hook(InPacket *ip, void *edx, char **s) {
#endif
	if (ip->unk2 == 0x02) {
		if (gDebugMode) {
			DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- DecodeStr");
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODESTR, ip->decoded - 4, sizeof(WORD) + *(WORD *)&ip->packet[ip->decoded] };
		AddExtra(pxi);
		// update
		pxi.data = &ip->packet[ip->decoded];
		AddExtra(pxi);
	}
	return _DecodeStr(ip, s);
}

#ifdef _WIN64
void DecodeBuffer_Hook(InPacket *ip, BYTE *b, DWORD len) {
#else
void __fastcall DecodeBuffer_Hook(InPacket *ip, void *edx, BYTE *b, DWORD len) {
#endif
	if (ip->unk2 == 0x02) {
		if (gDebugMode) {
			DEBUG(L"in @" + WORDtoString(*(WORD *)&ip->packet[4]) + L" --- DecodeBuffer");
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEBUFFER, ip->decoded - 4, len };
		AddExtra(pxi);
		// update
		pxi.data = &ip->packet[ip->decoded];
		AddExtra(pxi);
	}
	return _DecodeBuffer(ip, b, len);
}


#ifdef _WIN64
#else
// Packet Injector
ULONG_PTR uSendPacket = 0;
ULONG_PTR uSendPacket_2 = 0;
ULONG_PTR uEnterSendPacket = 0;
ULONG_PTR uEnterSendPacket_ret = 0;
ULONG_PTR uCClientSocket = 0;
void(*_EnterSendPacket)(OutPacket *op) = NULL;
void EnterSendPacket_Hook(OutPacket *op) {
	bool bBlock = false;
	AddSendPacket(op, (ULONG_PTR)_ReturnAddress(), bBlock);
	if (bBlock) {
		return;
	}
	return _EnterSendPacket(op);
}

ULONG_PTR GetCClientSocket() {
	if (!uCClientSocket) {
		return 0;
	}

	return *(ULONG_PTR *)uCClientSocket;
}

// FF 74 24 04 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C3
// 8B 44 24 04 8B 0D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? C3, v188
bool ScannerEnterSendPacket(ULONG_PTR uAddress) {
	if (!uSendPacket) {
		return false;
	}

	ULONG_PTR uCall = uAddress + 0x0A;
	ULONG_PTR uFunction = uCall + 0x05 + *(signed long int *)(uCall + 0x01);
	if (uFunction != uSendPacket) {
		return false;
	}

	uEnterSendPacket = uAddress;
	uEnterSendPacket_ret = uEnterSendPacket + 0x0F;
	uCClientSocket = *(ULONG_PTR *)(uAddress + 0x06);
	return true;
}

bool ScannerEnterSendPacket_188(ULONG_PTR uAddress) {
	if (!uSendPacket) {
		return false;
	}

	ULONG_PTR uCall = uAddress + 0x0B;
	ULONG_PTR uFunction = uCall + 0x05 + *(signed long int *)(uCall + 0x01);
	if (uFunction != uSendPacket) {
		return false;
	}

	uEnterSendPacket = uAddress;
	uEnterSendPacket_ret = uEnterSendPacket + 0x10;
	uCClientSocket = *(ULONG_PTR *)(uAddress + 0x06);
	return true;
}
#endif

void SetGlobalSettings(HookSettings &hs) {
	gDebugMode = hs.debug_mode;
	gHighVersionMode = hs.high_version_mode;
}

bool PacketHook_Thread(HookSettings &hs) {
	SetGlobalSettings(hs);
	Rosemary r;
	ULONG_PTR uProcessPacket = 0;
#ifdef _WIN64
	ULONG_PTR uSendPacket = 0;
	ULONG_PTR uCClientSocket = 0;
#endif

	AOBHookWithResult(SendPacket);
#ifndef _WIN64
	if (!_SendPacket) {
		AOBHookWithResult(SendPacket_2);
	}
#endif

#ifdef _WIN64
	size_t iWorkingAob = -1;
	ULONG_PTR uSendPacket_EH = r.Scan(AOB_SendPacket_EH, _countof(AOB_SendPacket_EH), iWorkingAob);
	SCANRES(uSendPacket_EH);

	if (uSendPacket && uSendPacket_EH) {
		uSendPacket_EH_Ret = uSendPacket_EH + Offset_SendPacket_EH_Ret[iWorkingAob];
		*(ULONG_PTR *)&bEnterSendPacket[0x06] = uSendPacket_EH_Ret;
		*(ULONG_PTR *)&bEnterSendPacket[0x11] = (ULONG_PTR)*_SendPacket;
		bEnterSendPacket[3] = ((BYTE *)uSendPacket_EH_Ret)[3]; // add rsp,XX -> sub rsp,XX

		uCClientSocket = uSendPacket_EH + Offset_SendPacket_EH_CClientSocket[iWorkingAob];
		uCClientSocket += *(signed long int *)(uCClientSocket + 0x01) + 0x05;
		_CClientSocket = (decltype(_CClientSocket))uCClientSocket;
		DEBUG(L"uCClientSocket = " + QWORDtoString(uCClientSocket));
		SHookFunction(SendPacket_EH, uSendPacket_EH);
	}
#else
	if (uSendPacket) {
		uEnterSendPacket = r.Scan(AOB_EnterSendPacket[0], ScannerEnterSendPacket);
		if (!uEnterSendPacket) {
			uEnterSendPacket = r.Scan(AOB_EnterSendPacket[1], ScannerEnterSendPacket_188);
		}
		if (uEnterSendPacket) {
			SHookFunction(EnterSendPacket, uEnterSendPacket);
		}
		SCANRES(uEnterSendPacket);
		SCANRES(uEnterSendPacket_ret);
		SCANRES(uCClientSocket);
	}
#endif

#ifdef _WIN64
	if (uSendPacket && uSendPacket_EH) {
#else
	if (uSendPacket || uSendPacket_2) {
#endif
		AOBHook(COutPacket);
#ifndef _WIN64
		// old version
		if (!_COutPacket) {
			AOBHook(COutPacket_2);
			if (!_COutPacket_2) {
				AOBHook(COutPacket_3);
			}
		}
#endif
		AOBHook(Encode1);
		AOBHook(Encode2);
		AOBHook(Encode4);
#ifdef _WIN64
		AOBHook(Encode8);
#endif
		AOBHook(EncodeStr);
		AOBHook(EncodeBuffer);
	}

	AOBHookWithResult(ProcessPacket);
#ifndef _WIN64
	// old version
	if (!uProcessPacket) {
		uProcessPacket = r.Scan(AOB_ProcessPacket_KMS55[0]);
		SHookFunction(ProcessPacket, uProcessPacket);
		gHeader1Byte = true;
		DEBUG(L"header 1 byte mode");
	}
#endif
	if (uProcessPacket) {
		AOBHook(Decode1);
		AOBHook(Decode2);
		AOBHook(Decode4);
#ifdef _WIN64
		AOBHook(Decode8);
#endif
		AOBHook(DecodeStr);
		AOBHook(DecodeBuffer);
	}

	return true;
}

bool PacketHook_Conf(HookSettings &hs) {
	SetGlobalSettings(hs);
	Rosemary r;
	ULONG_PTR uProcessPacket = 0;
#ifdef _WIN64
	ULONG_PTR uSendPacket = 0;
	ULONG_PTR uCClientSocket = 0;
#endif

	if (hs.addr_SendPacket) {
		SHookFunction(SendPacket, hs.addr_SendPacket);
		uSendPacket = hs.addr_SendPacket;
	}

#ifndef _WIN64
	// old version
	if (!_SendPacket) {
		if (hs.addr_SendPacket2) {
			SHookFunction(SendPacket_2, hs.addr_SendPacket2);
		}
	}
#endif

#ifdef _WIN64
	size_t iWorkingAob = -1;
	ULONG_PTR uSendPacket_EH = r.Scan(AOB_SendPacket_EH, _countof(AOB_SendPacket_EH), iWorkingAob);
	SCANRES(uSendPacket_EH);

	if (uSendPacket && uSendPacket_EH) {
		uSendPacket_EH_Ret = uSendPacket_EH + Offset_SendPacket_EH_Ret[iWorkingAob];
		*(ULONG_PTR *)&bEnterSendPacket[0x06] = uSendPacket_EH_Ret;
		*(ULONG_PTR *)&bEnterSendPacket[0x11] = (ULONG_PTR)*_SendPacket;
		bEnterSendPacket[3] = ((BYTE *)uSendPacket_EH_Ret)[3]; // add rsp,XX -> sub rsp,XX

		uCClientSocket = uSendPacket_EH + Offset_SendPacket_EH_CClientSocket[iWorkingAob];
		uCClientSocket += *(signed long int *)(uCClientSocket + 0x01) + 0x05;
		_CClientSocket = (decltype(_CClientSocket))uCClientSocket;
		DEBUG(L"uCClientSocket = " + QWORDtoString(uCClientSocket));
		SHookFunction(SendPacket_EH, uSendPacket_EH);
	}
#else
	if (_SendPacket) {
		uEnterSendPacket = r.Scan(AOB_EnterSendPacket[0], ScannerEnterSendPacket);
		if (!uEnterSendPacket) {
			uEnterSendPacket = r.Scan(AOB_EnterSendPacket[1], ScannerEnterSendPacket_188);
		}
		if (uEnterSendPacket) {
			SHookFunction(EnterSendPacket, uEnterSendPacket);
		}
		SCANRES(uEnterSendPacket);
		SCANRES(uEnterSendPacket_ret);
		SCANRES(uCClientSocket);
	}
#endif

#ifdef _WIN64
	if (_SendPacket && uSendPacket_EH) {
#else
	if (_SendPacket || _SendPacket_2) {
#endif
		if (hs.addr_COutPacket) {
			SHookFunction(COutPacket, hs.addr_COutPacket);
		}
#ifndef _WIN64
		// old version
		if (!_COutPacket) {
			if (hs.addr_COutPacket2) {
				SHookFunction(COutPacket_2, hs.addr_COutPacket2);
			}
		}
		if (!_COutPacket && !_COutPacket_2) {
			if (hs.addr_COutPacket3) {
				SHookFunction(COutPacket_3, hs.addr_COutPacket3);
			}
		}
#endif
		if (hs.addr_Encode1) {
			SHookFunction(Encode1, hs.addr_Encode1);
		}
		if (hs.addr_Encode2) {
			SHookFunction(Encode2, hs.addr_Encode2);
		}
		if (hs.addr_Encode4) {
			SHookFunction(Encode4, hs.addr_Encode4);
		}
#ifdef _WIN64
		if (hs.addr_Encode8) {
			SHookFunction(Encode8, hs.addr_Encode8);
		}
#endif
		if (hs.addr_EncodeStr) {
			SHookFunction(EncodeStr, hs.addr_EncodeStr);
		}
		if (hs.addr_EncodeBuffer) {
			SHookFunction(EncodeBuffer, hs.addr_EncodeBuffer);
		}
	}

	if (hs.addr_ProcessPacket) {
		SHookFunction(ProcessPacket, hs.addr_ProcessPacket);
	}
	if (_ProcessPacket) {
		if (hs.addr_Decode1) {
			SHookFunction(Decode1, hs.addr_Decode1);
		}
		if (hs.addr_Decode2) {
			SHookFunction(Decode2, hs.addr_Decode2);
		}
		if (hs.addr_Decode4) {
			SHookFunction(Decode4, hs.addr_Decode4);
		}
#ifdef _WIN64
		if (hs.addr_Decode8) {
			SHookFunction(Decode8, hs.addr_Decode8);
		}
#endif
		if (hs.addr_DecodeStr) {
			SHookFunction(DecodeStr, hs.addr_DecodeStr);
		}
		if (hs.addr_DecodeBuffer) {
			SHookFunction(DecodeBuffer, hs.addr_DecodeBuffer);
		}
	}

	return true;
}
