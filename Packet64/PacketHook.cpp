#include"PacketHook.h"
#include"../Share/Hook/SimpleHook.h"
#include"../Share/Simple/Simple.h"
#include<vector>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)
#include"../RirePE/RirePE.h"

PipeClient *pc = NULL;
CRITICAL_SECTION cs;

bool StartPipeClient() {
	pc = new PipeClient(L"PacketEditor");
	return pc->Run();
}

bool RestartPipeClient() {
	if (pc) {
		delete pc;
	}
	return StartPipeClient();
}

// ShiftJIS to UTF16
bool ShiftJIStoUTF8(std::string sjis, std::wstring &utf16) {
	// UTF16へ変換する際の必要なバイト数を取得
	int len = MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, 0, 0);
	if (!len) {
		return false;
	}

	// UTF16へ変換
	std::vector<BYTE> b((len + 1) * sizeof(WORD));
	if (!MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, (WCHAR *)&b[0], len)) {
		return false;
	}

	utf16 = std::wstring((WCHAR *)&b[0]);
	return true;
}

// バイト配列からShiftJIS文字列を取得
bool BYTEtoShiftJIS(BYTE *text, int len, std::string &sjis) {
	std::vector<BYTE> b(len + 1);
	for (size_t i = 0; i < len; i++) {
		b[i] = text[i];
	}
	sjis = std::string((char *)&b[0]);
	return true;
}

void(*_SendPacket)(void *rcx, OutPacket *p);
void(*_SendPacket_EH)(OutPacket *p);
void* (*_CClientSocket)(void);
void(*_COutPacket)(OutPacket *p, WORD w);
void(*_Encode1)(OutPacket *p, BYTE b);
void(*_Encode2)(OutPacket *p, WORD w);
void(*_Encode4)(OutPacket *p, DWORD dw);
void(*_Encode8)(OutPacket *p, ULONG_PTR u);
void(*_EncodeStr)(OutPacket *p, void *s);
void(*_EncodeBuffer)(OutPacket *p, BYTE *b, DWORD len);

void(*_ProcessPacket)(void *rcx, InPacket *p);
BYTE(*_Decode1)(InPacket *p);
WORD(*_Decode2)(InPacket *p);
DWORD(*_Decode4)(InPacket *p);
ULONG_PTR(*_Decode8)(InPacket *p);
char** (*_DecodeStr)(InPacket *p, char **s);
void(*_DecodeBuffer)(InPacket *p, BYTE *b, DWORD len);

DWORD packet_id_out = 0;
DWORD packet_id_in = 0;

typedef struct {
	ULONG_PTR id; // パケット識別子
	ULONG_PTR addr; // リターンアドレス
	MessageHeader fmt; // フォーマットの種類
	ULONG_PTR pos; // 場所
	ULONG_PTR len; // データの長さ (DecodeBuffer以外不要)

} PacketExtraInformation;


void AddExtra(PacketExtraInformation &pxi) {
	EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	pem = new PacketEditorMessage;

	if (!pem) {

		LeaveCriticalSection(&cs);
		return;
	}

	pem->header = pxi.fmt;
	pem->id = pxi.id;
	pem->addr = pxi.addr;
	pem->Extra.pos = pxi.pos;
	pem->Extra.size = pxi.len;

	if (!pc->Send(b, sizeof(PacketEditorMessage))) {
		RestartPipeClient();
	}

	delete pem;

	LeaveCriticalSection(&cs);
}

void AddSendPacket(OutPacket *p, ULONG_PTR addr, bool &bBlock) {
	EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->encoded];

	if (!b) {
		LeaveCriticalSection(&cs);
		return;
	}

	pem->header = SENDPACKET;
	pem->id = packet_id_out;
	pem->addr = addr;
	pem->Binary.length = p->encoded;
	memcpy_s(pem->Binary.packet, p->encoded, p->packet, p->encoded);
	if (p->header) {
		*(WORD *)&pem->Binary.packet[0] = p->header;
	}

	// BlackCipher HearBeat
	if (*(WORD *)&pem->Binary.packet[0] == 0x0066) {
		DEBUG(DatatoString(pem->Binary.packet, p->encoded, true));
	}

	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->encoded)) {
		RestartPipeClient();
	}
	else {
		std::wstring wResponse;
		pc->Recv(wResponse);
		if (wResponse.compare(L"Block") == 0) {
			bBlock = true;
		}
		else {
			bBlock = false;
		}
	}

	delete[] b;
	LeaveCriticalSection(&cs);
}

void AddRecvPacket(InPacket *p, ULONG_PTR addr, bool &bBlock) {
	EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->size];

	if (!b) {
		LeaveCriticalSection(&cs);
		return;
	}

	pem->header = RECVPACKET;
	pem->id = packet_id_in;
	pem->addr = addr;
	pem->Binary.length = p->size;
	memcpy_s(pem->Binary.packet, p->size, &p->packet[4], p->size);

	// BlackCipher HearBeat
	if (*(WORD *)&pem->Binary.packet[0] == 0x0017) {
		DEBUG(DatatoString(pem->Binary.packet, p->size, true));
	}

	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->size)) {
		RestartPipeClient();
	}
	else {
		std::wstring wResponse;
		pc->Recv(wResponse);
		if (wResponse.compare(L"Block") == 0) {
			bBlock = true;
		}
		else {
			bBlock = false;
		}
	}

	delete[] b;
	LeaveCriticalSection(&cs);
}


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

void(*_EnterSendPacket)(void *rcx, OutPacket *p) = (decltype(_EnterSendPacket))(ULONG_PTR)bEnterSendPacket;
void SendPacket_Hook(void *rcx, OutPacket *p) {
	// ヘッダが暗号化される場合は別のところでログを取るため無視する
	if (uSendPacket_EH_Ret != (ULONG_PTR)_ReturnAddress()) {
		bool bBlock = false;
		AddSendPacket(p, (ULONG_PTR)_ReturnAddress(), bBlock);
		// 一部パケットが正常に記録出来ないため送信済みなことを通知する
		packet_id_out++;
		if (!bBlock) {
			return _EnterSendPacket(rcx, p);
		}
		return;
	}
	return _EnterSendPacket(rcx, p);
}

void SendPacket_EH_Hook(OutPacket *p) {
	bool bBlock = false;
	AddSendPacket(p, (ULONG_PTR)_ReturnAddress(), bBlock);
	if (!bBlock) {
		return _SendPacket_EH(p);
	}
	return;
}

void COutPacket_Hook(OutPacket *p, WORD w) {
	packet_id_out++;
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD) };
	AddExtra(pxi);
	return _COutPacket(p, w);
}

void Encode1_Hook(OutPacket *p, BYTE b) {
	if (p->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE1, p->encoded, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Encode1(p, b);
}
void Encode2_Hook(OutPacket *p, WORD w) {
	if (p->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE2, p->encoded, sizeof(WORD) };
		AddExtra(pxi);
	}
	return _Encode2(p, w);

}
void Encode4_Hook(OutPacket *p, DWORD dw) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE4, p->encoded, sizeof(DWORD) };
	AddExtra(pxi);
	return _Encode4(p, dw);
}
void Encode8_Hook(OutPacket *p, ULONG_PTR u) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE8, p->encoded, sizeof(ULONG_PTR) };
	AddExtra(pxi);
	return _Encode8(p, u);
}

void EncodeStr_Hook(OutPacket *p, void *s) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODESTR, p->encoded, sizeof(WORD) + *(DWORD *)(*(ULONG_PTR *)s - 0x04) };
	AddExtra(pxi);
	return _EncodeStr(p, s);
}
void EncodeBuffer_Hook(OutPacket *p, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEBUFFER, p->encoded, len };
	AddExtra(pxi);
	return _EncodeBuffer(p, b, len);
}

// 後からフォーマット情報は送信される
void ProcessPacket_Hook(void *rcx, InPacket *p) {
	if (p->unk2 == 0x02) {
		packet_id_in++;
		bool bBlock = false;
		AddRecvPacket(p, (ULONG_PTR)_ReturnAddress(), bBlock);
		if (!bBlock) {
			_ProcessPacket(rcx, p);
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)0, DECODEEND, 0, 0 };
		AddExtra(pxi);
	}
	else {
		return _ProcessPacket(rcx, p);
	}
}

BYTE Decode1_Hook(InPacket *p) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE1, p->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Decode1(p);
}

WORD Decode2_Hook(InPacket *p) {
	if (p->unk2 == 0x02) {
		if (p->decoded == 4) {
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEHEADER, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
		}
		else {
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE2, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
		}
	}
	return _Decode2(p);
}

DWORD Decode4_Hook(InPacket *p) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE4, p->decoded - 4, sizeof(DWORD) };
		AddExtra(pxi);
	}
	return _Decode4(p);
}

ULONG_PTR Decode8_Hook(InPacket *p) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE8, p->decoded - 4, sizeof(ULONG_PTR) };
		AddExtra(pxi);
	}
	return _Decode8(p);
}

char** DecodeStr_Hook(InPacket *p, char **s) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODESTR, p->decoded - 4, sizeof(WORD) + *(WORD *)&p->packet[p->decoded] };
		AddExtra(pxi);
	}
	return _DecodeStr(p, s);
}

void DecodeBuffer_Hook(InPacket *p, BYTE *b, DWORD len) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEBUFFER, p->decoded - 4, len };
		AddExtra(pxi);
	}
	return _DecodeBuffer(p, b, len);
}


bool PacketHook() {
	InitializeCriticalSection(&cs);
	Rosemary r;

	// v403.1
	ULONG_PTR uSendPacket = r.Scan(L"48 89 54 24 10 48 89 4C 24 08 56 57 48 81 EC ?? ?? ?? ?? 48 C7 84 24 28 02 00 00 FE FF FF FF 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 B0 02 00 00 E9");
	// TWMS v246
	if (!uSendPacket) {
		uSendPacket = r.Scan(L"48 89 54 24 10 48 89 4C 24 08 56 57 48 81 EC ?? ?? ?? ?? 48 C7 84 24 40 01 00 00 FE FF FF FF 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E9");
	}
	ULONG_PTR uSendPacket_EH = r.Scan(L"48 89 4C 24 08 48 83 EC 28 E8 ?? ?? ?? ?? 48 8B 4C 24 30 8B 51 1C 48 8B C8 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 54 24 30 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3");
	DEBUG(L"uSendPacket = " + QWORDtoString(uSendPacket));
	DEBUG(L"uSendPacket_EH = " + QWORDtoString(uSendPacket_EH));
	ULONG_PTR uProcessPacket = r.Scan(L"48 89 54 24 10 48 89 4C 24 08 56 57 48 81 EC ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 75 05 E9 ?? ?? ?? ?? E9");
	DEBUG(L"uProcessPacket = " + QWORDtoString(uProcessPacket));

	if (uSendPacket && uSendPacket_EH) {
		uSendPacket_EH_Ret = uSendPacket_EH + 0x30;
		DEBUG(L"uSendPacket_EH_Ret = " + QWORDtoString(uSendPacket_EH_Ret));
		ULONG_PTR uCClientSocket = uSendPacket_EH + 0x1E;
		uCClientSocket += *(signed long int *)(uCClientSocket + 0x01) + 0x05;
		_CClientSocket = (decltype(_CClientSocket))uCClientSocket;
		DEBUG(L"uCClientSocket = " + QWORDtoString(uCClientSocket));

		SHookFunction(SendPacket, uSendPacket);
		*(ULONG_PTR *)&bEnterSendPacket[0x06] = uSendPacket_EH_Ret;
		*(ULONG_PTR *)&bEnterSendPacket[0x11] = (ULONG_PTR)*_SendPacket;
		SHookFunction(SendPacket_EH, uSendPacket_EH); // + 0x35 = tramp test

		ULONG_PTR uCOutPacket = r.Scan(L"48 89 4C 24 ?? 57 48 83 EC ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 89 5C 24 ?? 8B DA 48 8B F9 48 83 C1 ?? 48 C7 01 00 00 00 00");
		// TWMS v246
		if (!uCOutPacket) {
			uCOutPacket = r.Scan(L"48 89 4C 24 ?? 57 48 83 EC ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 89 5C 24 ?? 8B ?? 48 8B D9 48 C7 41 08 00 00 00 00 BA 04 01 00 00 48 8D 0D ?? ?? ?? ?? E8");
		}
		DEBUG(L"uCOutPacket = " + QWORDtoString(uCOutPacket));
		if (uCOutPacket) {
			SHookFunction(COutPacket, uCOutPacket);
			ULONG_PTR uEncode1 = r.Scan(L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 0F B6 DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 0F B6 CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3");
			if (uEncode1) {
				SHookFunction(Encode1, uEncode1);
			}

			ULONG_PTR uEncode2 = r.Scan(L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 0F B7 DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 0F B7 CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3");
			if (uEncode2) {
				SHookFunction(Encode2, uEncode2);
			}

			ULONG_PTR uEncode4 = r.Scan(L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 8B DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 8B CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3");
			if (uEncode4) {
				SHookFunction(Encode4, uEncode4);
			}

			ULONG_PTR uEncode8 = r.Scan(L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 48 8B CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3");
			if (uEncode8) {
				SHookFunction(Encode8, uEncode8);
			}

			ULONG_PTR uEncodeStr = r.Scan(L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B DA 48 8B CA E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 48 8B CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3");
			if (uEncodeStr) {
				SHookFunction(EncodeStr, uEncodeStr);
			}

			ULONG_PTR uEncodeBuffer = r.Scan(L"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA 41 8B F0 41 8B D0 48 8B F9 E8 ?? ?? ?? ?? 8B 47 10 48 03 47 08 85 F6 7E 18 8B D6 0F 1F 00 0F B6 0B 48 8D 5B 01 88 08 48 8D 40 01 48 83 EA 01 75 ED 01 77 10 48 8B 74 24 38 48 8B 5C 24 30 48 83 C4 20 5F C3 CC CC CC CC CC CC CC CC CC CC 41 8B C1 48 03 41 08 45 85 C0 7E 17 45 8B C0 90 0F B6 0A 48 8D 52 01 88 08 48 8D 40 01 49 83 E8 01 75 ED C3");
			if (uEncodeBuffer) {
				SHookFunction(EncodeBuffer, uEncodeBuffer);
			}

			DEBUG(L"uEncode1 = " + QWORDtoString(uEncode1));
			DEBUG(L"uEncode2 = " + QWORDtoString(uEncode2));
			DEBUG(L"uEncode4 = " + QWORDtoString(uEncode4));
			DEBUG(L"uEncode8 = " + QWORDtoString(uEncode8));
			DEBUG(L"uEncodeStr = " + QWORDtoString(uEncodeStr));
			DEBUG(L"uEncodeBuffer = " + QWORDtoString(uEncodeBuffer));
		}
	}

	if (uProcessPacket) {
		SHookFunction(ProcessPacket, uProcessPacket);
		ULONG_PTR uDecode1 = r.Scan(L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 0F B6 44 24 58 48 83 C4 40 5B C3");
		if (uDecode1) {
			SHookFunction(Decode1, uDecode1);
		}

		ULONG_PTR uDecode2 = r.Scan(L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 0F B7 44 24 58 48 83 C4 40 5B C3");
		if (uDecode2) {
			SHookFunction(Decode2, uDecode2);
		}

		ULONG_PTR uDecode4 = r.Scan(L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 8B 44 24 58 48 83 C4 40 5B C3");
		if (uDecode4) {
			SHookFunction(Decode4, uDecode4);
		}

		ULONG_PTR uDecode8 = r.Scan(L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 48 8B 44 24 58 48 83 C4 40 5B C3");
		if (uDecode8) {
			SHookFunction(Decode8, uDecode8);
		}

		ULONG_PTR uDecodeStr = r.Scan(L"48 89 54 24 10 48 89 4C 24 08 57 48 83 EC 50 48 C7 44 24 28 FE FF FF FF 48 89 5C 24 70 48 8B FA 48 8B D9 33 C0 89 44 24 20 48 89 02 C7 44 24 20 01 00 00 00 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8B CF E8 ?? ?? ?? ?? 01 43 1C 48 8B C7 48 8B 5C 24 70 48 83 C4 50 5F C3");
		if (uDecodeStr) {
			SHookFunction(DecodeStr, uDecodeStr);
		}

		ULONG_PTR uDecodeBuffer = r.Scan(L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 41 8B C0 4C 8B D2 48 8B D9 44 8B 41 1C 44 8B 49 10 45 2B C8 4C 03 41 08 8B D0 49 8B CA E8 ?? ?? ?? ?? 01 43 1C 48 83 C4 40 5B C3");
		if (uDecodeBuffer) {
			SHookFunction(DecodeBuffer, uDecodeBuffer);
		}

		DEBUG(L"uDecode1 = " + QWORDtoString(uDecode1));
		DEBUG(L"uDecode2 = " + QWORDtoString(uDecode2));
		DEBUG(L"uDecode4 = " + QWORDtoString(uDecode4));
		DEBUG(L"uDecode8 = " + QWORDtoString(uDecode8));
		DEBUG(L"uDecodeStr = " + QWORDtoString(uDecodeStr));
		DEBUG(L"uDecodeBuffer = " + QWORDtoString(uDecodeBuffer));
	}

	RunPacketSender();
	StartPipeClient();
	return true;
}
