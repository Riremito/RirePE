#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#include"../RirePE/RirePE.h"
#include"../Packet/PacketHook.h"
#include"../Packet/AobList.h"
#include<vector>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

PipeClient *pc = NULL;
CRITICAL_SECTION cs;

bool StartPipeClient() {
	pc = new PipeClient(PE_LOGGER_PIPE_NAME);
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
	int len = MultiByteToWideChar(932, 0, sjis.c_str(), -1, 0, 0);
	if (!len) {
		return false;
	}

	// UTF16へ変換
	std::vector<BYTE> b((len + 1) * sizeof(WORD));
	if (!MultiByteToWideChar(932, 0, sjis.c_str(), -1, (WCHAR *)&b[0], len)) {
		return false;
	}

	utf16 = std::wstring((WCHAR *)&b[0]);
	return true;
}

// バイト配列からShiftJIS文字列を取得
bool BYTEtoShiftJIS(BYTE *text, size_t len, std::string &sjis) {
	std::vector<BYTE> b(len + 1);
	for (size_t i = 0; i < len; i++) {
		b[i] = text[i];
	}
	sjis = std::string((char *)&b[0]);
	return true;
}

#ifdef _WIN64
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
#else
void(__thiscall *_SendPacket)(void *ecx, OutPacket *p);
void(__thiscall *_COutPacket)(OutPacket *p, WORD w);
void(__thiscall *_Encode1)(OutPacket *p, BYTE b);
void(__thiscall *_Encode2)(OutPacket *p, WORD w);
void(__thiscall *_Encode4)(OutPacket *p, DWORD dw);
void(__thiscall *_EncodeStr)(OutPacket *p, char *s);
void(__thiscall *_EncodeBuffer)(OutPacket *p, BYTE *b, DWORD len);

void(__thiscall *_ProcessPacket)(void *ecx, InPacket *p);
BYTE(__thiscall *_Decode1)(InPacket *p);
WORD(__thiscall *_Decode2)(InPacket *p);
DWORD(__thiscall *_Decode4)(InPacket *p);
char** (__thiscall *_DecodeStr)(InPacket *p, char **s);
void(__thiscall *_DecodeBuffer)(InPacket *p, BYTE *b, DWORD len);
#endif

DWORD packet_id_out = 0; // 偶数
DWORD packet_id_in = 1; // 奇数

typedef struct {
	DWORD id; // パケット識別子
	ULONGLONG addr; // リターンアドレス
	MessageHeader fmt; // フォーマットの種類
	DWORD pos; // 場所
	DWORD size; // データの長さ
	BYTE *data;
} PacketExtraInformation;

DWORD CountUpPacketID(DWORD &id) {
	id += 2;
	return id;
}


void AddExtra(PacketExtraInformation &pxi) {
	EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + pxi.size];

	if (!pem) {
		LeaveCriticalSection(&cs);
		return;
	}

	pem->header = pxi.fmt;
	pem->id = pxi.id;
	pem->addr = pxi.addr;
	pem->Extra.pos = pxi.pos;
	pem->Extra.size = pxi.size;

	if (!pxi.data) {
		pem->Extra.update = FORMAT_NO_UPDATE;
	}
	else {
		pem->Extra.update = FORMAT_UPDATE;
		memcpy_s(&pem->Extra.data[0], pxi.size, &pxi.data[0], pxi.size);
	}

	if (!pc->Send(b, sizeof(PacketEditorMessage) + pxi.size)) {
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
	CountUpPacketID(packet_id_out); // SendPacketとEnterSendPacketがあるのでここでカウントアップ

#ifdef _WIN64
	if (p->header) {
		*(WORD *)&pem->Binary.packet[0] = p->header;
	}

	// BlackCipher HearBeat
	if (*(WORD *)&pem->Binary.packet[0] == 0x0066) {
		DEBUG(DatatoString(pem->Binary.packet, p->encoded, true));
	}
#endif

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
#ifdef _WIN64
	b = new BYTE[sizeof(PacketEditorMessage) + p->size];
#else
	b = new BYTE[sizeof(PacketEditorMessage) + p->length2];
#endif
	if (!b) {
		LeaveCriticalSection(&cs);
		return;
	}

	pem->header = RECVPACKET;
	pem->id = packet_id_in;
	pem->addr = addr;
#ifdef _WIN64
	pem->Binary.length = p->size;
	memcpy_s(pem->Binary.packet, p->size, &p->packet[4], p->size);
#else
	pem->Binary.length = p->length2;
	memcpy_s(pem->Binary.packet, p->length2, &p->packet[4], p->length2);
#endif
#ifdef _WIN64
	// BlackCipher HearBeat
	if (*(WORD *)&pem->Binary.packet[0] == 0x0017) {
		DEBUG(DatatoString(pem->Binary.packet, p->size, true));
	}
#endif

#ifdef _WIN64
	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->size)) {
#else
	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->length2)) {
#endif
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

#else
// 先にフォーマット情報は送信される
void __fastcall SendPacket_Hook(void *ecx, void *edx, OutPacket *p) {
	if (uEnterSendPacket_ret != (ULONG_PTR)_ReturnAddress()) {
		bool bBlock = false;
		AddSendPacket(p, (DWORD)_ReturnAddress(), bBlock);
		if (bBlock) {
			return;
		}
	}
	return _SendPacket(ecx, p);
}
#endif

bool IGNORE_PACKET = false; // 無視
void(__thiscall *_WriteTempPacket)(void *ecx) = 0;
void __fastcall WriteTempPacket_Hook(void *ecx, void *edx) {
	IGNORE_PACKET = true;
	_WriteTempPacket(ecx);
	IGNORE_PACKET = false;
}

#ifdef _WIN64
void COutPacket_Hook(OutPacket *p, WORD w) {
#else
void __fastcall  COutPacket_Hook(OutPacket *p, void *edx, WORD w) {
#endif
	if (!IGNORE_PACKET) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD) };
		AddExtra(pxi);
	}
	return _COutPacket(p, w);
}

#ifdef _WIN64
void Encode1_Hook(OutPacket *p, BYTE b) {
#else
void __fastcall Encode1_Hook(OutPacket *p, void *edx, BYTE b) {
#endif
	if (p->encoded) {
		if (!IGNORE_PACKET) {
			PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE1, p->encoded, sizeof(BYTE) };
			AddExtra(pxi);
		}
	}
	return _Encode1(p, b);
}

#ifdef _WIN64
void Encode2_Hook(OutPacket *p, WORD w) {
#else
void __fastcall Encode2_Hook(OutPacket *p, void *edx, WORD w) {
#endif
	if (p->encoded) {
		if (!IGNORE_PACKET) {
			PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE2, p->encoded, sizeof(WORD) };
			AddExtra(pxi);
		}
	}
	return _Encode2(p, w);

}

#ifdef _WIN64
void Encode4_Hook(OutPacket *p, DWORD dw) {
#else
void __fastcall Encode4_Hook(OutPacket *p, void *edx, DWORD dw) {
#endif
	if (!IGNORE_PACKET) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE4, p->encoded, sizeof(DWORD) };
		AddExtra(pxi);
	}
	return _Encode4(p, dw);
}

#ifdef _WIN64
void Encode8_Hook(OutPacket *p, ULONG_PTR u) {
	PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODE8, p->encoded, sizeof(ULONG_PTR) };
	AddExtra(pxi);
	return _Encode8(p, u);
}
#endif

#ifdef _WIN64
void EncodeStr_Hook(OutPacket *p, void *s) {
#else
void __fastcall EncodeStr_Hook(OutPacket *p, void *edx, char *s) {
#endif
	if (!IGNORE_PACKET) {
#ifdef _WIN64
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODESTR, p->encoded, sizeof(WORD) + *(DWORD *)(*(ULONG_PTR *)s - 0x04) };
#else
		PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODESTR, p->encoded, sizeof(WORD) + strlen(s) };
#endif
		AddExtra(pxi);
	}
	return _EncodeStr(p, s);
}

#ifdef _WIN64
void EncodeBuffer_Hook(OutPacket *p, BYTE *b, DWORD len) {
#else
void __fastcall EncodeBuffer_Hook(OutPacket *p, void *edx, BYTE *b, DWORD len) {
#endif
	if (!IGNORE_PACKET) {
		PacketExtraInformation pxi = { packet_id_out, (ULONG_PTR)_ReturnAddress(), ENCODEBUFFER, p->encoded, len };
		AddExtra(pxi);
	}
	return _EncodeBuffer(p, b, len);
}

// 後からフォーマット情報は送信される
#ifdef _WIN64
void ProcessPacket_Hook(void *pCClientSocket, InPacket *p) {
#else
void __fastcall ProcessPacket_Hook(void *pCClientSocket, void *edx, InPacket *p) {
#endif
	if (p->unk2 == 0x02) {
		CountUpPacketID(packet_id_in);

		bool bBlock = false;
		AddRecvPacket(p, (ULONG_PTR)_ReturnAddress(), bBlock);
		if (!bBlock) {
			_ProcessPacket(pCClientSocket, p);
		}
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)0, DECODE_END, 0, 0 };
		AddExtra(pxi);
	}
	else {
		_ProcessPacket(pCClientSocket, p);
	}
}

#ifdef _WIN64
BYTE Decode1_Hook(InPacket *p) {
#else
BYTE __fastcall Decode1_Hook(InPacket *p, void *edx) {
#endif
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE1, p->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
		// update
		pxi.data = &p->packet[p->decoded];
		AddExtra(pxi);
	}
	return _Decode1(p);
}

#ifdef _WIN64
WORD Decode2_Hook(InPacket *p) {
#else
WORD __fastcall Decode2_Hook(InPacket *p, void *edx) {
#endif
	if (p->unk2 == 0x02) {
		if (p->decoded == 4) {
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEHEADER, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
			// update
			pxi.data = &p->packet[p->decoded];
			AddExtra(pxi);
		}
		else {
			PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE2, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
			// update
			pxi.data = &p->packet[p->decoded];
			AddExtra(pxi);
		}
	}
	return _Decode2(p);
}

#ifdef _WIN64
DWORD Decode4_Hook(InPacket *p) {
#else
DWORD __fastcall Decode4_Hook(InPacket *p, void *edx) {
#endif
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE4, p->decoded - 4, sizeof(DWORD) };
		AddExtra(pxi);
		// update
		pxi.data = &p->packet[p->decoded];
		AddExtra(pxi);
	}
	return _Decode4(p);
}

#ifdef _WIN64
ULONG_PTR Decode8_Hook(InPacket *p) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODE8, p->decoded - 4, sizeof(ULONG_PTR) };
		AddExtra(pxi);
		// update
		pxi.data = &p->packet[p->decoded];
		AddExtra(pxi);
	}
	return _Decode8(p);
}
#endif

#ifdef _WIN64
char** DecodeStr_Hook(InPacket *p, char **s) {
#else
char** __fastcall DecodeStr_Hook(InPacket *p, void *edx, char **s) {
#endif
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODESTR, p->decoded - 4, sizeof(WORD) + *(WORD *)&p->packet[p->decoded] };
		AddExtra(pxi);
		// update
		pxi.data = &p->packet[p->decoded];
		AddExtra(pxi);
	}
	return _DecodeStr(p, s);
}

#ifdef _WIN64
void DecodeBuffer_Hook(InPacket *p, BYTE *b, DWORD len) {
#else
void __fastcall DecodeBuffer_Hook(InPacket *p, void *edx, BYTE *b, DWORD len) {
#endif
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (ULONG_PTR)_ReturnAddress(), DECODEBUFFER, p->decoded - 4, len };
		AddExtra(pxi);
		// update
		pxi.data = &p->packet[p->decoded];
		AddExtra(pxi);
	}
	return _DecodeBuffer(p, b, len);
}

#ifdef _WIN64
#else
// Packet Injector
ULONG_PTR uSendPacket = 0;
ULONG_PTR uEnterSendPacket = 0;
ULONG_PTR uEnterSendPacket_ret = 0;
ULONG_PTR uCClientSocket = 0;
void(*_EnterSendPacket)(OutPacket *p) = NULL;
void EnterSendPacket_Hook(OutPacket *p) {
	bool bBlock = false;
	AddSendPacket(p, (ULONG_PTR)_ReturnAddress(), bBlock);
	if (bBlock) {
		return;
	}
	return _EnterSendPacket(p);
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

bool ListScan(Rosemary &r, ULONG_PTR &result, std::wstring aob[], size_t count, int &used) {
	result = 0; // scan result
	used = -1; // which aob is used
	for (size_t i = 0; i < count; i++) {
		result = r.Scan(aob[i]);
		if (result) {
			used = (int)i;
			return true;
		}
	}
	return false;
}

#define HOOKDEBUG(func) \
{\
	ListScan(r, u##func, AOB_##func, _countof(AOB_##func), iWorkingAob);\
	DEBUG(L""#func" = " + QWORDtoString(u##func) + L", Aob = " + std::to_wstring(iWorkingAob));\
	if (iWorkingAob > -1) {\
		SHookFunction(func, u##func);\
	}\
}

bool PacketHook_Thread() {
	InitializeCriticalSection(&cs);
	Rosemary r;

	//ULONG_PTR uSendPacket = 0;
	ULONG_PTR uProcessPacket = 0;
	ULONG_PTR uCOutPacket = 0;
	ULONG_PTR uEncode1 = 0;
	ULONG_PTR uEncode2 = 0;
	ULONG_PTR uEncode4 = 0;
	ULONG_PTR uEncodeStr = 0;
	ULONG_PTR uEncodeBuffer = 0;
	ULONG_PTR uDecode1 = 0;
	ULONG_PTR uDecode2 = 0;
	ULONG_PTR uDecode4 = 0;
	ULONG_PTR uDecodeStr = 0;
	ULONG_PTR uDecodeBuffer = 0;
	int iWorkingAob = 0; // do not change name

#ifdef _WIN64
	ULONG_PTR uSendPacket = 0;
	ULONG_PTR uSendPacket_EH = 0;
	ULONG_PTR uEncode8 = 0;
	ULONG_PTR uDecode8 = 0;
	ULONG_PTR uCClientSocket = 0;
#endif

	HOOKDEBUG(SendPacket);

#ifdef _WIN64
	HOOKDEBUG(SendPacket_EH);

	if (uSendPacket && uSendPacket_EH) {
		uSendPacket_EH_Ret = uSendPacket_EH + Offset_SendPacket_EH_Ret[iWorkingAob];
		*(ULONG_PTR *)&bEnterSendPacket[0x06] = uSendPacket_EH_Ret;
		*(ULONG_PTR *)&bEnterSendPacket[0x11] = (ULONG_PTR)*_SendPacket;
		bEnterSendPacket[3] = ((BYTE *)uSendPacket_EH_Ret)[3]; // add rsp,XX -> sub rsp,XX

		uCClientSocket = uSendPacket_EH + Offset_SendPacket_EH_CClientSocket[iWorkingAob];
		uCClientSocket += *(signed long int *)(uCClientSocket + 0x01) + 0x05;
		_CClientSocket = (decltype(_CClientSocket))uCClientSocket;
		DEBUG(L"uCClientSocket = " + QWORDtoString(uCClientSocket));
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
	if (uSendPacket) {
#endif
		HOOKDEBUG(COutPacket);
		HOOKDEBUG(Encode1);
		HOOKDEBUG(Encode2);
		HOOKDEBUG(Encode4);
#ifdef _WIN64
		HOOKDEBUG(Encode8);
#endif
		HOOKDEBUG(EncodeStr);
		HOOKDEBUG(EncodeBuffer);

#ifndef _WIN64
		ULONG_PTR uWriteTempPacket = 0;
		HOOKDEBUG(WriteTempPacket);
#endif
	}

	HOOKDEBUG(ProcessPacket);

	if (uProcessPacket) {
		HOOKDEBUG(Decode1);
		HOOKDEBUG(Decode2);
		HOOKDEBUG(Decode4);
#ifdef _WIN64
		HOOKDEBUG(Decode8);
#endif
		HOOKDEBUG(DecodeStr);
		HOOKDEBUG(DecodeBuffer);
	}

	StartPipeClient();
	RunPacketSender();
	return true;
}


bool PacketHook() {
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)PacketHook_Thread, NULL, NULL, NULL);

	if (hThread) {
		CloseHandle(hThread);
	}

	return true;
}
