#include"PacketHook.h"
#include"../Share/Hook/SimpleHook.h"
#include"../Share/Simple/Simple.h"
#include<vector>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)
#include"../RirePE/RirePE.h"
#include"PacketRelatedAob.h"

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

bool ListScan(Rosemary &r, ULONG_PTR &result, std::wstring aob[], size_t count, int &used) {
	result = 0; // scan result
	used = -1; // which aob is used
	for (int i = 0; i < count; i++) {
		result = r.Scan(aob[i]);
		if (result) {
			used = i;
			return true;
		}
	}
	return false;
}

#define HOOKDEBUG(func) \
{\
	ListScan(r, u##func, AOB_##func, _countof(AOB_##func), iWorkingAob);\
	DEBUG(L""#func" = " + QWORDtoString(u##func) + L", Aob = " + std::to_wstring(iWorkingAob));\
	SHookFunction(func, u##func);\
}

bool PacketHook() {
	InitializeCriticalSection(&cs);
	Rosemary r; // do not change name

	ULONG_PTR uSendPacket = 0;
	ULONG_PTR uProcessPacket = 0;
	ULONG_PTR uSendPacket_EH = 0;
	ULONG_PTR uCOutPacket = 0;
	ULONG_PTR uEncode1 = 0;
	ULONG_PTR uEncode2 = 0;
	ULONG_PTR uEncode4 = 0;
	ULONG_PTR uEncode8 = 0;
	ULONG_PTR uEncodeStr = 0;
	ULONG_PTR uEncodeBuffer = 0;
	ULONG_PTR uDecode1 = 0;
	ULONG_PTR uDecode2 = 0;
	ULONG_PTR uDecode4 = 0;
	ULONG_PTR uDecode8 = 0;
	ULONG_PTR uDecodeStr = 0;
	ULONG_PTR uDecodeBuffer = 0;
	int iWorkingAob = 0; // do not change name
	ULONG_PTR uCClientSocket = 0;

	HOOKDEBUG(SendPacket);
	HOOKDEBUG(SendPacket_EH);

	if (uSendPacket && uSendPacket_EH) {
		uSendPacket_EH_Ret = uSendPacket_EH + Offset_SendPacket_EH_Ret[iWorkingAob];
		*(ULONG_PTR *)&bEnterSendPacket[0x06] = uSendPacket_EH_Ret;
		*(ULONG_PTR *)&bEnterSendPacket[0x11] = (ULONG_PTR)*_SendPacket;
		bEnterSendPacket[3] = ((BYTE *)uSendPacket_EH_Ret)[3]; // add rsp,XX -> sub rsp,XX

		uCClientSocket = uSendPacket_EH + Offset_SendPacket_EH_CClientSocket;
		uCClientSocket += *(signed long int *)(uCClientSocket + 0x01) + 0x05;
		_CClientSocket = (decltype(_CClientSocket))uCClientSocket;
		DEBUG(L"uCClientSocket = " + QWORDtoString(uCClientSocket));
	}

	if (uSendPacket && uSendPacket_EH) {
		HOOKDEBUG(COutPacket);
		HOOKDEBUG(Encode1);
		HOOKDEBUG(Encode2);
		HOOKDEBUG(Encode4);
		HOOKDEBUG(Encode8);
		HOOKDEBUG(EncodeStr);
		HOOKDEBUG(EncodeBuffer);
	}

	HOOKDEBUG(ProcessPacket);

	if (uProcessPacket) {
		HOOKDEBUG(Decode1);
		HOOKDEBUG(Decode2);
		HOOKDEBUG(Decode4);
		HOOKDEBUG(Decode8);
		HOOKDEBUG(DecodeStr);
		HOOKDEBUG(DecodeBuffer);
	}

	RunPacketSender();
	StartPipeClient();
	return true;
}
