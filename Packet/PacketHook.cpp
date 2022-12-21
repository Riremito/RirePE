#include"PacketHook.h"
#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#include<vector>
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)
#include"../RirePE/RirePE.h"
#include"AobList.h"

PipeClient *pc = NULL;

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
bool BYTEtoShiftJIS(BYTE *text, size_t len, std::string &sjis) {
	std::vector<BYTE> b(len + 1);
	for (size_t i = 0; i < len; i++) {
		b[i] = text[i];
	}
	sjis = std::string((char *)&b[0]);
	return true;
}

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

DWORD packet_id_out = 0;
DWORD packet_id_in = 0;

typedef struct {
	DWORD id; // パケット識別子
	DWORD addr; // リターンアドレス
	MessageHeader fmt; // フォーマットの種類
	DWORD pos; // 場所
	DWORD len; // データの長さ (DecodeBuffer以外不要)

} PacketExtraInformation;


void AddExtra(PacketExtraInformation &pxi) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	pem = new PacketEditorMessage;

	if (!pem) {
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
}

void AddSendPacket(OutPacket *p, DWORD addr, bool &bBlock) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->encoded];

	if (!b) {
		return;
	}

	pem->header = SENDPACKET;
	pem->id = packet_id_out++;
	pem->addr = addr;
	pem->Binary.length = p->encoded;
	memcpy_s(pem->Binary.packet, p->encoded, p->packet, p->encoded);

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
}

void AddRecvPacket(InPacket *p, DWORD addr, bool &bBlock) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->length2];

	if (!b) {
		return;
	}

	pem->header = RECVPACKET;
	pem->id = packet_id_in;
	pem->addr = addr;
	pem->Binary.length = p->length2;
	memcpy_s(pem->Binary.packet, p->length2, &p->packet[4], p->length2);

	if (!pc->Send(b, sizeof(PacketEditorMessage) + p->length2)) {
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
}


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

void __fastcall  COutPacket_Hook(OutPacket *p, void *edx, WORD w) {
	packet_id_out++;
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODEHEADER, 0, sizeof(WORD) };
	AddExtra(pxi);
	return _COutPacket(p, w);
}

void __fastcall Encode1_Hook(OutPacket *p, void *edx, BYTE b) {
	if (p->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODE1, p->encoded, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Encode1(p, b);
}
void __fastcall Encode2_Hook(OutPacket *p, void *edx, WORD w) {
	if (p->encoded) {
		PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODE2, p->encoded, sizeof(WORD) };
		AddExtra(pxi);
	}
	return _Encode2(p, w);

}
void __fastcall Encode4_Hook(OutPacket *p, void *edx, DWORD dw) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODE4, p->encoded, sizeof(DWORD) };
	AddExtra(pxi);
	return _Encode4(p, dw);
}
void __fastcall EncodeStr_Hook(OutPacket *p, void *edx, char *s) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODESTR, p->encoded, sizeof(WORD) + strlen(s) };
	AddExtra(pxi);
	return _EncodeStr(p, s);
}
void __fastcall EncodeBuffer_Hook(OutPacket *p, void *edx, BYTE *b, DWORD len) {
	PacketExtraInformation pxi = { packet_id_out, (DWORD)_ReturnAddress(), ENCODEBUFFER, p->encoded, len };
	AddExtra(pxi);
	return _EncodeBuffer(p, b, len);
}

// 後からフォーマット情報は送信される
void __fastcall ProcessPacket_Hook(void *ecx, void *edx, InPacket *p) {
	if (p->unk2 == 0x02) {
		packet_id_in++;
		bool bBlock = false;
		AddRecvPacket(p, (DWORD)_ReturnAddress(), bBlock);
		if (!bBlock) {
			_ProcessPacket(ecx, p);
		}
		PacketExtraInformation pxi = { packet_id_in, (DWORD)0, DECODEEND, 0, 0 };
		AddExtra(pxi);
	}
	else {
		_ProcessPacket(ecx, p);
	}
}

BYTE __fastcall Decode1_Hook(InPacket *p, void *edx) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODE1, p->decoded - 4, sizeof(BYTE) };
		AddExtra(pxi);
	}
	return _Decode1(p);
}

WORD __fastcall Decode2_Hook(InPacket *p, void *edx) {
	if (p->unk2 == 0x02) {
		if (p->decoded == 4) {
			PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODEHEADER, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
		}
		else {
			PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODE2, p->decoded - 4, sizeof(WORD) };
			AddExtra(pxi);
		}
	}
	return _Decode2(p);
}

DWORD __fastcall Decode4_Hook(InPacket *p, void *edx) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODE4, p->decoded - 4, sizeof(DWORD) };
		AddExtra(pxi);
	}
	return _Decode4(p);
}

char** __fastcall DecodeStr_Hook(InPacket *p, void *edx, char **s) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODESTR, p->decoded - 4, sizeof(WORD) + *(WORD *)&p->packet[p->decoded] };
		AddExtra(pxi);
	}
	return _DecodeStr(p, s);
}

void __fastcall DecodeBuffer_Hook(InPacket *p, void *edx, BYTE *b, DWORD len) {
	if (p->unk2 == 0x02) {
		PacketExtraInformation pxi = { packet_id_in, (DWORD)_ReturnAddress(), DECODEBUFFER, p->decoded - 4, len };
		AddExtra(pxi);
	}
	return _DecodeBuffer(p, b, len);
}

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

bool ListScan(Rosemary &r, ULONG_PTR &result, std::wstring aob[], size_t count, int &used) {
	result = 0; // scan result
	used = -1; // which aob is used
	for (size_t i = 0; i < count; i++) {
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
	//ULONG_PTR uEncode8 = 0;
	//ULONG_PTR uDecode8 = 0;
	int iWorkingAob = 0; // do not change name

	HOOKDEBUG(SendPacket);

	if (uSendPacket) {
		uEnterSendPacket = r.Scan(AOB_EnterSendPacket[0], ScannerEnterSendPacket);
		if (uEnterSendPacket) {
			SHookFunction(EnterSendPacket, uEnterSendPacket);
		}
		SCANRES(uEnterSendPacket);
		SCANRES(uEnterSendPacket_ret);
		SCANRES(uCClientSocket);
	}

	if (uSendPacket) {
		HOOKDEBUG(COutPacket);
		HOOKDEBUG(Encode1);
		HOOKDEBUG(Encode2);
		HOOKDEBUG(Encode4);
		//HOOKDEBUG(Encode8);
		HOOKDEBUG(EncodeStr);
		HOOKDEBUG(EncodeBuffer);
	}

	HOOKDEBUG(ProcessPacket);

	if (uProcessPacket) {
		HOOKDEBUG(Decode1);
		HOOKDEBUG(Decode2);
		HOOKDEBUG(Decode4);
		//HOOKDEBUG(Decode8);
		HOOKDEBUG(DecodeStr);
		HOOKDEBUG(DecodeBuffer);
	}

	StartPipeClient();
	RunPacketSender();
	return true;
}
