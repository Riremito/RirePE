#ifndef __MAPLEPACKET_H__
#define __MAPLEPACKET_H__
#include<Windows.h>

#ifdef _WIN64
#define MAPLE_VERSION 403
#else
#define MAPLE_VERSION 186
#endif

#pragma pack(push, 1)
// x64
#if MAPLE_VERSION >= 403
typedef struct {
	DWORD unk1; // 0x00
	DWORD unk2; // 0x01
	BYTE *packet;
	DWORD encoded;
	DWORD unk3;
	DWORD unk4;
	WORD header;
	BYTE padding[0x256];
} OutPacket;

typedef struct {
	DWORD unk1; // 0x00
	DWORD unk2; // 0x02
	BYTE *packet; // unk4bytes + packet
	DWORD fullsize;
	DWORD header;
	DWORD size; // DataLength - 4
	DWORD decoded; // starts from 0x04
	BYTE padding[0x256];
} InPacket;
// BB前
#elif MAPLE_VERSION <= 186
typedef struct {
	DWORD unk1; // 0x00
	BYTE *packet;
	DWORD encoded;
	DWORD unk4; // OutPacket
} OutPacket;


typedef struct {
	DWORD unk1; // 0
	DWORD unk2; // 0x02
	BYTE *packet; // unk4bytes + packet
	WORD length1; // data length
	WORD unk5; // unk 2 bytes?
	WORD length2; // packet length
	WORD unk7; // ??
	DWORD decoded; // from 0x04 to decoded
} InPacket;
#else
// TODO
#endif
#pragma pack(pop)

bool PacketHook();
bool SetCallBack();
bool RunPacketSender();

#ifdef _WIN64
void ProcessPacket_Hook(void *pCClientSocket, InPacket *p);
void COutPacket_Hook(OutPacket *p, WORD w);
void SendPacket_Hook(void *pCClientSocket, OutPacket *p);
void SendPacket_EH_Hook(OutPacket *p);

// original functions
extern void(*_COutPacket)(OutPacket *p, WORD w); // ヘッダの暗号化チェック用
extern void(*_SendPacket_EH)(OutPacket *p); // ヘッダの暗号化有効時に呼び出す
extern void(*_EnterSendPacket)(void *pCClientSocket, OutPacket *p); // ヘッダの暗号化無効時に呼び出す
extern void(*_ProcessPacket)(void *pCClientSocket, InPacket *p);
extern void* (*_CClientSocket)(void);
#else

void __fastcall  COutPacket_Hook(OutPacket *p, void *edx, WORD w);
void __fastcall SendPacket_Hook(void *pCClientSocket, void *edx, OutPacket *p);
void __fastcall ProcessPacket_Hook(void *pCClientSocket, void *edx, InPacket *p);
// sender
extern ULONG_PTR uEnterSendPacket_ret;
void EnterSendPacket_Hook(OutPacket *p);
ULONG_PTR GetCClientSocket();
#endif

#endif