#ifndef __MAPLEPACKET_H__
#define __MAPLEPACKET_H__
#include<Windows.h>

#define MAPLE_VERSION 403

#pragma pack(push, 1)
// BB前
#if MAPLE_VERSION <= 186
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
#elif MAPLE_VERSION >= 402 // x64 Update
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

#else
// TODO
#endif
#pragma pack(pop)

bool PacketHook();
void ProcessPacket_Hook(void *rcx, InPacket *p);
void COutPacket_Hook(OutPacket *p, WORD w);
void SendPacket_Hook(void *rcx, OutPacket *p);
void SendPacket_EH_Hook(OutPacket *p);

// original functions
extern void(*_COutPacket)(OutPacket *p, WORD w); // ヘッダの暗号化チェック用
extern void(*_SendPacket_EH)(OutPacket *p); // ヘッダの暗号化有効時に呼び出す
extern void(*_EnterSendPacket)(void *rcx, OutPacket *p); // ヘッダの暗号化無効時に呼び出す
extern void(*_ProcessPacket)(void *rcx, InPacket *p);
extern void* (*_CClientSocket)(void);

// sender
bool RunPacketSender();
bool SetCallBack();

#endif