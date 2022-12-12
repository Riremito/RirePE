#ifndef __MAPLEPACKET_H__
#define __MAPLEPACKET_H__
#include<Windows.h>

#define MAPLE_VERSION 186

#pragma pack(push, 1)
// BB‘O
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
#else
// TODO
#endif
#pragma pack(pop)

bool PacketHook();

void __fastcall  COutPacket_Hook(OutPacket *p, void *edx, WORD w);
void __fastcall SendPacket_Hook(void *ecx, void *edx, OutPacket *p);
void __fastcall ProcessPacket_Hook(void *ecx, void *edx, InPacket *p);
// sender
extern ULONG_PTR uEnterSendPacket_ret;
bool RunPacketSender();
void EnterSendPacket_Hook(OutPacket *p);
ULONG_PTR GetCClientSocket();

#endif