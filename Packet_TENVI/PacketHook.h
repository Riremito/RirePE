#ifndef __TENVIPACKET_H__
#define __TENVIPACKET_H__
#include<Windows.h>

#pragma pack(push, 1)
// TENVI v127
typedef struct {
	DWORD unk1; // 0x00
	BYTE *packet;
	DWORD unk3; // 0x100
	DWORD unk4; // 0x100
	DWORD unk5; // 0x0
	DWORD encoded;
} OutPacket;

typedef struct {
	DWORD unk1; // 0
	DWORD unk2; // 4
	BYTE *packet; // +0x08
	DWORD unk4; // C
	DWORD unk5; // 10
	DWORD unk6; // 14
	WORD length; // + 0x18 ???
	WORD unk8; // 1A
	DWORD unk9; // 1C
	DWORD decoded; // +0x20
	DWORD unk10;
} InPacket;
#pragma pack(pop)

bool PacketHook();
bool SetCallBack();
bool RunPacketSender();

void __fastcall COutPacket_Hook(OutPacket *p, void *edx, BYTE b, void *v);
void __fastcall SendPacket_Hook(void *pCClientSocket, void *edx, OutPacket *p);
void __fastcall ProcessPacket_Hook(void *pCClientSocket, void *edx, InPacket *p);
// sender
extern ULONG_PTR uEnterSendPacket_ret;
void __fastcall EnterSendPacket_Hook(OutPacket *p);
ULONG_PTR GetCClientSocket();
void MyProcessPacket(InPacket *p);

extern DWORD packet_id_in;

#endif