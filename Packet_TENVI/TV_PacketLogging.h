#ifndef __TV_PACKET_LOGGING_H__
#define __TV_PACKET_LOGGING_H__

#include"../Share/Simple/Simple.h"
#include"TV_Packet.h"
#include"TV_PacketHook.h"
#include"../RirePE/RirePE.h"

typedef struct {
	ULONG_PTR id;
	ULONG_PTR addr;
	MessageHeader fmt;
	ULONG_PTR pos;
	ULONG_PTR size;
} PacketExtraInformation;

std::wstring GetPipeNameLogger();
std::wstring GetPipeNameSender();

int get_target_pid();
void set_target_pid(int pid);

bool TV_RunRirePE(TenviHookConfig &thc);
void AddExtra(PacketExtraInformation &pxi);
void AddSendPacket(TV_OutPacket *p, ULONG_PTR addr, bool &bBlock);
void AddRecvPacket(TV_InPacket *p, ULONG_PTR addr, bool &bBlock);

#endif
