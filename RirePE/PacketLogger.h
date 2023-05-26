#ifndef __PACKETLOGGER_H__
#define __PACKETLOGGER_H__

typedef struct {
	ULONGLONG addr;
	MessageHeader type;
	ULONG_PTR pos;
	ULONG_PTR size;
	bool modified;
} PacketFormat;

typedef struct {
	ULONGLONG addr;
	ULONG_PTR id;
	MessageHeader type;
	std::vector<BYTE> packet;
	std::vector<PacketFormat> format;
	int status;
	ULONG_PTR used;
	BOOL lock;
} PacketData;

bool PacketLogger();
void ClearAll();
std::vector<PacketData>& GetOutPacketFormat();
std::vector<PacketData>& GetInPacketFormat();

#endif