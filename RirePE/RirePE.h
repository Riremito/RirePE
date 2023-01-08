#ifndef __PACKETEDITOR_H__
#define __PACKETEDITOR_H__

#include<Windows.h>

#define PE_LOGGER_PIPE_NAME L"PacketLogger"
#define PE_SENDER_PIPE_NAME L"PacketSender"

#pragma pack(push, 1)
enum MessageHeader {
	SENDPACKET, // stop encoding
	RECVPACKET, // start decoding
	ENCODEHEADER, // start encoding
	ENCODE1,
	ENCODE2,
	ENCODE4,
	ENCODE8,
	ENCODESTR,
	ENCODEBUFFER,
	DECODEHEADER,
	DECODE1,
	DECODE2,
	DECODE4,
	DECODE8,
	DECODESTR,
	DECODEBUFFER,
	DECODEEND,
	UNKNOWNDATA, // not decoded by function
	NOTUSED, // recv not used
	WHEREFROM, // not encoded by function
	UNKNOWN,
};
typedef struct {
	MessageHeader header;
	ULONG_PTR id;
	ULONG_PTR addr;
	union {
		// SEND or RECV
		struct {
			ULONG_PTR length; // パケットのサイズ
			BYTE packet[1]; // パケット
		} Binary;
		// Encode or Decode
		struct {
			ULONG_PTR pos; // Encode or Decodeされた位置
			ULONG_PTR size; // サイズ
		} Extra;
		// Encode or Decode 完了通知
		ULONG_PTR status; // 状態
	};
} PacketEditorMessage;
#pragma pack(pop)

#endif