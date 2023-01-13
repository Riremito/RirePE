#ifndef __PACKETEDITOR_H__
#define __PACKETEDITOR_H__

#include<Windows.h>

#define PE_LOGGER_PIPE_NAME L"PacketLogger"
#define PE_SENDER_PIPE_NAME L"PacketSender"

#pragma pack(push, 1)

enum MessageHeader {
	SENDPACKET, // stop encoding
	RECVPACKET, // start decoding
	// encode
	ENCODE_BEGIN,
	ENCODEHEADER,
	ENCODE1,
	ENCODE2,
	ENCODE4,
	ENCODE8,
	ENCODESTR,
	ENCODEBUFFER,
	// TENVI
	TENVI_ENCODE_HEADER_1,
	TENVI_ENCODE_WSTR_1,
	TENVI_ENCODE_WSTR_2,
	ENCODE_END,
	// decode
	DECODE_BEGIN,
	DECODEHEADER,
	DECODE1,
	DECODE2,
	DECODE4,
	DECODE8,
	DECODESTR,
	DECODEBUFFER,
	// TENVI
	TENVI_DECODE_HEADER_1,
	TENVI_DECODE_WSTR_1,
	TENVI_DECODE_WSTR_2,
	DECODE_END, // not a tag
	// unknown
	UNKNOWNDATA, // not decoded by function
	NOTUSED, // recv not used
	WHEREFROM, // not encoded by function
	UNKNOWN,
};

enum FormatUpdate {
	FORMAT_NO_UPDATE,
	FORMAT_UPDATE,
};

typedef struct {
	MessageHeader header;
	DWORD id;
#ifdef _WIN64
	ULONG_PTR addr;
#else
	ULONGLONG addr;
#endif
	union {
		// SEND or RECV
		struct {
			DWORD length; // パケットのサイズ
			BYTE packet[1]; // パケット
		} Binary;
		// Encode or Decode
		struct {
			DWORD pos; // Encode or Decodeされた位置
			DWORD size; // サイズ
			FormatUpdate update;
			BYTE data[1]; // packet buffer sometimes changed before reading it
		} Extra;
		// Encode or Decode 完了通知
		DWORD status; // 状態
	};
} PacketEditorMessage;
#pragma pack(pop)

#endif