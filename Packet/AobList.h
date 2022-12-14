#ifndef __AOB_LIST_H__
#define __AOB_LIST_H__

#include<Windows.h>
#include<string>

/*
	v20Xかv30XあたりからPacket Senderの対策が追加されています
		1) Thread IDの確認, Main Thread以外からSendPacketを呼び出すと検出されます, Packet Senderを使わない限りは回避不要です
		2) Return Addressの確認, SendPacketが呼ばれた時のReturn Addressがexeの範囲外のだと検出されます
		3) Memoryの確認, Return Address - 0x05がcall SendPacketでない場合に検出されます
		4) Memoryの確認, Return Adressがret (0xC3)の場合も検出されます
		5) Return Addressの確認, SendPacketが呼ばれた時のReturn Addressがexeのthemidaのvirtualizerの範囲内だと3, 4が無視されます

	以下のメモリを探しSendPacketのフックに利用します
		call SendPacket // Bypass Memory Check
		add rsp,XX // Bypass Return Address Check, FakeReturn
		ret

	フックから_SendPacketの呼び出す時の書き方
		sub rsp,XX // 適当に利用した処理でStackがずれる分を事前に調整します
		mov rax,FakeReturn // ここがRetun Addressとなります
		push rax
		mov rax,_SendPacket // push + retで任意のReturn Addressを設置したcallを実行します
		push rax
		ret
*/

// Send Hook
std::wstring AOB_SendPacket[] = {
	#ifdef _WIN64
	// v410.2 from v403.1
	L"48 89 54 24 10 48 89 4C 24 08 56 57 48 81 EC ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? FE FF FF FF 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E9",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 10 53 56 8B F1 8D 9E 80 00 00 00 57 8B CB 89 5D F0 E8 ?? ?? ?? ?? 8B 46 0C 33 FF 3B C7",
	// v302.0
	L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 20 64 A3 00 00 00 00 8B F9 8D 87 84 00 00 00 50 8D 4C 24 10 E8",
	#endif
};

#ifdef _WIN64
std::wstring AOB_SendPacket_EH[] = {
	// v410.2
	L"48 89 4C 24 08 48 83 EC 38 E8 ?? ?? ?? ?? 48 8B 4C 24 40 8B 51 1C 48 8B C8 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 44 24 20 48 83 7C 24 20 00 74 0F 48 8B 54 24 40 48 8B 4C 24 20 E8 ?? ?? ?? ?? 48 83 C4 38 C3",
	// v403.1
	L"48 89 4C 24 08 48 83 EC 28 E8 ?? ?? ?? ?? 48 8B 4C 24 30 8B 51 1C 48 8B C8 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 54 24 30 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3",
};

DWORD Offset_SendPacket_EH_Ret[] = {
	// v410.2
	0x3F,
	// v403.1
	0x30,
};

DWORD Offset_SendPacket_EH_CClientSocket = 0x1E; // not changed

#else
std::wstring AOB_EnterSendPacket[] = {
	// v164.0 to v186.1
	L"FF 74 24 04 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C3",
};
#endif

// Recv Hook
std::wstring AOB_ProcessPacket[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 54 24 10 48 89 4C 24 08 48 81 EC ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? FE FF FF FF 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 75",
	// v403.1
	L"48 89 54 24 10 48 89 4C 24 08 56 57 48 81 EC ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 75 05 E9 ?? ?? ?? ?? E9",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7",
	// v302.0
	L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 08 53 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F9 8B 1D ?? ?? ?? ?? 89 5C 24 14 85 DB 74",
	#endif
};

// Format Hook
std::wstring AOB_COutPacket[] = {
	#ifdef _WIN64
	// v410.2 from v403.1
	L"48 89 4C 24 ?? 57 48 83 EC ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 89 5C 24 ?? 8B DA 48 8B F9 48 83 C1 ?? 48 C7 01 00 00 00 00",
	// TWMS v246
	L"48 89 4C 24 ?? 57 48 83 EC ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 89 5C 24 ?? 8B ?? 48 8B D9 48 C7 41 08 00 00 00 00 BA 04 01 00 00 48 8D 0D ?? ?? ?? ?? E8",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 F3 50 8D 4E 04 68 00 01 00 00 89 75 EC E8 ?? ?? ?? ?? FF 75 08 83 65 FC 00 8B CE E8",
	#endif
};

std::wstring AOB_Encode1[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B D9 0F B6 FA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75",
	// v403.1
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 0F B6 DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 0F B6 CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3",
	#else
	// v164.0 to v186.1
	L"56 8B F1 6A 01 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8A 54 24 08 88 14 08 FF 46 08 5E C2 04 00",
	#endif
};

std::wstring AOB_Encode2[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B D9 0F B7 FA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75",
	// v403.1
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 0F B7 DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 0F B7 CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3",
	#else
	// v164.0 to v186.1
	L"56 8B F1 6A 02 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 66 8B 54 24 08 66 89 14 08 83 46 08 02 5E C2 04 00",
	#endif
};

std::wstring AOB_Encode4[] = {
	#ifdef _WIN64

	// v410.2
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B D9 8B FA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75",
	// v403.1
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 8B DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 8B CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3",
	#else
	// v164.0 to v186.1
	L"56 8B F1 6A 04 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8B 54 24 08 89 14 08 83 46 08 04 5E C2 04 00",
	#endif
};

#ifdef _WIN64
std::wstring AOB_Encode8[] = {
	// v410.2
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B FA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75",
	// v403.1
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B DA 48 8D 4C 24 38 E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 48 8B CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3",
};
#endif

std::wstring AOB_EncodeStr[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B FA 48 8B CA E8 ?? ?? ?? ?? 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75",
	// v403.1
	L"48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B DA 48 8B CA E8 ?? ?? ?? ?? 8B D0 48 8B CF E8 ?? ?? ?? ?? 8B 57 10 48 8B CB 48 03 57 08 E8 ?? ?? ?? ?? 01 47 10 48 8B 5C 24 30 48 83 C4 20 5F C3",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 8B F1 8B 45 08 83 65 FC 00 85 C0 74 05 8B 40 FC EB 02 33 C0 83 C0 02 50 8B CE E8",
	#endif
};

std::wstring AOB_EncodeBuffer[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA 41 8B F0 41 8B D0 48 8B F9 E8 ?? ?? ?? ?? 48 8B 47 08 48 85 C0 75",
	// v403.1
	L"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA 41 8B F0 41 8B D0 48 8B F9 E8 ?? ?? ?? ?? 8B 47 10 48 03 47 08 85 F6 7E 18 8B D6 0F 1F 00 0F B6 0B 48 8D 5B 01 88 08 48 8D 40 01 48 83 EA 01 75 ED 01 77 10 48 8B 74 24 38 48 8B 5C 24 30 48 83 C4 20 5F C3",
	#else
	// v164.0 to v186.1
	L"56 57 8B 7C 24 10 8B F1 57 E8 ?? ?? ?? ?? 8B 46 04 03 46 08 57 FF 74 24 10 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 5F 5E C2 08 00",
	#endif
};

std::wstring AOB_Decode1[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 48 8B 41 08 48 85 C0 75 13 B9 A7 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 74 0B 83 78 FC 00 77 1A 48 85 C0 75 05 45 33 C0 EB 04 44 8B 40 FC 33 D2 B9 93 00 00 00 E8 ?? ?? ?? ?? 8B 53 1C 44 8B 43 10 44 2B C2 48 03 53 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 0F B6 44 24 58 48 83 C4 40 5B C3",
	// v403.1
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 0F B6 44 24 58 48 83 C4 40 5B C3",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 01",
	#endif
};

std::wstring AOB_Decode2[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 48 8B 41 08 48 85 C0 75 13 B9 A7 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 74 0B 83 78 FC 00 77 1A 48 85 C0 75 05 45 33 C0 EB 04 44 8B 40 FC 33 D2 B9 93 00 00 00 E8 ?? ?? ?? ?? 8B 53 1C 44 8B 43 10 44 2B C2 48 03 53 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 0F B7 44 24 58 48 83 C4 40 5B C3",
	// v403.1
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 0F B7 44 24 58 48 83 C4 40 5B C3",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 02",
	#endif
};

std::wstring AOB_Decode4[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 48 8B 41 08 48 85 C0 75 13 B9 A7 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 74 0B 83 78 FC 00 77 1A 48 85 C0 75 05 45 33 C0 EB 04 44 8B 40 FC 33 D2 B9 93 00 00 00 E8 ?? ?? ?? ?? 8B 53 1C 44 8B 43 10 44 2B C2 48 03 53 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 8B 44 24 58 48 83 C4 40 5B C3",
	// v403.1
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 8B 44 24 58 48 83 C4 40 5B C3",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 04",
	#endif
};

#ifdef _WIN64
std::wstring AOB_Decode8[] = {
	// v410.2
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 48 8B 41 08 48 85 C0 75 13 B9 A7 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 74 0B 83 78 FC 00 77 1A 48 85 C0 75 05 45 33 C0 EB 04 44 8B 40 FC 33 D2 B9 93 00 00 00 E8 ?? ?? ?? ?? 8B 53 1C 44 8B 43 10 44 2B C2 48 03 53 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 48 8B 44 24 58 48 83 C4 40 5B C3",
	// v403.1
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 8B D9 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8D 4C 24 58 E8 ?? ?? ?? ?? 01 43 1C 48 8B 44 24 58 48 83 C4 40 5B C3",
};
#endif

std::wstring AOB_DecodeStr[] = {
	#ifdef _WIN64
	// v410.2
	L"48 8B C4 48 89 50 10 48 89 48 08 57 48 83 EC 50 48 C7 40 D0 FE FF FF FF 48 89 58 18 48 89 70 20 48 8B F2 48 8B D9 33 FF 89 78 C8 48 89 3A C7 40 C8 01 00 00 00 48 8B 41 08 48 85 C0 75 13 B9 A7 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 74 0E 83 78 FC 00 77 17 48 85 C0 74 03 8B 78 FC 44 8B C7 33 D2 B9 93 00 00 00 E8 ?? ?? ?? ?? 8B 53 1C 44 8B 43 10 44 2B C2 48 03 53 08 48 8B CE E8 ?? ?? ?? ?? 01 43 1C 48 8B C6 48 8B 5C 24 70 48 8B 74 24 78 48 83 C4 50 5F C3",
	// v403.1
	L"48 89 54 24 10 48 89 4C 24 08 57 48 83 EC 50 48 C7 44 24 28 FE FF FF FF 48 89 5C 24 70 48 8B FA 48 8B D9 33 C0 89 44 24 20 48 89 02 C7 44 24 20 01 00 00 00 8B 51 1C 44 8B 41 10 44 2B C2 48 03 51 08 48 8B CF E8 ?? ?? ?? ?? 01 43 1C 48 8B C7 48 8B 5C 24 70 48 83 C4 50 5F C3",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 18 53 56 57 89 65 F0 6A 01 33 FF 8B F1 5B",
	#endif
};

std::wstring AOB_DecodeBuffer[] = {
	#ifdef _WIN64
	// v410.2
	L"48 89 4C 24 08 57 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 48 89 5C 24 58 48 89 74 24 60 41 8B F8 48 8B F2 48 8B D9 48 8B 41 08 48 85 C0 75 13 B9 A7 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 74 0B 83 78 FC 00 77 1A 48 85 C0 75 05 45 33 C0 EB 04 44 8B 40 FC 33 D2 B9 93 00 00 00 E8 ?? ?? ?? ?? 44 8B 43 1C 44 8B 4B 10 45 2B C8 4C 03 43 08 8B D7 48 8B CE E8 ?? ?? ?? ?? 01 43 1C 48 8B 5C 24 58 48 8B 74 24 60 48 83 C4 40 5F C3",
	// v403.1
	L"48 89 4C 24 08 53 48 83 EC 40 48 C7 44 24 20 FE FF FF FF 41 8B C0 4C 8B D2 48 8B D9 44 8B 41 1C 44 8B 49 10 45 2B C8 4C 03 41 08 8B D0 49 8B CA E8 ?? ?? ?? ?? 01 43 1C 48 83 C4 40 5B C3",
	#else
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 83 65 FC 00 53 56 8B F1 0F B7 46 0C",
	#endif
};

#endif