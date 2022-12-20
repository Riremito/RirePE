#ifndef __AOB_LIST_H__
#define __AOB_LIST_H__

#include<Windows.h>
#include<string>

std::wstring AOB_SendPacket[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 10 53 56 8B F1 8D 9E 80 00 00 00 57 8B CB 89 5D F0 E8 ?? ?? ?? ?? 8B 46 0C 33 FF 3B C7",
	// v302.0
	L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 20 64 A3 00 00 00 00 8B F9 8D 87 84 00 00 00 50 8D 4C 24 10 E8",
};

std::wstring AOB_EnterSendPacket[] = {
	// v164.0 to v186.1
	L"FF 74 24 04 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C3",
};

std::wstring AOB_ProcessPacket[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7",
	// v302.0
	L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 08 53 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F9 8B 1D ?? ?? ?? ?? 89 5C 24 14 85 DB 74",
};

std::wstring AOB_COutPacket[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 F3 50 8D 4E 04 68 00 01 00 00 89 75 EC E8 ?? ?? ?? ?? FF 75 08 83 65 FC 00 8B CE E8",
};

std::wstring AOB_Encode1[] = {
	// v164.0 to v186.1
	L"56 8B F1 6A 01 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8A 54 24 08 88 14 08 FF 46 08 5E C2 04 00",
};

std::wstring AOB_Encode2[] = {
	// v164.0 to v186.1
	L"56 8B F1 6A 02 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 66 8B 54 24 08 66 89 14 08 83 46 08 02 5E C2 04 00",
};

std::wstring AOB_Encode4[] = {
	// v164.0 to v186.1
	L"56 8B F1 6A 04 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8B 54 24 08 89 14 08 83 46 08 04 5E C2 04 00",
};

std::wstring AOB_EncodeStr[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 8B F1 8B 45 08 83 65 FC 00 85 C0 74 05 8B 40 FC EB 02 33 C0 83 C0 02 50 8B CE E8",
};

std::wstring AOB_EncodeBuffer[] = {
	// v164.0 to v186.1
	L"56 57 8B 7C 24 10 8B F1 57 E8 ?? ?? ?? ?? 8B 46 04 03 46 08 57 FF 74 24 10 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 5F 5E C2 08 00",
};

std::wstring AOB_Decode1[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 01",
};

std::wstring AOB_Decode2[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 02",
};

std::wstring AOB_Decode4[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 04",
};

std::wstring AOB_DecodeStr[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 18 53 56 57 89 65 F0 6A 01 33 FF 8B F1 5B",
};

std::wstring AOB_DecodeBuffer[] = {
	// v164.0 to v186.1
	L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 83 65 FC 00 53 56 8B F1 0F B7 46 0C",
};

std::wstring AOB_Encode8[] = {
	L"",
};

std::wstring AOB_Decode8[] = {
	L"",
};

#endif