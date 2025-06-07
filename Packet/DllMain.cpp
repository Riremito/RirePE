#include"../Share/Simple/Simple.h"
#include"../Packet/PacketHook.h"

#ifndef _WIN64
#define DLL_NAME L"Packet"
#else
#define DLL_NAME L"Packet64"
#endif
#define INI_FILE_NAME DLL_NAME".ini"


ULONG_PTR StringtoAddress(std::wstring &wAddr) {
	ULONG_PTR uAddr = 0;
#ifdef _WIN64
	swscanf_s(wAddr.c_str(), L"%llX", &uAddr);
#else
	swscanf_s(wAddr.c_str(), L"%08X", &uAddr);
#endif
	return uAddr;
}

ULONG_PTR ConftoAddress(Config &conf, std::wstring wLabel) {
	std::wstring wText;
	if (conf.Read(DLL_NAME, wLabel, wText)) {
		return StringtoAddress(wText);
	}
	return 0;
}

HookSettings gHookSettings = {}; // for thread
bool LoadPacketConfig(HINSTANCE hinstDLL) {
	HookSettings &hs = gHookSettings;
	hs.hinstDLL = hinstDLL;
	Config conf(INI_FILE_NAME, hs.hinstDLL);

	// debug mode
	std::wstring wDebugMode;
	if (conf.Read(DLL_NAME, L"DEBUG_MODE", wDebugMode) && _wtoi(wDebugMode.c_str())) {
		hs.debug_mode = true;
	}
	// hook from thread
	std::wstring wUseThread;
	if (conf.Read(DLL_NAME, L"USE_THREAD", wUseThread) && _wtoi(wUseThread.c_str())) {
		hs.use_thread = true;
	}
	// hook without using aob scan
	std::wstring wUseAddr;
	if (conf.Read(DLL_NAME, L"USE_ADDR", wUseAddr) && _wtoi(wUseAddr.c_str())) {
		hs.use_addr = true;
		// Send
		hs.addr_SendPacket = ConftoAddress(conf, L"SendPacket");
		if (!hs.addr_SendPacket) {
			hs.addr_SendPacket2 = ConftoAddress(conf, L"SendPacket2");
		}
		hs.addr_COutPacket = ConftoAddress(conf, L"COutPacket");
		if (!hs.addr_COutPacket) {
			hs.addr_COutPacket2 = ConftoAddress(conf, L"COutPacket2");
			if (!hs.addr_COutPacket2) {
				hs.addr_COutPacket3 = ConftoAddress(conf, L"COutPacket3");
			}
		}
		hs.addr_Encode1 = ConftoAddress(conf, L"Encode1");
		hs.addr_Encode2 = ConftoAddress(conf, L"Encode2");
		hs.addr_Encode4 = ConftoAddress(conf, L"Encode4");
		hs.addr_Encode8 = ConftoAddress(conf, L"Encode8");
		hs.addr_EncodeStr = ConftoAddress(conf, L"EncodeStr");
		hs.addr_EncodeBuffer = ConftoAddress(conf, L"EncodeBuffer");
		// Recv
		hs.addr_ProcessPacket = ConftoAddress(conf, L"ProcessPacket");
		hs.addr_Decode1 = ConftoAddress(conf, L"Decode1");
		hs.addr_Decode2 = ConftoAddress(conf, L"Decode2");
		hs.addr_Decode4 = ConftoAddress(conf, L"Decode4");
		hs.addr_Decode8 = ConftoAddress(conf, L"Decode8");
		hs.addr_DecodeStr = ConftoAddress(conf, L"DecodeStr");
		hs.addr_DecodeBuffer = ConftoAddress(conf, L"DecodeBuffer");
	}

	return true;
}

bool SavePacketConfig() {
	HookSettings &hs = gHookSettings;
	Config conf(INI_FILE_NAME, hs.hinstDLL);
	// do not update
	if (hs.use_addr || hs.use_thread) {
		return false;
	}
#ifdef _WIN64
	return false;
#endif

	// aob results
	conf.Update(DLL_NAME, L"SendPacket", DWORDtoString(hs.addr_SendPacket));
	conf.Update(DLL_NAME, L"SendPacket2", DWORDtoString(hs.addr_SendPacket2));
	conf.Update(DLL_NAME, L"COutPacket", DWORDtoString(hs.addr_COutPacket));
	conf.Update(DLL_NAME, L"COutPacket2", DWORDtoString(hs.addr_COutPacket2));
	conf.Update(DLL_NAME, L"COutPacket3", DWORDtoString(hs.addr_COutPacket3));
	conf.Update(DLL_NAME, L"Encode1", DWORDtoString(hs.addr_Encode1));
	conf.Update(DLL_NAME, L"Encode2", DWORDtoString(hs.addr_Encode2));
	conf.Update(DLL_NAME, L"Encode4", DWORDtoString(hs.addr_Encode4));
	conf.Update(DLL_NAME, L"Encode8", DWORDtoString(hs.addr_Encode8));
	conf.Update(DLL_NAME, L"EncodeStr", DWORDtoString(hs.addr_EncodeStr));
	conf.Update(DLL_NAME, L"EncodeBuffer", DWORDtoString(hs.addr_EncodeBuffer));
	conf.Update(DLL_NAME, L"ProcessPacket", DWORDtoString(hs.addr_ProcessPacket));
	conf.Update(DLL_NAME, L"Decode1", DWORDtoString(hs.addr_Decode1));
	conf.Update(DLL_NAME, L"Decode2", DWORDtoString(hs.addr_Decode2));
	conf.Update(DLL_NAME, L"Decode4", DWORDtoString(hs.addr_Decode4));
	conf.Update(DLL_NAME, L"Decode8", DWORDtoString(hs.addr_Decode8));
	conf.Update(DLL_NAME, L"DecodeStr", DWORDtoString(hs.addr_DecodeStr));
	conf.Update(DLL_NAME, L"DecodeBuffer", DWORDtoString(hs.addr_DecodeBuffer));
	return true;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		LoadPacketConfig(hinstDLL);
		PacketHook(gHookSettings);
		//SavePacketConfig();
	}
	return TRUE;
}
