#include"../Share/Simple/Simple.h"
#include"../Packet/PacketHook.h"
#include"../Packet/PacketLogging.h"
#include"../RirePE/RirePE.h"


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
	// high version mode (CInPacket), TODO
	std::wstring wHighVersionMode;
	if (conf.Read(DLL_NAME, L"HIGH_VERSION_MODE", wHighVersionMode) && _wtoi(wHighVersionMode.c_str())) {
		hs.high_version_mode = true;
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


int target_pid = 0;
std::wstring GetPipeNameLogger() {
	if (target_pid) {
		return PE_LOGGER_PIPE_NAME + std::to_wstring(target_pid);
	}
	return PE_LOGGER_PIPE_NAME;
}

std::wstring GetPipeNameSender() {
	if (target_pid) {
		return PE_SENDER_PIPE_NAME + std::to_wstring(target_pid);
	}
	return PE_SENDER_PIPE_NAME;
}

bool RunRirePE(HookSettings &hs) {
	std::wstring wDir;
	if (GetDir(wDir, hs.hinstDLL)) {
		std::wstring param = std::to_wstring(target_pid) + L" MapleStoryClass";
#ifndef _WIN64
		ShellExecuteW(NULL, NULL, (wDir + L"\\RirePE.exe").c_str(), param.c_str(), wDir.c_str(), SW_SHOW);
#else
		ShellExecuteW(NULL, NULL, (wDir + L"\\RirePE64.exe").c_str(), param.c_str(), wDir.c_str(), SW_SHOW);
#endif
	}

	StartPipeClient();
	RunPacketSender();
	return true;
}

bool PipeStartup(HookSettings &hs) {
	target_pid = GetCurrentProcessId();
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)RunRirePE, &hs, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}

bool PacketHook(HookSettings &hs) {
	PipeStartup(hs);
	// use thread, DllMain sometimes causes timeout
	if (hs.use_thread) {
		LPTHREAD_START_ROUTINE thread_func = hs.use_addr ? (LPTHREAD_START_ROUTINE)PacketHook_Conf : (LPTHREAD_START_ROUTINE)PacketHook_Thread;
		HANDLE hThread = CreateThread(NULL, NULL, thread_func, &hs, NULL, NULL);
		if (hThread) {
			CloseHandle(hThread);
		}
		return true;
	}
	// use conf
	if (hs.use_addr) {
		PacketHook_Conf(hs);
		return true;
	}
	// aob scan mode (default)
	PacketHook_Thread(hs);
	return true;
}


/*
	Packet.dll
		load config.
		run RirePE.exe.
		create pipe.
		hook functions. (aob or conf)
		send data to RirePE.exe from hooks.
	RirePE.exe
		log packets.
*/
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		LoadPacketConfig(hinstDLL);
		PacketHook(gHookSettings);
		//SavePacketConfig();
	}
	return TRUE;
}
