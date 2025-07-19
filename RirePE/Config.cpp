#include"../RirePE/MainGUI.h"

#define CONF_HEADER_SIZE L"HeaderSize"
#define CONF_IGNORE_SEND L"IgnoreSend"
#define CONF_IGNORE_RECV L"IgnoreRecv"

PESettings gSettings = {};
bool LoadConfig() {
	PESettings &ps = gSettings;
	Config conf(INI_FILE_NAME);

	ps.header_size = 2; // default

	std::wstring wDebugMode;
	if (conf.Read(EXE_NAME, L"DEBUG_MODE", wDebugMode) && _wtoi(wDebugMode.c_str())) {
		ps.debug_mode = true;
	}
	// inlined Decode1
	std::wstring wTHMS88Mode;
	if (conf.Read(EXE_NAME, L"THMS88_MODE", wTHMS88Mode) && _wtoi(wTHMS88Mode.c_str())) {
		ps.thms88_mode = true;
	}

	std::wstring wConfig_HeaderSize, wConfig_IgnoreSend, wConfig_IgnoreRecv;
	if (conf.Read(EXE_NAME, CONF_HEADER_SIZE, wConfig_HeaderSize)) {
		int header_size = _wtoi(wConfig_HeaderSize.c_str());
		SetHeaderSize(header_size);
	}

	/*
	if (conf.Read(EXE_NAME, CONF_IGNORE_SEND, wConfig_IgnoreSend)) {
		LoadFilterList(SENDPACKET, IGNORE_PACKET, wConfig_IgnoreSend);
	}
	
	if (conf.Read(EXE_NAME, CONF_IGNORE_RECV, wConfig_IgnoreRecv)) {
		LoadFilterList(RECVPACKET, IGNORE_PACKET, wConfig_IgnoreRecv);
	}
	*/

	SetGlobalSettings(ps);
	return true;
}

bool SaveConfig() {
	/*
	Config conf(INI_FILE_NAME);

	std::wstring wConfig_HeaderSize, wConfig_IgnoreSend, wConfig_IgnoreRecv;

	wConfig_HeaderSize = std::to_wstring(GetHeaderSize());
	conf.Update(EXE_NAME, CONF_HEADER_SIZE, wConfig_HeaderSize);

	GetFilterList(SENDPACKET, IGNORE_PACKET, wConfig_IgnoreSend);
	GetFilterList(RECVPACKET, IGNORE_PACKET, wConfig_IgnoreRecv);

	conf.Update(EXE_NAME, CONF_IGNORE_SEND, wConfig_IgnoreSend);
	conf.Update(EXE_NAME, CONF_IGNORE_RECV, wConfig_IgnoreRecv);
	*/
	return true;
}