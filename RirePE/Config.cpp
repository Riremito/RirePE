#include"../RirePE/MainGUI.h"

#ifndef _WIN64
#define EXE_NAME L"RirePE"
#else
#define EXE_NAME L"RirePE64"
#endif

#define CONF_HEADER_SIZE L"HeaderSize"
#define CONF_IGNORE_SEND L"IgnoreSend"
#define CONF_IGNORE_RECV L"IgnoreRecv"

bool LoadConfig() {
	Config conf(EXE_NAME".ini");

	std::wstring wConfig_HeaderSize, wConfig_IgnoreSend, wConfig_IgnoreRecv;

	if (conf.Read(EXE_NAME, CONF_HEADER_SIZE, wConfig_HeaderSize)) {
		int header_size = _wtoi(wConfig_HeaderSize.c_str());
		SetHeaderSize(header_size);
	}

	if (conf.Read(EXE_NAME, CONF_IGNORE_SEND, wConfig_IgnoreSend)) {
		LoadFilterList(SENDPACKET, IGNORE_PACKET, wConfig_IgnoreSend);
	}
	
	if (conf.Read(EXE_NAME, CONF_IGNORE_RECV, wConfig_IgnoreRecv)) {
		LoadFilterList(RECVPACKET, IGNORE_PACKET, wConfig_IgnoreRecv);
	}
	return true;
}

bool SaveConfig() {
	Config conf(EXE_NAME".ini");

	std::wstring wConfig_HeaderSize, wConfig_IgnoreSend, wConfig_IgnoreRecv;

	wConfig_HeaderSize = std::to_wstring(GetHeaderSize());
	conf.Update(EXE_NAME, CONF_HEADER_SIZE, wConfig_HeaderSize);

	GetFilterList(SENDPACKET, IGNORE_PACKET, wConfig_IgnoreSend);
	GetFilterList(RECVPACKET, IGNORE_PACKET, wConfig_IgnoreRecv);

	conf.Update(EXE_NAME, CONF_IGNORE_SEND, wConfig_IgnoreSend);
	conf.Update(EXE_NAME, CONF_IGNORE_RECV, wConfig_IgnoreRecv);
	return true;
}