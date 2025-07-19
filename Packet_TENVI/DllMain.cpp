#include"TV_PacketHook.h"
#include"TV_PacketLogging.h"

TenviHookConfig gthc = {};

bool InitializeConfig(TenviHookConfig &thc) {

	switch (thc.region) {
	case TENVI_JP:
	{
		thc.uSendPacket = 0x0055E91B;
		thc.uOutPacket = 0x0055F36D;
		thc.uEncode1 = 0x0040F287;
		thc.uEncode2 = 0x00402FFD;
		thc.uEncode4 = 0x00403025;
		thc.uEncode8 = 0;
		thc.uEncodeFloat = 0x0041414B;
		thc.uEncodeStrW1 = 0x0040F435;
		thc.uEncodeStrW2 = 0;
		thc.uProcessPacket = 0x0055E557;
		thc.uDecodeHeader = 0x0055F357;
		thc.uDecode1 = 0x00402EFE;
		thc.uDecode2 = 0x00402F30;
		thc.uDecode4 = 0x00402F63;
		thc.uDecode8 = 0x00402FC7;
		thc.uDecodeFloat = 0x00402F95;
		thc.uDecodeStrW1 = 0x0045BBCD;
		thc.uDecodeStrW2 = 0x0040921A;
		thc.uClientSocketBase = 0x006DB3B8;
		thc.uClientSocketOffset = 0x160;
		return true;
	}
	case TENVI_KR:
	{
		thc.uSendPacket = 0x005CBA0F;
		thc.uOutPacket = 0x005CBAD4;
		thc.uEncode1 = 0x0040705B;
		thc.uEncode2 = 0x00402249;
		thc.uEncode4 = 0x00402271;
		thc.uEncode8 = 0x00402297;
		thc.uEncodeFloat = 0;
		thc.uEncodeStrW1 = 0x004143DC;
		thc.uEncodeStrW2 = 0;
		thc.uProcessPacket = 0;
		thc.uDecodeHeader = 0x005CBABE;
		thc.uDecode1 = 0x0040214A;
		thc.uDecode2 = 0x0040217C;
		thc.uDecode4 = 0x004021AF;
		thc.uDecode8 = 0x00402213;
		thc.uDecodeFloat = 0x004021E1;
		thc.uDecodeStrW1 = 0x0044C2BE;
		thc.uDecodeStrW2 = 0x0047B50E;
		return true;
	}
	case TENVI_KRX:
	{
		thc.uSendPacket = 0;
		thc.uOutPacket = 0;
		thc.uEncode1 = 0;
		thc.uEncode2 = 0;
		thc.uEncode4 = 0;
		thc.uEncode8 = 0;
		thc.uEncodeFloat = 0;
		thc.uEncodeStrW1 = 0;
		thc.uEncodeStrW2 = 0;
		thc.uProcessPacket = 0;
		thc.uDecodeHeader = 0;
		thc.uDecode1 = 0;
		thc.uDecode2 = 0;
		thc.uDecode4 = 0;
		thc.uDecodeStrW1 = 0;
		thc.uDecodeStrW2 = 0;
		thc.uDecodeFloat = 0;
		return true;
	}
	case TENVI_HK:
	{
		thc.uSendPacket = 0x005AC927;
		thc.uOutPacket = 0x005AC9EC;
		thc.uEncode1 = 0x00417D30;
		thc.uEncode2 = 0x00402262;
		thc.uEncode4 = 0x0040228A;
		thc.uEncode8 = 0;
		thc.uEncodeFloat = 0;
		thc.uEncodeStrW1 = 0x0040FC19;
		thc.uEncodeStrW2 = 0;
		thc.uProcessPacket = 0;
		thc.uDecodeHeader = 0x005AC9D6;
		thc.uDecode1 = 0x00402163;
		thc.uDecode2 = 0x00402195;
		thc.uDecode4 = 0x004021C8;
		thc.uDecode8 = 0x0040222C;
		thc.uDecodeFloat = 0x004021FA;
		thc.uDecodeStrW1 = 0x0043B921;
		thc.uDecodeStrW2 = 0x00469777;
		return true;
	}
	case TENVI_CN:
	{
		thc.uSendPacket = 0x0056AADB;
		thc.uOutPacket = 0x0056ABA0;
		thc.uEncode1 = 0x0040EEB6;
		thc.uEncode2 = 0x0040346A;
		thc.uEncode4 = 0x00403492;
		thc.uEncode8 = 0x004034B8;
		thc.uEncodeFloat = 0;
		thc.uEncodeStrW1 = 0x00413ECC;
		thc.uEncodeStrW2 = 0x00496239;
		thc.uProcessPacket = 0;
		thc.uDecodeHeader = 0x0056AB8A;
		thc.uDecode1 = 0x0040336B;
		thc.uDecode2 = 0x0040339D;
		thc.uDecode4 = 0x004033D0;
		thc.uDecode8 = 0x00403434;
		thc.uDecodeFloat = 0x00403402;
		thc.uDecodeStrW1 = 0x0045CB52;
		thc.uDecodeStrW2 = 0x00408EEF;
		return true;
	}
	default:
	{
		break;
	}
	}

	return false;
}

TenviRegion getRegion(std::wstring wRegion) {
	if (wRegion.compare(L"JP") == 0) {
		return TENVI_JP;
	}
	if (wRegion.compare(L"KR") == 0) {
		return TENVI_KR;
	}
	if (wRegion.compare(L"KRX") == 0) {
		return TENVI_KRX;
	}
	if (wRegion.compare(L"HK") == 0) {
		return TENVI_HK;
	}
	if (wRegion.compare(L"CN") == 0) {
		return TENVI_CN;
	}

	return TENVI_JP;
}

#define DLL_NAME_TV L"Packet_TENVI"

bool LoadPacketConfig(HINSTANCE hinstDLL, TenviHookConfig &thc) {
	Config conf(INI_FILE_NAME, hinstDLL);
	thc.hinstDLL = hinstDLL;
	thc.region = TENVI_JP;

	std::wstring wRegion;
	if (conf.Read(DLL_NAME_TV, L"REGION", wRegion)) {
		thc.region = getRegion(wRegion);
	}

	std::wstring wDebugMode;
	if (conf.Read(DLL_NAME_TV, L"DEBUG_MODE", wDebugMode) && _wtoi(wDebugMode.c_str())) {
		thc.debug_mode = true;
	}

	return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		LoadPacketConfig(hinstDLL, gthc);
		InitializeConfig(gthc);
		TV_RunRirePE(gthc);
		PacketHookConf_TV(gthc);
	}
	return TRUE;
}
