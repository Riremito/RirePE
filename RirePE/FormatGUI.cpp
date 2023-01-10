#include"../RirePE/MainGUI.h"

Alice *global_fv = NULL;
HINSTANCE hFVInstance = NULL;

HWND FVGet() {
	if (!global_fv) {
		return 0;
	}
	if (!global_fv->IsAlive()) {
		return 0;
	}
	return global_fv->GetMainHWND();
}

bool FVOnCreate(Alice &fv) {
	fv.ListView(FV_LISTVIEW_FORMAT, 3, 3, (FV_WIDTH - 6), (FV_HEIGHT / 2 - 6));
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Index", 60);
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Return", 120);
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Position", 60);
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Type", 100);
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Size", 50);
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Data", 300);
	fv.ListView_AddHeader(FV_LISTVIEW_FORMAT, L"Int", 80);
	// status
	fv.TextArea(FV_EDIT_INFO, 3, (FV_HEIGHT / 2), (FV_WIDTH - 6), (FV_HEIGHT / 2 - 6));
	fv.ReadOnly(FV_EDIT_INFO);
	return true;
}

bool FVOnCommand(Alice &fv, int nIDDlgItem) {
	return true;
}

bool FVOnNotify(Alice &fv, int nIDDlgItem) {
	if (nIDDlgItem == FV_LISTVIEW_FORMAT) {

	}
	return true;
}

bool OpenFormatGUI() {
	if (global_fv) {
		// dead
		if (!global_fv->IsAlive()) {
			delete global_fv;
			global_fv = NULL;
		}
		// already opened
		else {
			return true;
		}
	}

	if (global_fv) {
		return true;
	}

	global_fv = new Alice(L"FormatClass", L"Format View", FV_WIDTH, FV_HEIGHT, hFVInstance);
	global_fv->SetOnCreate(FVOnCreate);
	global_fv->SetOnCommand(FVOnCommand);
	global_fv->SetOnNotify(FVOnNotify);
	global_fv->Run();
	return true;
}

// start gui
bool InitFormatGUI(HINSTANCE hInstance) {
	hFVInstance = hInstance;
	//OpenFormatGUI();
	return true;
}

// format
std::wstring GetPacketStatus(PacketData &pd) {
	if (pd.status == 1) {
		return L"OK";
	}
	if (pd.status == -1) {
		return L"NG";
	}
	if (pd.status == 0) {
		return L"Wait";
	}
	return L"Error";
}

std::wstring GetPacketType(PacketData &pd) {
	if (pd.type == SENDPACKET) {
		return L"SendPacket";
	}
	if (pd.type == RECVPACKET) {
		return L"RecvPacket";
	}
	return L"Error";
}

std::wstring GetFormatType(PacketFormat &pf) {
	switch (pf.type) {
	case ENCODEHEADER:
	case DECODEHEADER:
	case TENVI_ENCODE_HEADER_1:
	case TENVI_DECODE_HEADER_1:
	{
		return L"HEADER";
	}
	case ENCODE1:
	case DECODE1:
	{
		return L"BYTE";
	}
	case ENCODE2:
	case DECODE2:
	{
		return L"WORD";
	}
	case ENCODE4:
	case DECODE4:
	{
		return L"DWORD";
	}
	case ENCODE8:
	case DECODE8:
	{
		return L"QWORD";
	}
	case ENCODESTR:
	case DECODESTR:
	{
		return L"Str(" + std::to_wstring(pf.size - sizeof(WORD)) + L")";
	}
	case ENCODEBUFFER:
	case DECODEBUFFER:
	{
		return L"Buffer(" + std::to_wstring(pf.size) + L")";
	}
	// TENVI
	case TENVI_ENCODE_WSTR_1:
	case TENVI_DECODE_WSTR_1:
	{
		return L"WStr1(" + std::to_wstring((pf.size - sizeof(BYTE)) / 2) + L")";
	}
	case TENVI_ENCODE_WSTR_2:
	case TENVI_DECODE_WSTR_2:
	{
		return L"WStr2(" + std::to_wstring((pf.size - sizeof(WORD)) / 2) + L")";
	}
	// エラー処理
	case NOTUSED: {
		return L"Not Used(" + std::to_wstring(pf.size) + L")";
	}
	case UNKNOWNDATA: {
		return L"Unknown(" + std::to_wstring(pf.size) + L")";
	}
	case WHEREFROM: {
		return L"Not Encoded(" + std::to_wstring(pf.size) + L")";
	}
	}
	return L"Error";
}

// ShiftJIS to UTF16
bool ShiftJIStoUTF8(std::string sjis, std::wstring &utf16) {
	try {
		// UTF16へ変換する際の必要なバイト数を取得
		int len = MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, 0, 0);
		if (!len) {
			return false;
		}

		// UTF16へ変換
		std::vector<BYTE> b((len + 1) * sizeof(WORD));
		if (!MultiByteToWideChar(CP_ACP, 0, sjis.c_str(), -1, (WCHAR *)&b[0], len)) {
			return false;
		}

		utf16 = std::wstring((WCHAR *)&b[0]);
		return true;
	}
	catch (...) {
		return false;
	}

	return true;
}

// バイト配列からShiftJIS文字列を取得
bool BYTEtoShiftJIS(BYTE *text, size_t len, std::string &sjis) {
	try {
		std::vector<BYTE> b(len + 1);
		for (size_t i = 0; i < len; i++) {
			b[i] = text[i];
		}
		sjis = std::string((char *)&b[0]);
	}
	catch (...) {
		return false;
	}
	return true;
}

std::wstring GetFormatData(PacketData &pd, PacketFormat &pf) {
	switch (pf.type) {
	case ENCODEHEADER:
	case DECODEHEADER:
	{
		return L"@" + WORDtoString(*(WORD *)&pd.packet[pf.pos]);
	}
	case ENCODE1:
	case DECODE1:
	{
		return BYTEtoString(pd.packet[pf.pos]);
	}
	case ENCODE2:
	case DECODE2:
	{
		return WORDtoString(*(WORD *)&pd.packet[pf.pos]);
	}
	case ENCODE4:
	case DECODE4:
	{
		return DWORDtoString(*(DWORD *)&pd.packet[pf.pos]);
	}
	case ENCODE8:
	case DECODE8:
	{
		return DWORDtoString(*(DWORD *)&pd.packet[pf.pos + sizeof(DWORD)]) + DWORDtoString(*(DWORD *)&pd.packet[pf.pos]);
	}
	case ENCODESTR:
	case DECODESTR:
	{
		size_t len = *(WORD *)&pd.packet[pf.pos];
		std::string sjis;
		std::wstring utf16;
		if (BYTEtoShiftJIS(&pd.packet[pf.pos + sizeof(WORD)], len, sjis) && ShiftJIStoUTF8(sjis, utf16)) {
			return L"\"" + utf16 + L"\"";
		}
		return DatatoString(&pd.packet[pf.pos], pf.size + sizeof(WORD));
	}
	case ENCODEBUFFER:
	case DECODEBUFFER:
	{
		return DatatoString(&pd.packet[pf.pos], pf.size);
	}
	// TENVI
	case TENVI_ENCODE_HEADER_1:
	case TENVI_DECODE_HEADER_1:
	{
		return L"@" + BYTEtoString(pd.packet[pf.pos]);
	}
	case TENVI_ENCODE_WSTR_1:
	case TENVI_DECODE_WSTR_1:
	{
		std::wstring utf16 = std::wstring((WCHAR *)&pd.packet[pf.pos + sizeof(BYTE)], pd.packet[pf.pos]);
		return L"L\"" + utf16 + L"\"";
	}
	case TENVI_ENCODE_WSTR_2:
	case TENVI_DECODE_WSTR_2:
	{
		std::wstring utf16 = std::wstring((WCHAR *)&pd.packet[pf.pos + sizeof(WORD)], *(WORD *)&pd.packet[pf.pos]);
		return L"L\"" + utf16 + L"\"";
	}
	// エラー処理
	case NOTUSED:
	case UNKNOWNDATA:
	case WHEREFROM: {
		return DatatoString(&pd.packet[pf.pos], pf.size, true);
	}
	default: {
		break;
	}
	}
	return L"Error";
}

bool GetIntData(PacketData &pd, PacketFormat &pf, int &val) {
	switch (pf.type) {
	case ENCODE1:
	case DECODE1:
	{
		val = (int)pd.packet[pf.pos];
		return true;
	}
	case ENCODE2:
	case DECODE2:
	{
		val = (int)*(WORD *)&pd.packet[pf.pos];
		return true;
	}
	case ENCODE4:
	case DECODE4:
	{
		val = (int)(*(DWORD *)&pd.packet[pf.pos]);
		return true;
	}
	default: {
		break;
	}
	}
	return false;
}

std::wstring GetAddress(ULONGLONG uAddr) {
	if (uAddr & 0xFFFFFFFF00000000) {
		return DWORDtoString((DWORD)(uAddr >> 32)) + DWORDtoString((DWORD)uAddr);
	}
	return DWORDtoString((DWORD)uAddr);
}

bool UpdateFV(PacketData &pd) {
	if (global_fv) {
		// dead
		if (!global_fv->IsAlive()) {
			return false;
		}
	}
	else {
		// not opened
		return false;
	}

	// reset
	global_fv->ListView_Clear(FV_LISTVIEW_FORMAT);

	int count = 0;
	size_t prev_pos = 0;
	for (auto &pf : pd.format) {
		if (pf.pos < prev_pos) {
			break;
		}
		prev_pos = pf.pos;

		global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_INDEX, std::to_wstring(count));
		global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_RETURN, GetAddress(pf.addr));
		global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_POSITION, L"+" + std::to_wstring(pf.pos));
		global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_TYPE, GetFormatType(pf));
		global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_SIZE, std::to_wstring(pf.size));
		global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_DATA, GetFormatData(pd, pf));
		int val = 0;
		if (GetIntData(pd, pf, val)) {
			global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_DATA_INT, std::to_wstring(val));
		}
		else {
			global_fv->ListView_AddItem(FV_LISTVIEW_FORMAT, FV_LV_DATA_INT, L"");
		}

		count++;
	}
	return true;
}

// TextArea
bool SetExtraInfo(std::vector<PacketData>& vpd, DWORD id) {
	if (global_fv) {
		// dead
		if (!global_fv->IsAlive()) {
			return false;
		}
	}
	else {
		// not opened
		return false;
	}

	for (auto &pd : vpd) {
		if (pd.id == id) {
			std::wstring wText;
			wText += L"[Basic]\r\n";
			wText += L"Status = " + GetPacketStatus(pd) + L"\r\n";
			wText += L"Type = " + GetPacketType(pd) + L"\r\n";
			wText += L"Return = " + GetAddress(pd.addr) + L"\r\n";
			wText += L"Length = " + std::to_wstring(pd.packet.size()) + L"\r\n";

			if (pd.packet.size() == 0) {
				global_fv->SetText(FV_EDIT_INFO, L"size is 0 ?");
				return false;
			}

			wText += L"\r\n";
			wText += L"[Format]\r\n";
			int count = 0;
			size_t prev_pos = 0;
			for (auto &pf : pd.format) {
				if (pf.pos < prev_pos) {
					wText += L"Something broken\r\n";
					break;
				}
				prev_pos = pf.pos;

				wText += L"<" + std::to_wstring(count) + L">\r\n";
				wText += L"Position = +" + std::to_wstring(pf.pos) + L"\r\n";
				wText += L"Type = " + GetFormatType(pf) + L"\r\n";
				// Return Address
				//if (show_return) {
					wText += L"Return = " + GetAddress(pf.addr) + L"\r\n";
				//}
				wText += L"Data = " + GetFormatData(pd, pf) + L"\r\n";
				// 整数値
				//if (show_int) {
					int val = 0;
					if (GetIntData(pd, pf, val)) {
						wText += L"Int = " + std::to_wstring(val) + L"\r\n";
					}
				//}
				//if (show_raw) {
					wText += L"Raw = " + DatatoString(&pd.packet[pf.pos], pf.size, true) + L"\r\n";
				//}
				count++;
			}

			// オリジナルデータ
			//if (show_raw) {
				wText += L"\r\n";
				wText += L"[Raw]\r\n";
				wText += L"Raw = " + DatatoString(&pd.packet[0], pd.packet.size(), true) + L"\r\n";
			//}

			global_fv->SetText(FV_EDIT_INFO, wText);
			UpdateFV(pd);
			return true;
		}
	}

	global_fv->SetText(FV_EDIT_INFO, L"no data");
	return false;
}