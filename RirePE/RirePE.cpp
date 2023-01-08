#include<Windows.h>
#include"../Share/Simple/Simple.h"
#include"RirePE.h"
/*

#define FILTER_FILE "Filter.txt"
// UTF16 to SJIS
bool ShiftJIStoUTF8(std::wstring utf16, std::string &sjis) {
	// UTF16へ変換する際の必要なバイト数を取得
	int len = WideCharToMultiByte(CP_ACP, 0, utf16.c_str(), -1, 0, 0, 0, 0);
	if (!len) {
		return false;
	}

	std::vector<BYTE> b(len + 1);

	if (!WideCharToMultiByte(CP_ACP, 0, utf16.c_str(), -1, (char *)&b[0], len, 0, 0)) {
		return false;
	}

	sjis = std::string((char *)&b[0]);
	return true;
}

// ログインパケットのパスワードを消す
bool RemovePassword(PacketData &pd) {
	if (pd.packet.size() < 2) {
		return false;
	}

	if (*(WORD *)&pd.packet[0] != 0x0069) {
		return false;
	}

	for (size_t i = 0; i < pd.format.size(); i++) {
		if (pd.format[i].type == ENCODESTR) {
			for (size_t j = 0; j < *(WORD *)&pd.packet[pd.format[i].pos]; j++) {
				*(BYTE *)&pd.packet[pd.format[i].pos + 2 + j] = '*';
			}
		}
	}

	return true;
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
bool BYTEtoShiftJIS(BYTE *text, int len, std::string &sjis) {
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
*/