﻿#include"../RirePE/MainGUI.h"

bool CheckLetter(std::wstring wText) {
	static std::wstring gLetterList = L"0123456789ABCDEFabcdef ?*";

	for (size_t i = 0; i < wText.length(); i++) {
		if (gLetterList.find(wText.at(i)) == std::wstring::npos) {
			return false;
		}
	}

	return true;
}

bool StringtoBYTE(std::wstring wText, std::vector<BYTE> &vData) {
	if (wText.length() % 2) {
		return false;
	}

	vData.clear();
	for (size_t i = 0; i < wText.length(); i += 2) {
		BYTE high = 0x00;
		BYTE low = 0x00;

		if (wText.at(i) == L'*' || wText.at(i) == L'?') {
			high = rand() % 0x10;
		}
		else {
			if (L'0' <= wText.at(i) && wText.at(i) <= '9') {
				high = wText.at(i) - L'0';
			}
			else if (L'A' <= wText.at(i) && wText.at(i) <= 'F') {
				high = wText.at(i) - L'A' + 0x0A;
			}
			else if (L'a' <= wText.at(i) && wText.at(i) <= 'f') {
				high = wText.at(i) - L'a' + 0x0A;
			}
			else {
				return false;
			}
		}

		if (wText.at(i + 1) == L'*' || wText.at(i + 1) == L'?') {
			low = rand() % 0x10;
		}
		else {
			if (L'0' <= wText.at(i + 1) && wText.at(i + 1) <= '9') {
				low = wText.at(i + 1) - L'0';
			}
			else if (L'A' <= wText.at(i + 1) && wText.at(i + 1) <= 'F') {
				low = wText.at(i + 1) - L'A' + 0x0A;
			}
			else if (L'a' <= wText.at(i + 1) && wText.at(i + 1) <= 'f') {
				low = wText.at(i + 1) - L'a' + 0x0A;
			}
			else {
				return false;
			}
		}

		vData.push_back((high << 4) + low);
	}

	return true;
}

bool PacketSender(Alice &a, MessageHeader type, std::wstring raw) {
	PipeClient pc(GetPipeNameSender());
	if (!pc.Run()) {
		return false;
	}

	std::wstring wpacket;

	if (raw.length()) {
		wpacket = raw;
	}
	else {
		wpacket = a.GetText((type == SENDPACKET) ? EDIT_PACKET_SEND : EDIT_PACKET_RECV);
	}

	std::wstring wpacket_fmt;
	size_t header_size = (size_t)GetHeaderSize();

	if (header_size) {
		if (wpacket.length() < header_size * 2 +1) {
			return false;
		}

		// header check
		if (wpacket.find(L"@") != 0) {
			return false;
		}

		// remove header tag (@)
		wpacket.erase(wpacket.begin(), wpacket.begin() + 1);
	}

	if (header_size == 0) {
		header_size = 1;
	}

	// remove space
	for (size_t i = 0; i < wpacket.length(); i++) {
		if (!CheckLetter(wpacket)) {
			return false;
		}

		if (wpacket.at(i) == L' ') {
			continue;
		}

		wpacket_fmt.push_back(wpacket.at(i));
	}

	if (wpacket_fmt.length() < header_size * 2) {
		return false;
	}

	if (wpacket_fmt.length() % 2) {
		return false;
	}

	std::wstring wHeader;

	if (header_size == 2) {
		wHeader.push_back(wpacket_fmt.at(2));
		wHeader.push_back(wpacket_fmt.at(3));
		wHeader.push_back(wpacket_fmt.at(0));
		wHeader.push_back(wpacket_fmt.at(1));
		wpacket_fmt.erase(wpacket_fmt.begin(), (wpacket_fmt.begin() + (header_size * 2)));
		wpacket_fmt = wHeader + wpacket_fmt;
	}
	else if (header_size == 4) {
		wHeader.push_back(wpacket.at(6));
		wHeader.push_back(wpacket.at(7));
		wHeader.push_back(wpacket.at(4));
		wHeader.push_back(wpacket.at(5));
		wHeader.push_back(wpacket.at(2));
		wHeader.push_back(wpacket.at(3));
		wHeader.push_back(wpacket.at(0));
		wHeader.push_back(wpacket.at(1));
		wpacket_fmt.erase(wpacket_fmt.begin(), (wpacket_fmt.begin() + (header_size * 2)));
		wpacket_fmt = wHeader + wpacket_fmt;
	}

	std::vector<BYTE> packet;

	if (!StringtoBYTE(wpacket_fmt, packet)) {
		return false;
	}

	if (packet.size() < header_size) {
		return false;
	}

	union {
		BYTE *b;
		PacketEditorMessage *pcm;
	};

	ULONG_PTR data_length = sizeof(PacketEditorMessage) - 1 + packet.size();
	b = new BYTE[data_length];

	if (!b) {
		return false;
	}

	memset(pcm, 0, sizeof(data_length));
	pcm->header = type;
	pcm->Binary.length = (DWORD)packet.size();
	memcpy_s(&pcm->Binary.packet[0], packet.size(), &packet[0], packet.size());
	pc.Send((BYTE *)pcm, data_length);

	delete[] b;

	return true;
}