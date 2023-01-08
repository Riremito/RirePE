#include"../RirePE/MainGUI.h"

// メモ
void SetInfo(std::wstring wText) {
	Alice &a = GetMainGUI();
	a.SetText(EDIT_EXTRA, wText);
}

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

// format info
bool SetExtraInfo(Alice &a, std::vector<PacketData>& vpd, DWORD id) {
	for (auto &pd : vpd) {
		if (pd.id == id) {
			std::wstring wText;
			wText += L"[Basic]\r\n";
			wText += L"Status = " + GetPacketStatus(pd) + L"\r\n";
			wText += L"Type = " + GetPacketType(pd) + L"\r\n";
			wText += L"Return = " + QWORDtoString(pd.addr) + L"\r\n";
			wText += L"Length = " + std::to_wstring(pd.packet.size()) + L"\r\n";
			wText += L"\r\n";
			wText += L"[Format]\r\n";
			for (auto &pf : pd.format) {
			}
			a.SetText(EDIT_EXTRA, wText);
			return true;
		}
	}

	a.SetText(EDIT_EXTRA, L"no data");
	return false;
}

// log packet
bool UpdateLogger(PacketEditorMessage &pem, bool bBlock) {
	if (pem.header != SENDPACKET && pem.header != RECVPACKET) {
		return false;
	}

	Alice &a = GetMainGUI();

	std::wstring wType;
	if (pem.header == SENDPACKET) {
		wType = L"Send";
	}
	else if (pem.header == RECVPACKET) {
		wType = L"Recv";
	}

	a.ListView_AddItem(LISTVIEW_LOGGER, LV_TYPE, wType);
	a.ListView_AddItem(LISTVIEW_LOGGER, LV_ID, std::to_wstring(pem.id));
	a.ListView_AddItem(LISTVIEW_LOGGER, LV_LENGTH, std::to_wstring(pem.Binary.length));

	std::wstring wpacket = DatatoString(pem.Binary.packet, (pem.Binary.length > 1024) ? 1024 : pem.Binary.length, true);
	wpacket.erase(wpacket.begin(), wpacket.begin() + 5);
	if (!bBlock) {
		wpacket = L"@" + WORDtoString(*(WORD *)&pem.Binary.packet[0]) + wpacket;
	}
	else {
		wpacket = L"@" + WORDtoString(*(WORD *)&pem.Binary.packet[0]) + L" (Blocked)" + wpacket;
	}
	a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, wpacket);
	return true;
}

// raw packet from listview
bool SetRawPacket(Alice &a, MessageHeader type, std::wstring &text_packet) {
	if (text_packet.length() > 1024) {
		return false;
	}

	if (type == SENDPACKET) {
		a.SetText(EDIT_PACKET_SEND, text_packet);
		a.SetText(EDIT_PACKET_RECV, L"");
		return true;
	}

	if (type == RECVPACKET) {
		a.SetText(EDIT_PACKET_SEND, L"");
		a.SetText(EDIT_PACKET_RECV, text_packet);
		return true;
	}

	return false;
}

bool OnCreate(Alice &a) {
	a.ListView(LISTVIEW_LOGGER, 3, 3, (PE_WIDTH - 6), (PE_HEIGHT / 2 - 6));
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Type", 40);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"ID", 50);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Length", 50);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Packet", (PE_WIDTH - 180));
	a.TextArea(EDIT_EXTRA, 3, (PE_HEIGHT / 2), ((PE_WIDTH / 2) - 6), (PE_HEIGHT / 2 - 6));
	a.SetText(EDIT_EXTRA, L"Format View");
	a.ReadOnly(EDIT_EXTRA);
	a.CheckBox(CHECK_SEND, L"Send", (PE_WIDTH - 100), (PE_HEIGHT / 2 + 10), BST_CHECKED);
	a.CheckBox(CHECK_RECV, L"Recv", (PE_WIDTH - 50), (PE_HEIGHT / 2 + 10), BST_CHECKED);
	a.Button(BUTTON_CLEAR, L"Clear", (PE_WIDTH - 150), (PE_HEIGHT / 2 + 10));

	// sender
	a.EditBox(EDIT_PACKET_SEND, (PE_WIDTH / 2 + 3), (PE_HEIGHT / 2 + 50), L"CClientSocket::SendPacket", (PE_WIDTH / 2 - 110));
	a.EditBox(EDIT_PACKET_RECV, (PE_WIDTH / 2 + 3), (PE_HEIGHT / 2 + 70), L"CClientSocket::ProcessPacket", (PE_WIDTH / 2 -110));
	a.Button(BUTTON_SEND, L"SendPacket", (PE_WIDTH - 100), (PE_HEIGHT / 2 + 50));
	a.Button(BUTTON_RECV, L"RecvPacket", (PE_WIDTH - 100), (PE_HEIGHT / 2 + 70));
	a.CheckBox(CHECK_LOCK, L"Lock", (PE_WIDTH - 150), (PE_HEIGHT / 2 + 90));
	// debug
#ifdef PE_DEBUG
	a.Button(BUTTON_INC_SEND, L"+", (PE_WIDTH - 25), (PE_HEIGHT / 2 + 50));
	a.Button(BUTTON_INC_RECV, L"+", (PE_WIDTH - 25), (PE_HEIGHT / 2 + 70));
#endif
	PacketLogger(); // logger
	return true;
}

// 色々な処理
bool OnCommand(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == BUTTON_CLEAR) {
		ClearAll(); // logger
		a.ListView_Clear(LISTVIEW_LOGGER);
		return true;
	}

	if (nIDDlgItem == BUTTON_SEND) {
		PacketSender(a, SENDPACKET);
		return true;
	}

	if (nIDDlgItem == BUTTON_RECV) {
		PacketSender(a, RECVPACKET);
		return true;
	}

	// edit lock
	if (nIDDlgItem == CHECK_LOCK) {
		bool read_only = a.CheckBoxStatus(CHECK_LOCK);
		a.ReadOnly(EDIT_PACKET_SEND, read_only);
		a.ReadOnly(EDIT_PACKET_RECV, read_only);
		return true;
	}

	return true;
}

// ListView上で選択したパケットを入力欄にコピー
bool OnNotify(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == LISTVIEW_LOGGER) {
		std::wstring text_type;
		std::wstring text_id;
		std::wstring text_packet;
		std::wstring text_header;
		bool check = true;

		check &= a.ListView_Copy(LISTVIEW_LOGGER, LV_TYPE, text_type, false);
		check &= a.ListView_Copy(LISTVIEW_LOGGER, LV_ID, text_id, false);
		check &= a.ListView_Copy(LISTVIEW_LOGGER, LV_PACKET, text_packet, true);

		if (!check) {
			return false;
		}

		MessageHeader type = UNKNOWN;

		if (text_type.compare(L"Send") == 0) {
			type = SENDPACKET;
		}
		else if (text_type.compare(L"Recv") == 0) {
			type = RECVPACKET;
		}

		// raw packet
		if (!a.CheckBoxStatus(CHECK_LOCK)) {
			SetRawPacket(a, type, text_packet);
		}

		// format

		text_header = text_packet;
		text_header.erase(text_header.begin() + 5, text_header.end());

		DWORD id = _wtoi(text_id.c_str());

		if (text_type.compare(L"Send") == 0) {
			a.SetText(EDIT_SEND_HEADER, text_header);
			a.SetText(EDIT_RECV_HEADER, L"");
			SetExtraInfo(a, GetOutPacketFormat(), id);
			return true;
		}
		if (text_type.compare(L"Recv") == 0) {
			a.SetText(EDIT_SEND_HEADER, L"");
			a.SetText(EDIT_RECV_HEADER, text_header);
			SetExtraInfo(a, GetInPacketFormat(), id);
			return true;
		}

		return false;
	}
	return true;
}

// global main gui
Alice *global_a = NULL;
void SetMainGUI(Alice *ga) {
	global_a = ga;
}

Alice& GetMainGUI() {
	return *global_a;
}

// start gui
bool MainGUI(HINSTANCE hInstance) {
#ifdef _WIN64
	Alice a(L"PacketEditorClass64", L"Rire PE x64", PE_WIDTH, PE_HEIGHT, hInstance);
#else
	Alice a(L"PacketEditorClass", L"Rire PE x86", PE_WIDTH, PE_HEIGHT, hInstance);
#endif

	SetMainGUI(&a);
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.Run();
	a.Wait();
	return true;
}