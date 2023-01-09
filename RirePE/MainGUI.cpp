#include"../RirePE/MainGUI.h"

int global_header_size = 2; // default, 0 = raw
bool SetHeaderSize(Alice &a) {
	std::wstring wText = a.GetText(EDIT_HEADER_SIZE);
	int header_size = _wtoi(wText.c_str());

	// BYTE or WORD or DWORD
	if (header_size == 0 || header_size == 1 || header_size == 2 || header_size == 4) {
		global_header_size = header_size;
		return true;
	}

	return false;
}

int GetHeaderSize() {
	return global_header_size;
}

// 接続状態
void SetInfo(std::wstring wText) {
	Alice &a = GetMainGUI();
	a.SetText(STATIC_INFO, wText);
}

// ListViewの更新
bool UpdateLogger(PacketEditorMessage &pem, bool bBlock) {
	if (pem.header != SENDPACKET && pem.header != RECVPACKET) {
		return false;
	}

	Alice &a = GetMainGUI();

	std::wstring wType;
	if (pem.header == SENDPACKET) {
		if (!a.CheckBoxStatus(CHECK_SEND)) {
			return false;
		}
		wType = L"Send";
	}
	else if (pem.header == RECVPACKET) {
		if (!a.CheckBoxStatus(CHECK_RECV)) {
			return false;
		}
		wType = L"Recv";
	}

	a.ListView_AddItem(LISTVIEW_LOGGER, LV_TYPE, wType);
	a.ListView_AddItem(LISTVIEW_LOGGER, LV_ID, std::to_wstring(pem.id));
	a.ListView_AddItem(LISTVIEW_LOGGER, LV_LENGTH, std::to_wstring(pem.Binary.length));
	std::wstring wpacket = DatatoString(pem.Binary.packet, (pem.Binary.length > 1024) ? 1024 : pem.Binary.length, true);

	int header_size = GetHeaderSize();
	if (header_size <= pem.Binary.length) {
		if (header_size) {
			// remove header
			wpacket.erase(wpacket.begin(), wpacket.begin() + (header_size * 2 + (header_size - 1))); // XX YY
			// add header
			std::wstring header_text = L"@";
			if (header_size == 1) {
				header_text += BYTEtoString(pem.Binary.packet[0]);
			}
			else if (header_size == 2) {
				header_text += WORDtoString(*(WORD *)&pem.Binary.packet[0]);
			}
			else if (header_size == 4) {
				header_text += DWORDtoString(*(DWORD *)&pem.Binary.packet[0]);
			}

			if (!bBlock) {
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, header_text + wpacket);
			}
			else {
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, header_text + L" (Blocked)" + wpacket);
			}
		}
		// Raw
		else {
			if (!bBlock) {
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, wpacket);
			}
			else {
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, L"(Blocked) " + wpacket);
			}
		}
	}
	else {
		a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, L"(too short)" + wpacket);
	}
	return true;
}

// ListViewで選択中のPacketをセット
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
	a.ListView(LISTVIEW_LOGGER, 3, 3, (PE_WIDTH - 6), (PE_HEIGHT * 2 / 3 - 6));
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Type", 40);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"ID", 50);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Length", 50);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Packet", (PE_WIDTH - 180));


	a.StaticText(STATIC_INFO, L"Disconnected", 10, (PE_HEIGHT * 2 / 3 + 10));

	a.Button(BUTTON_OPEN_FORMATVIEW, L"Format View", 100, (PE_HEIGHT * 2 / 3 + 10), 100);
	a.StaticText(STATIC_HEADER_SIZE, L"Header Size:", 250, (PE_HEIGHT * 2 / 3 + 10));
	a.EditBox(EDIT_HEADER_SIZE, 330, (PE_HEIGHT * 2 / 3 + 10), L"2", 50);
	a.CheckBox(CHECK_HEADER_SIZE, L"Update", 390, (PE_HEIGHT * 2 / 3 + 10), BST_CHECKED);
	a.ReadOnly(EDIT_HEADER_SIZE);

	a.CheckBox(CHECK_SEND, L"Send", (PE_WIDTH - 100), (PE_HEIGHT * 2 / 3 + 10), BST_CHECKED);
	a.CheckBox(CHECK_RECV, L"Recv", (PE_WIDTH - 50), (PE_HEIGHT * 2 / 3 + 10), BST_CHECKED);
	a.Button(BUTTON_CLEAR, L"Clear", (PE_WIDTH - 150), (PE_HEIGHT * 2 / 3 + 10));

	// sender
	a.EditBox(EDIT_PACKET_SEND, 10, (PE_HEIGHT * 2 / 3 + 50), L"CClientSocket::SendPacket", (PE_WIDTH - 120));
	a.EditBox(EDIT_PACKET_RECV, 10, (PE_HEIGHT * 2 / 3 + 70), L"CClientSocket::ProcessPacket", (PE_WIDTH -120));
	a.Button(BUTTON_SEND, L"SendPacket", (PE_WIDTH - 100), (PE_HEIGHT * 2 / 3 + 50));
	a.Button(BUTTON_RECV, L"RecvPacket", (PE_WIDTH - 100), (PE_HEIGHT * 2 / 3 + 70));
	a.CheckBox(CHECK_LOCK, L"Lock", (PE_WIDTH - 150), (PE_HEIGHT * 2 / 3 + 90));
	// debug
#ifdef PE_DEBUG
	a.Button(BUTTON_INC_SEND, L"+", (PE_WIDTH - 25), (PE_HEIGHT * 2 / 3 + 50));
	a.Button(BUTTON_INC_RECV, L"+", (PE_WIDTH - 25), (PE_HEIGHT * 2 / 3 + 70));
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

	// header size
	if (nIDDlgItem == CHECK_HEADER_SIZE) {
		bool read_only = a.CheckBoxStatus(nIDDlgItem);
		if (read_only && !SetHeaderSize(a)) {
			return true;
		}
		a.ReadOnly(EDIT_HEADER_SIZE, read_only);
		return true;
	}
	// edit lock
	if (nIDDlgItem == CHECK_LOCK) {
		bool read_only = a.CheckBoxStatus(nIDDlgItem);
		a.ReadOnly(EDIT_PACKET_SEND, read_only);
		a.ReadOnly(EDIT_PACKET_RECV, read_only);
		return true;
	}

	if (nIDDlgItem == BUTTON_OPEN_FORMATVIEW) {
		OpenFormatGUI();
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
			SetExtraInfo(GetOutPacketFormat(), id);
			return true;
		}
		if (text_type.compare(L"Recv") == 0) {
			SetExtraInfo(GetInPacketFormat(), id);
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

// 終了処理
LRESULT CALLBACK ExitCallback(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
	if (Msg == WM_DESTROY) {
		// format view
		HWND sub_hwnd = FVGet();
		if (sub_hwnd) {
			CloseWindow(sub_hwnd);
			DestroyWindow(sub_hwnd);
		}
		// 強制終了
		ExitProcess(0);
	}
	return 0;
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
	a.SetCallback(ExitCallback, Alice::CT_CALL);
	a.Run();
	InitFormatGUI(hInstance); // no lock
	a.Wait(); // lock
	return true;
}