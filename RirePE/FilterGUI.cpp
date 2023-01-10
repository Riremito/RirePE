#include"../RirePE/MainGUI.h"

typedef struct {
	MessageHeader packet;
	FilterType filter;
	DWORD header;
	int header_size;
} PacketFilter;

std::vector<PacketFilter> filter_list;

Alice *global_ig = NULL;
HINSTANCE hIGInstance = NULL;

HWND IGGet() {
	if (!global_ig) {
		return 0;
	}
	if (!global_ig->IsAlive()) {
		return 0;
	}
	return global_ig->GetMainHWND();
}

bool SetFilterHeader(MessageHeader type, std::wstring wHeader) {
	if (!IGGet()) {
		return false;
	}

	if (wHeader.size() < (size_t)GetHeaderSize() * 2 + 1) {
		return false;
	}

	if (wHeader.at(0) != L'@') {
		return false;
	}

	size_t pos = wHeader.find(L" ");
	if (pos != std::wstring::npos) {
		wHeader.erase(wHeader.begin() + pos, wHeader.end());
	}

	if (type == SENDPACKET) {
		global_ig->SetText(IG_EDIT_HEADER_SEND, wHeader);
		return true;
	}

	if (type == RECVPACKET) {
		global_ig->SetText(IG_EDIT_HEADER_RECV, wHeader);
		return true;
	}

	return false;
}

bool CheckFilter(PacketEditorMessage &pem, FilterType &ft) {
	int header_size = GetHeaderSize();


	if (pem.Binary.length < (DWORD)header_size) {
		return false;
	}

	DWORD header = 0;
	switch (header_size) {
	case 1: {
		header = (DWORD)pem.Binary.packet[0];
		break;
	}
	case 2: {
		header = (DWORD)*(WORD *)&pem.Binary.packet[0];
		break;
	}
	case 4: {
		header = *(DWORD *)&pem.Binary.packet[0];
		break;
	}
	default:
	{
		return false;
	}
	}

	for (auto &v : filter_list) {
		if (v.packet == pem.header && v.header_size == header_size) {
			if (v.header == header) {
				ft = v.filter;
				return true;
			}
		}
	}

	return true;
}

bool AddHeader(Alice &a, PacketFilter &pf) {
	int header_size = GetHeaderSize();
	std::wstring wHeader = L"@";

	switch (header_size) {
	case 1: {
		wHeader += BYTEtoString((BYTE)pf.header);
		break;
	}
	case 2: {
		wHeader += WORDtoString((WORD)pf.header);
		break;
	}
	case 4: {
		wHeader += DWORDtoString(pf.header);
		break;
	}
	default:
	{
		return false;
	}
	}

	pf.header_size = header_size;

	if (pf.packet == SENDPACKET) {
		a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_TYPE, L"Send");
	}
	else {
		a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_TYPE, L"Recv");
	}

	if (pf.filter == IGNORE_PACKET) {
		a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_FILTER, L"Ignore");
	}
	else {
		a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_FILTER, L"Block");
	}

	a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_HEADER, wHeader);
	return true;
}

bool UpdateFilter(Alice &a) {
	a.ListView_Clear(IG_LISTVIEW_FORMAT);
	for (auto &v : filter_list) {
		if (v.packet == SENDPACKET) {
			a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_TYPE, L"Send");
		}
		else {
			a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_TYPE, L"Recv");
		}

		if (v.filter == IGNORE_PACKET) {
			a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_FILTER, L"Ignore");
		}
		else {
			a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_FILTER, L"Block");
		}

		std::wstring wHeader = L"@";
		switch (v.header_size) {
		case 1: {
			wHeader += BYTEtoString((BYTE)v.header);
			break;
		}
		case 2: {
			wHeader += WORDtoString((WORD)v.header);
			break;
		}
		case 4: {
			wHeader += DWORDtoString(v.header);
			break;
		}
		default:
		{
			wHeader = L"Error";
			break;
		}
		}

		a.ListView_AddItem(IG_LISTVIEW_FORMAT, HV_HEADER, wHeader);
	}

	return true;
}

bool GetHeader(Alice &a, int nIDDlgItem, DWORD &dwHeader) {
	std::wstring wHeader = a.GetText(nIDDlgItem);

	if (!swscanf_s(wHeader.c_str(), L"@%lX", &dwHeader)) {
		return false;
	}

	return true;

}

bool AddFilter(Alice &a, int nIDDlgItem, PacketFilter &pf) {
	if (!GetHeader(a, nIDDlgItem, pf.header)) {
		return false;
	}

	for (auto &v : filter_list) {
		if (v.packet == pf.packet && v.filter == pf.filter) {
			if (v.header == pf.header) {
				return false;
			}
		}
	}

	if (!AddHeader(a, pf)) {
		return false;
	}

	filter_list.push_back(pf);
	return true;
}

bool DeleteFilter(Alice &a, int nIDDlgItem, MessageHeader type) {
	PacketFilter pf = { type };
	if (!GetHeader(a, nIDDlgItem, pf.header)) {
		return false;
	}

	for (size_t i = 0; i < filter_list.size(); i++) {
		if (filter_list[i].packet == pf.packet) {
			if (filter_list[i].header == pf.header) {
				filter_list.erase(filter_list.begin() + i);
				UpdateFilter(a);
				return true;
			}
		}
	}

	return false;
}

bool IGOnCreate(Alice &a) {
	a.ListView(IG_LISTVIEW_FORMAT, 3, 3, (IG_WIDTH - 6), (IG_HEIGHT / 2 - 6));
	a.ListView_AddHeader(IG_LISTVIEW_FORMAT, L"Type", 100);
	a.ListView_AddHeader(IG_LISTVIEW_FORMAT, L"Filter", 100);
	a.ListView_AddHeader(IG_LISTVIEW_FORMAT, L"Header", 100);

	a.StaticText(IG_STATIC_SEND, L"Send", 20, (IG_HEIGHT / 2 + 20));
	a.StaticText(IG_STATIC_RECV, L"Recv", 20, (IG_HEIGHT / 2 + 40));
	a.EditBox(IG_EDIT_HEADER_SEND, 60, (IG_HEIGHT / 2 + 20), L"", 100);
	a.EditBox(IG_EDIT_HEADER_RECV, 60, (IG_HEIGHT / 2 + 40), L"", 100);
	a.Button(IG_BUTTON_IGNORE_SEND, L"Ignore", 170, (IG_HEIGHT / 2 + 20), 50);
	a.Button(IG_BUTTON_IGNORE_RECV, L"Ignore", 170, (IG_HEIGHT / 2 + 40), 50);
	a.Button(IG_BUTTON_BLOCK_SEND, L"Block", 230, (IG_HEIGHT / 2 + 20), 50);
	a.Button(IG_BUTTON_BLOCK_RECV, L"Block", 230, (IG_HEIGHT / 2 + 40), 50);
	a.Button(IG_BUTTON_DELETE_SEND, L"Delete", 290, (IG_HEIGHT / 2 + 20), 50);
	a.Button(IG_BUTTON_DELETE_RECV, L"Delete", 290, (IG_HEIGHT / 2 + 40), 50);

	//a.Button(IG_BUTTON_SAVE_CONFIG, L"Save Config", (IG_WIDTH - 100), (IG_HEIGHT / 2 + 80));

	UpdateFilter(a);
	return true;
}

bool IGOnCommand(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == IG_BUTTON_SAVE_CONFIG) {
		return true;
	}
	if (nIDDlgItem == IG_BUTTON_IGNORE_SEND) {
		PacketFilter pf = { SENDPACKET, IGNORE_PACKET };
		AddFilter(a, IG_EDIT_HEADER_SEND, pf);
		return true;
	}
	if (nIDDlgItem == IG_BUTTON_IGNORE_RECV) {
		PacketFilter pf = { RECVPACKET, IGNORE_PACKET };
		AddFilter(a, IG_EDIT_HEADER_RECV, pf);
		return true;
	}
	if (nIDDlgItem == IG_BUTTON_BLOCK_SEND) {
		PacketFilter pf = { SENDPACKET, BLOCK_PACKET };
		AddFilter(a, IG_EDIT_HEADER_SEND, pf);
		return true;
	}
	if (nIDDlgItem == IG_BUTTON_BLOCK_RECV) {
		PacketFilter pf = { RECVPACKET, BLOCK_PACKET };
		AddFilter(a, IG_EDIT_HEADER_RECV, pf);
		return true;
	}
	if (nIDDlgItem == IG_BUTTON_DELETE_SEND) {
		DeleteFilter(a, IG_EDIT_HEADER_SEND, SENDPACKET);
		return true;
	}
	if (nIDDlgItem == IG_BUTTON_DELETE_RECV) {
		DeleteFilter(a, IG_EDIT_HEADER_RECV, RECVPACKET);
		return true;
	}
	return true;
}

bool IGOnNotify(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == FV_LISTVIEW_FORMAT) {

	}
	return true;
}

bool OpenFilterGUI() {
	if (global_ig) {
		// dead
		if (!global_ig->IsAlive()) {
			delete global_ig;
			global_ig = NULL;
		}
		// already opened
		else {
			return true;
		}
	}

	if (global_ig) {
		return true;
	}

	global_ig = new Alice(L"FilterClass", L"Filter List", IG_WIDTH, IG_HEIGHT, hIGInstance);
	global_ig->SetOnCreate(IGOnCreate);
	global_ig->SetOnCommand(IGOnCommand);
	global_ig->SetOnNotify(IGOnNotify);
	global_ig->Run();
	return true;
}

bool InitFilterGUI(HINSTANCE hInstance) {
	hIGInstance = hInstance;
	//OpenFilterGUI();
	return true;
}