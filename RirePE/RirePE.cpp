#include<Windows.h>
#include"../Share/Simple/Simple.h"
#include"RirePE.h"

#define FILTER_FILE "Filter.txt"

// Pipe from Client
bool Communicate(PipeServerThread& psh);

bool RunPipeServer() {
	PipeServer ps(L"PacketEditor");
	ps.SetCommunicate(Communicate);
	return ps.Run();
}

bool Server(Alice &a) {
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)RunPipeServer, NULL, NULL, NULL);
	if (!hThread) {
		return false;
	}
	CloseHandle(hThread);
	return true;
}

// gui
Alice *ga = NULL;

enum SubControl {
	LISTVIEW_LOGGER,
	EDIT_EXTRA,
	BUTTON_CLEAR,
	BUTTON_EXPORT,
	EDIT_SEND_HEADER,
	BUTTON_SEND_IGNORE,
	BUTTON_SEND_IGNORE_DELETE,
	EDIT_RECV_HEADER,
	BUTTON_RECV_IGNORE,
	BUTTON_RECV_IGNORE_DELETE,
	LISTVIEW_HEADERS,
	BUTTON_SEND_BLOCK,
	BUTTON_SEND_BLOCK_DELETE,
	BUTTON_RECV_BLOCK,
	BUTTON_RECV_BLOCK_DELETE,
	CHECK_SEND,
	CHECK_RECV,
	BUTTON_SAVE_FILTER,
	EDIT_PACKET_SEND,
	BUTTON_SEND,
	EDIT_PACKET_RECV,
	BUTTON_RECV,
};

enum ListViewIndex {
	LV_TYPE,
	LV_ID,
	LV_LENGTH,
	LV_PACKET,
};

enum HeaderViewIndex {
	HV_TYPE,
	HV_FILTER,
	HV_HEADER
};


typedef struct {
	ULONG_PTR addr;
	MessageHeader type;
	ULONG_PTR pos;
	ULONG_PTR size;
} PacketFormat;

typedef struct {
	ULONG_PTR addr;
	ULONG_PTR id;
	MessageHeader type;
	std::vector<BYTE> packet;
	std::vector<PacketFormat> format;
	int status;
	ULONG_PTR used;
	BOOL lock;
} PacketData;

std::vector<PacketData> packet_data_out;
std::vector<PacketData> packet_data_in;
std::wstring GetExtraInfo(PacketData &pd);


// sender
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

bool PacketSender(Alice &a, MessageHeader type) {
	PipeClient pc(L"PacketSender");
	if (!pc.Run()) {
		return false;
	}

	std::wstring wpacket = a.GetText((type == SENDPACKET) ? EDIT_PACKET_SEND : EDIT_PACKET_RECV);
	std::wstring wpacket_fmt;
	if (wpacket.length() < 5) {
		return false;
	}

	// header check
	if (wpacket.find(L"@") != 0) {
		return false;
	}
	wpacket.erase(wpacket.begin(), wpacket.begin() + 1);
	std::wstring wHeader;
	wHeader.push_back(wpacket.at(2));
	wHeader.push_back(wpacket.at(3));
	wHeader.push_back(wpacket.at(0));
	wHeader.push_back(wpacket.at(1));
	wpacket.erase(wpacket.begin(), wpacket.begin() + 4);
	wpacket = wHeader + wpacket;


	for (size_t i = 0; i < wpacket.length(); i++) {
		if (!CheckLetter(wpacket)) {
			return false;
		}

		if (wpacket.at(i) == L' ') {
			continue;
		}

		wpacket_fmt.push_back(wpacket.at(i));
	}

	if (wpacket_fmt.length() < 4) {
		return false;
	}

	if (wpacket_fmt.length() % 2) {
		return false;
	}

	std::vector<BYTE> packet;

	if (!StringtoBYTE(wpacket_fmt, packet)) {
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
	pcm->Binary.length = packet.size();
	memcpy_s(&pcm->Binary.packet[0], packet.size(), &packet[0], packet.size());
	pc.Send((BYTE *)pcm, data_length);

	delete[] b;

	return true;
}

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


bool AddFormat(PacketData &pd, PacketEditorMessage &pem) {
	// パケットロック済み
	if (pd.lock) {
		return false;
	}
	// パケットを登録
	if (pem.header == SENDPACKET || pem.header == RECVPACKET) {
		pd.packet.resize(pem.Binary.length);
		memcpy_s(&pd.packet[0], pem.Binary.length, pem.Binary.packet, pem.Binary.length);
		pd.addr = pem.addr;

		// Sendの場合は先に全てEncodeされ後からパケットのサイズが判明する
		if (pd.packet.size() && pd.packet.size() == pd.used) {
			// 全てのデータが利用された
			if (pd.status == 0) {
				pd.status = 1;
			}
		}

		// パケットロック
		if (pem.header == SENDPACKET) {
			pd.lock = TRUE;

			// 末尾に謎データがある場合
			if (pd.used < pd.packet.size()) {
				PacketFormat unk;
				unk.type = WHEREFROM;
				unk.pos = pd.used;
				unk.size = pd.packet.size() - pd.used;
				unk.addr = 0;
				pd.format.push_back(unk);
				pd.status = -1;
			}
			else {
				pd.status = 1;
			}

			// ログインパケットのパスワードを消す
			RemovePassword(pd);
		}
		return true;
	}

	// パケットロック
	if (pem.header == DECODEEND) {
		pd.lock = TRUE;
		if (pd.used < pd.packet.size()) {
			PacketFormat unk;
			unk.type = NOTUSED;
			unk.pos = pd.used;
			unk.size = pd.packet.size() - pd.used;
			unk.addr = 0;
			pd.format.push_back(unk);
			pd.status = -1;
		}
		return true;
	}

	// 正常にdecode or encode出来ていない場合は穴埋めする
	if (pd.used < pem.Extra.pos) {
		PacketFormat unk;
		unk.type = UNKNOWNDATA;
		unk.pos = pd.used;
		unk.size = pem.Extra.pos - pd.used;
		unk.addr = 0;
		pd.format.push_back(unk);
		pd.status = -1;
		pd.used += unk.size;
		return false;
	}

	// フォーマットを登録
	PacketFormat pf;
	pf.type = pem.header;
	pf.pos = pem.Extra.pos;
	pf.size = pem.Extra.size;
	pf.addr = pem.addr;
	pd.format.push_back(pf);

	// 状態を変更
	pd.used += pf.size;
	// Recvの場合は先にパケットのサイズが分かっている
	if (pd.packet.size() && pd.packet.size() == pd.used) {
		// 全てのデータが利用された
		if (pd.status == 0) {
			pd.status = 1;
		}
	}
	return true;
}

bool AddRecvPacket(PacketEditorMessage &pem) {
	for (size_t i = 0; i < packet_data_in.size(); i++) {
		if (packet_data_in[i].id == pem.id) {
			AddFormat(packet_data_in[i], pem);
			return false;
		}
	}

	PacketData pd;
	pd.id = pem.id;
	pd.type = RECVPACKET;
	pd.status = 0;
	pd.used = 0;
	pd.lock = FALSE;
	AddFormat(pd, pem);
	packet_data_in.push_back(pd);
	return true;
}

bool AddSendPacket(PacketEditorMessage &pem) {
	for (size_t i = 0; i < packet_data_out.size(); i++) {
		if (packet_data_out[i].id == pem.id) {
			AddFormat(packet_data_out[i], pem);
			return false;
		}
	}

	PacketData pd;
	pd.id = pem.id;
	pd.type = SENDPACKET;
	pd.status = 0;
	pd.used = 0;
	pd.lock = FALSE;
	AddFormat(pd, pem);
	packet_data_out.push_back(pd);
	return true;
}

// filter
std::vector<WORD> vIgnoreSendHeaders;
std::vector<WORD> vIgnoreRecvHeaders;
std::vector<WORD> vBlockSendHeaders;
std::vector<WORD> vBlockRecvHeaders;

bool SaveFilter() {
	FILE *fp = NULL;
	if (fopen_s(&fp, FILTER_FILE, "w")) {
		return false;
	}

	for (const auto& item : vIgnoreSendHeaders) {
		fprintf(fp, "Send,Ignore,@%04X\n", item);
	}
	for (const auto& item : vIgnoreRecvHeaders) {
		fprintf(fp, "Recv,Ignore,@%04X\n", item);
	}
	for (const auto& item : vBlockSendHeaders) {
		fprintf(fp, "Send,Block,@%04X\n", item);
	}
	for (const auto& item : vBlockRecvHeaders) {
		fprintf(fp, "Recv,Block,@%04X\n", item);
	}

	fclose(fp);
	return true;
}

bool SetHeaders(std::string header_type, std::string filter_type, WORD header) {
	if (header_type.compare("Send") == 0) {
		if (filter_type.compare("Ignore") == 0) {
			vIgnoreSendHeaders.push_back(header);
			return true;
		}
		if (filter_type.compare("Block") == 0) {
			vBlockSendHeaders.push_back(header);
			return true;
		}
		return false;
	}
	if (header_type.compare("Recv") == 0) {
		if (filter_type.compare("Ignore") == 0) {
			vIgnoreRecvHeaders.push_back(header);
			return true;
		}
		if (filter_type.compare("Block") == 0) {
			vBlockRecvHeaders.push_back(header);
			return true;
		}
		return false;
	}


	return false;
}

void UpdateFilter(Alice &a) {
	a.ListView_Clear(LISTVIEW_HEADERS);
	for (const auto& item : vIgnoreSendHeaders) {
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Send");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Ignore");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, L"@" + WORDtoString(item));
	}
	for (const auto& item : vIgnoreRecvHeaders) {
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Recv");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Ignore");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, L"@" + WORDtoString(item));
	}
	for (const auto& item : vBlockSendHeaders) {
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Send");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Block");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, L"@" + WORDtoString(item));
	}
	for (const auto& item : vBlockRecvHeaders) {
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Recv");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Block");
		a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, L"@" + WORDtoString(item));
	}
}

bool LoadFilter(Alice &a) {
	FILE *fp = NULL;
	if (fopen_s(&fp, FILTER_FILE, "r")) {
		return false;
	}

	char buf[256] = { 0 };
	char buf_type[256] = { 0 };
	char buf_filter[256] = { 0 };
	DWORD header = 0;
	while (fgets(buf, sizeof(buf), fp) > 0) {
		if (sscanf_s(buf, "%[^,],%[^,],@%lX", buf_type, 256, buf_filter, 256, &header)) {
			SetHeaders(buf_type, buf_filter, (WORD)header);
		}
	}

	fclose(fp);
	UpdateFilter(a);
	return true;
}

bool SearchHeaders(std::vector<WORD> &vHeaders, WORD wHeader) {
	for (size_t i = 0; i < vHeaders.size(); i++) {
		if (vHeaders[i] == wHeader) {
			return true;
		}
	}
	return false;
}

bool AddFilter(std::vector<WORD> &vHeaders, WORD wHeader) {
	if (SearchHeaders(vHeaders, wHeader)) {
		return false;
	}
	vHeaders.push_back(wHeader);
	return true;
}

bool DeleteFilter(std::vector<WORD> &vHeaders, WORD wHeader) {
	for (size_t i = 0; i < vHeaders.size(); i++) {
		if (vHeaders[i] == wHeader) {
			vHeaders.erase(vHeaders.begin() + i);
			return true;
		}
	}
	return false;
}

WORD HeaderStringToWORD(std::wstring wHeaderText) {
	WORD wHeader = 0xFFFF;
	swscanf_s(wHeaderText.c_str(), L"@%hX", &wHeader);
	return wHeader;
}

// クライアントからのパケットの処理
bool Communicate(PipeServerThread& psh) {
	Alice &a = *ga;
	a.SetText(EDIT_EXTRA, L"Connected");

	std::vector<BYTE> data;
	bool bBlock = false;
	while (psh.Recv(data)) {
		PacketEditorMessage &pem = (PacketEditorMessage&)data[0];

		if (pem.header == SENDPACKET && SearchHeaders(vBlockSendHeaders, *(WORD *)&pem.Binary.packet[0])) {
			psh.Send(L"Block");
			bBlock = true;
		}
		else if (pem.header == RECVPACKET && SearchHeaders(vBlockRecvHeaders, *(WORD *)&pem.Binary.packet[0])) {
			psh.Send(L"Block");
			bBlock = true;
		}
		else {
			if (pem.header == SENDPACKET || pem.header == RECVPACKET) {
				psh.Send(L"OK");
			}
			bBlock = false;
		}

		if (pem.header == SENDPACKET) {
			if (a.CheckBoxStatus(CHECK_SEND) && !SearchHeaders(vIgnoreSendHeaders, *(WORD *)&pem.Binary.packet[0])) {
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_TYPE, L"Send");
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_ID, std::to_wstring(pem.id));
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_LENGTH, std::to_wstring(pem.Binary.length));
				std::wstring wpacket = DatatoString(pem.Binary.packet, (pem.Binary.length > 1024) ? 1024 : pem.Binary.length, true);
				// @header data
				wpacket.erase(wpacket.begin(), wpacket.begin() + 5);
				if (!bBlock) {
					wpacket = L"@" + WORDtoString(*(WORD *)&pem.Binary.packet[0]) + wpacket;
				}
				else {
					wpacket = L"@" + WORDtoString(*(WORD *)&pem.Binary.packet[0]) + L" (Blocked)" + wpacket;
				}
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, wpacket);
			}
			AddSendPacket(pem);
			continue;
		}

		if (pem.header == RECVPACKET) {
			if (a.CheckBoxStatus(CHECK_RECV) && !SearchHeaders(vIgnoreRecvHeaders, *(WORD *)&pem.Binary.packet[0])) {
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_TYPE, L"Recv");
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_ID, std::to_wstring(pem.id));
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_LENGTH, std::to_wstring(pem.Binary.length));
				std::wstring wpacket = DatatoString(pem.Binary.packet, (pem.Binary.length > 1024) ? 1024 : pem.Binary.length, true);
				// @header data
				wpacket.erase(wpacket.begin(), wpacket.begin() + 5);
				if (!bBlock) {
					wpacket = L"@" + WORDtoString(*(WORD *)&pem.Binary.packet[0]) + wpacket;
				}
				else {
					wpacket = L"@" + WORDtoString(*(WORD *)&pem.Binary.packet[0]) + L" (Blocked)" + wpacket;
				}
				a.ListView_AddItem(LISTVIEW_LOGGER, LV_PACKET, wpacket);
			}
			// Recv追加
			AddRecvPacket(pem);
			continue;
		}

		if (ENCODEHEADER <= pem.header && pem.header <= ENCODEBUFFER) {
			AddSendPacket(pem);
			continue;
		}

		if (DECODEHEADER <= pem.header && pem.header <= DECODEBUFFER) {
			AddRecvPacket(pem);
			continue;
		}

		if (pem.header == DECODEEND) {
			AddRecvPacket(pem);
			continue;
		}
	}
	a.SetText(EDIT_EXTRA, L"Disconnected");
	return true;
}

bool OnCreate(Alice &a) {
	a.ListView(LISTVIEW_LOGGER, 3, 3, 794, 294);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Type", 40);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"ID", 0);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Length", 50);
	a.ListView_AddHeader(LISTVIEW_LOGGER, L"Packet", 650);
	a.TextArea(EDIT_EXTRA, 3, 300 + 30, 794, 294 - 30);
	a.ReadOnly(EDIT_EXTRA);
	a.CheckBox(CHECK_SEND, L"Send", 700, 310, BST_CHECKED);
	a.CheckBox(CHECK_RECV, L"Recv", 750, 310, BST_CHECKED);
	a.Button(BUTTON_CLEAR, L"Clear", 600, 310);
	//a.Button(BUTTON_EXPORT, L"Export", 500, 310);

	// sender
	a.EditBox(EDIT_PACKET_SEND, 200, 620, L"", 500);
	a.EditBox(EDIT_PACKET_RECV, 200, 640, L"", 500);
	a.Button(BUTTON_SEND, L"SendPacket", 720, 620);
	a.Button(BUTTON_RECV, L"RecvPacket", 720, 640);

	a.EditBox(EDIT_SEND_HEADER, 820, 310, L"", 60);
	a.Button(BUTTON_SEND_IGNORE, L"Ignore Send", 890, 310);
	a.Button(BUTTON_SEND_IGNORE_DELETE, L"Delete", 970, 310);
	a.Button(BUTTON_SEND_BLOCK, L"Block  Send", 890, 330);
	a.Button(BUTTON_SEND_BLOCK_DELETE, L"Delete", 970, 330);
	a.EditBox(EDIT_RECV_HEADER, 820, 360, L"", 60);
	a.Button(BUTTON_RECV_IGNORE, L"Ignore Recv", 890, 360);
	a.Button(BUTTON_RECV_IGNORE_DELETE, L"Delete", 970, 360);
	a.Button(BUTTON_RECV_BLOCK, L"Block  Recv", 890, 380);
	a.Button(BUTTON_RECV_BLOCK_DELETE, L"Delete", 970, 380);
	a.Button(BUTTON_SAVE_FILTER, L"Save Filter", 890, 410);


	a.ListView(LISTVIEW_HEADERS, 810, 3, 211, 294);
	a.ListView_AddHeader(LISTVIEW_HEADERS, L"Type", 40);
	a.ListView_AddHeader(LISTVIEW_HEADERS, L"Filter", 60);
	a.ListView_AddHeader(LISTVIEW_HEADERS, L"Header", 100);

	LoadFilter(a);

	Server(a);
	return true;
}

// 色々な処理
bool OnCommand(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == BUTTON_CLEAR) {
		a.ListView_Clear(LISTVIEW_LOGGER);
		packet_data_out.clear();
		packet_data_in.clear();
		return true;
	}

	if (nIDDlgItem == BUTTON_SEND_IGNORE) {
		std::wstring wHeaderText = a.GetText(EDIT_SEND_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (AddFilter(vIgnoreSendHeaders, wHeader)) {
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Send");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Ignore");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, wHeaderText);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_SEND_BLOCK) {
		std::wstring wHeaderText = a.GetText(EDIT_SEND_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (AddFilter(vBlockSendHeaders, wHeader)) {
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Send");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Block");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, wHeaderText);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_SEND_IGNORE_DELETE) {
		std::wstring wHeaderText = a.GetText(EDIT_SEND_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (DeleteFilter(vIgnoreSendHeaders, wHeader)) {
				UpdateFilter(a);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_SEND_BLOCK_DELETE) {
		std::wstring wHeaderText = a.GetText(EDIT_SEND_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (DeleteFilter(vBlockSendHeaders, wHeader)) {
				UpdateFilter(a);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_RECV_IGNORE) {
		std::wstring wHeaderText = a.GetText(EDIT_RECV_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (AddFilter(vIgnoreRecvHeaders, wHeader)) {
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Recv");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Ignore");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, wHeaderText);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_RECV_BLOCK) {
		std::wstring wHeaderText = a.GetText(EDIT_RECV_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (AddFilter(vBlockRecvHeaders, wHeader)) {
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_TYPE, L"Recv");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_FILTER, L"Block");
				a.ListView_AddItem(LISTVIEW_HEADERS, HV_HEADER, wHeaderText);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_RECV_IGNORE_DELETE) {
		std::wstring wHeaderText = a.GetText(EDIT_RECV_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (DeleteFilter(vIgnoreRecvHeaders, wHeader)) {
				UpdateFilter(a);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_RECV_BLOCK_DELETE) {
		std::wstring wHeaderText = a.GetText(EDIT_RECV_HEADER);
		if (wHeaderText.find(L"@") == 0 && wHeaderText.size() >= 5) {
			WORD wHeader = HeaderStringToWORD(wHeaderText);
			if (DeleteFilter(vBlockRecvHeaders, wHeader)) {
				UpdateFilter(a);
			}
		}
		return true;
	}

	if (nIDDlgItem == BUTTON_SAVE_FILTER) {
		SaveFilter();
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

std::wstring GetFormat(PacketData &pd, PacketFormat &fmt) {
	std::wstring wText;

	wText = QWORDtoString(fmt.addr) + (((int)fmt.pos >= 0) ? L" +" : L" ") + std::to_wstring((int)fmt.pos) + L" ";

	try {
		switch (fmt.type) {
		case ENCODEHEADER:
		{
			wText += L"Header\r\n\t";
			wText += L"@" + WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case ENCODE1:
		{
			wText += L"BYTE\r\n\t";
			wText += BYTEtoString(*(BYTE *)&pd.packet[fmt.pos]);
			break;
		}
		case ENCODE2:
		{
			wText += L"WORD\r\n\t";
			wText += WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case ENCODE4:
		{
			wText += L"DWORD\r\n\t";
			//wText += DWORDtoString(*(DWORD *)&pd.packet[fmt.pos]);
			// 整数値も表示
			DWORD dw = *(DWORD *)&pd.packet[fmt.pos];
			wText += DWORDtoString(dw) + L"(" + std::to_wstring((signed long int)dw) + L")";
			break;
		}
		case ENCODE8:
		{
			wText += L"QWORD\r\n\t";
			//wText += QWORDtoString(*(ULONG_PTR *)&pd.packet[fmt.pos]);
			// 整数値も表示
			ULONG_PTR u = *(ULONG_PTR *)&pd.packet[fmt.pos];
			wText += QWORDtoString(u) + L"(" + std::to_wstring((LONG_PTR)u) + L")";
			break;
		}
		case ENCODESTR:
		{
			wText += L"Str(" + std::to_wstring(fmt.size - sizeof(WORD)) + L")\r\n\t";
			std::string sjis;
			std::wstring utf16;
			if (BYTEtoShiftJIS((BYTE *)&pd.packet[fmt.pos + sizeof(WORD)], *(WORD *)&pd.packet[fmt.pos], sjis) && ShiftJIStoUTF8(sjis, utf16)) {
				wText += L"\"" + utf16 + L"\"";
			}
			else {
				wText += L"ERROR!";
			}
			break;
		}
		case ENCODEBUFFER:
		{
			wText += L"Buffer(" + std::to_wstring(fmt.size) + L")\r\n\t";
			wText += L"\'" + DatatoString(&pd.packet[fmt.pos], fmt.size) + L"\'";
			break;
		}
		case DECODEHEADER:
		{
			wText += L"Header\r\n\t";
			wText += L"@" + WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case DECODE1:
		{
			wText += L"BYTE\r\n\t";
			wText += BYTEtoString(*(BYTE *)&pd.packet[fmt.pos]);
			break;
		}
		case DECODE2:
		{
			wText += L"WORD\r\n\t";
			wText += WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case DECODE4:
		{
			wText += L"DWORD\r\n\t";
			//wText += DWORDtoString(*(DWORD *)&pd.packet[fmt.pos]);
			// 整数値も表示
			DWORD dw = *(DWORD *)&pd.packet[fmt.pos];
			wText += DWORDtoString(dw) + L"(" + std::to_wstring((signed long int)dw) + L")";
			break;
		}
		case DECODE8:
		{
			wText += L"QWORD\r\n\t";
			//wText += QWORDtoString(*(ULONG_PTR *)&pd.packet[fmt.pos]);
			// 整数値も表示
			ULONG_PTR u = *(ULONG_PTR *)&pd.packet[fmt.pos];
			wText += QWORDtoString(u) + L"(" + std::to_wstring((LONG_PTR)u) + L")";
			break;
		}
		case DECODESTR:
		{
			wText += L"Str(" + std::to_wstring(fmt.size - sizeof(WORD)) + L")\r\n\t";
			std::string sjis;
			std::wstring utf16;
			if (BYTEtoShiftJIS((BYTE *)&pd.packet[fmt.pos + sizeof(WORD)], *(WORD *)&pd.packet[fmt.pos], sjis) && ShiftJIStoUTF8(sjis, utf16)) {
				wText += L"\"" + utf16 + L"\"";
			}
			else {
				wText += L"ERROR!";
			}
			break;
		}
		case DECODEBUFFER:
		{
			wText += L"Buffer(" + std::to_wstring(fmt.size) + L")\r\n\t";
			wText += L"\'" + DatatoString(&pd.packet[fmt.pos], fmt.size) + L"\'";
			break;
		}
		// エラー処理
		case NOTUSED: {
			wText += L"NotUsed(" + std::to_wstring(fmt.size) + L")\r\n\t";
			wText += DatatoString(&pd.packet[fmt.pos], fmt.size, true);
			break;
		}
		case UNKNOWNDATA: {
			wText += L"UnknownFormat(" + std::to_wstring(fmt.size) + L")\r\n\t";
			wText += DatatoString(&pd.packet[fmt.pos], fmt.size, true);
			break;
		}
		case WHEREFROM: {
			wText += L"NotEncoded(" + std::to_wstring(fmt.size) + L")\r\n\t";
			wText += DatatoString(&pd.packet[fmt.pos], fmt.size, true);
			break;
		}
		}
	}
	catch (...) {
	}

	return wText;
}

std::wstring GetFormatData(PacketData &pd, PacketFormat &fmt) {
	std::wstring wText;

	try {

		switch (fmt.type) {
		case ENCODEHEADER:
		{
			wText = L"@" + WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case ENCODE1:
		{
			wText = BYTEtoString(*(BYTE *)&pd.packet[fmt.pos]);
			break;
		}
		case ENCODE2:
		{
			wText = WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case ENCODE4:
		{
			//wText = DWORDtoString(*(DWORD *)&pd.packet[fmt.pos]);
			// 整数値も表示
			DWORD dw = *(DWORD *)&pd.packet[fmt.pos];
			wText = DWORDtoString(dw) + L"(" + std::to_wstring((signed long int)dw) + L")";
			break;
		}
		case ENCODE8:
		{
			//wText = QWORDtoString(*(ULONG_PTR *)&pd.packet[fmt.pos]);
			// 整数値も表示
			ULONG_PTR u = *(ULONG_PTR *)&pd.packet[fmt.pos];
			wText = QWORDtoString(u) + L"(" + std::to_wstring((LONG_PTR)u) + L")";
			break;
		}
		case ENCODESTR:
		{
			std::string sjis;
			std::wstring utf16;
			if (BYTEtoShiftJIS((BYTE *)&pd.packet[fmt.pos + sizeof(WORD)], *(WORD *)&pd.packet[fmt.pos], sjis) && ShiftJIStoUTF8(sjis, utf16)) {
				wText = L"\"" + utf16 + L"\"";
			}
			else {
				wText = L"ERROR!";
			}
			break;
		}
		case ENCODEBUFFER:
		{
			wText = L"\'" + DatatoString(&pd.packet[fmt.pos], fmt.size) + L"\'";
			break;
		}
		case DECODEHEADER:
		{
			wText = L"@" + WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case DECODE1:
		{
			wText = BYTEtoString(*(BYTE *)&pd.packet[fmt.pos]);
			break;
		}
		case DECODE2:
		{
			wText = WORDtoString(*(WORD *)&pd.packet[fmt.pos]);
			break;
		}
		case DECODE4:
		{
			//wText = DWORDtoString(*(DWORD *)&pd.packet[fmt.pos]);
			// 整数値も表示
			DWORD dw = *(DWORD *)&pd.packet[fmt.pos];
			wText = DWORDtoString(dw) + L"(" + std::to_wstring((signed long int)dw) + L")";
			break;
		}
		case DECODE8:
		{
			//wText = QWORDtoString(*(ULONG_PTR *)&pd.packet[fmt.pos]);
			// 整数値も表示
			ULONG_PTR u = *(ULONG_PTR *)&pd.packet[fmt.pos];
			wText = QWORDtoString(u) + L"(" + std::to_wstring((LONG_PTR)u) + L")";
			break;
		}
		case DECODESTR:
		{
			std::string sjis;
			std::wstring utf16;
			if (BYTEtoShiftJIS((BYTE *)&pd.packet[fmt.pos + sizeof(WORD)], *(WORD *)&pd.packet[fmt.pos], sjis) && ShiftJIStoUTF8(sjis, utf16)) {
				wText = L"\"" + utf16 + L"\"";
			}
			else {
				wText = L"ERROR!";
			}
			break;
		}
		case DECODEBUFFER:
		{
			wText = L"\'" + DatatoString(&pd.packet[fmt.pos], fmt.size) + L"\'";
			break;
		}
		// エラー処理
		case NOTUSED: {
			wText = L"NotUsed(" + DatatoString(&pd.packet[fmt.pos], fmt.size, true) + L")";
			break;
		}
		case UNKNOWNDATA: {
			wText = L"Unknown(" + DatatoString(&pd.packet[fmt.pos], fmt.size, true) + L")";
			break;
		}
		case WHEREFROM: {
			wText = L"Where(" + DatatoString(&pd.packet[fmt.pos], fmt.size, true) + L")";
			break;
		}
		}
	}
	catch (...) {
	}

	return wText;
}


std::wstring GetExtraInfo(PacketData &pd) {
	std::wstring wText;

	// パケットの状態
	wText += L"[Packet Status]\r\n";
	//wText += L"\tLock = " + std::to_wstring(pd.lock) + L"\r\n";
	wText += L"\tStatus = ";
	if (pd.status == 1) {
		wText += L"OK";
	}
	if (pd.status == 0) {
		wText += L"Wait";
	}
	if (pd.status == -1) {
		wText += L"NG";
	}
	wText += L"\r\n\r\n";

	if (pd.type == SENDPACKET) {
		wText += L"[SendPacket]\r\n";
	}
	else {
		wText += L"[RecvPacket]\r\n";
	}

	wText += L"ret = " + QWORDtoString(pd.addr) + L"\r\n";
	wText += L"length = " + std::to_wstring((int)pd.packet.size()) + L"\r\n";
	if (pd.packet.size()) {
		wText += DatatoString(&pd.packet[0], pd.packet.size(), true) + L"\r\n";
	}
	else {
		wText += L"ERROR\r\n";
	}
	if (pd.packet.size() >= 2) {
		std::wstring wFormattedPacket;
		for (size_t i = 0; i < pd.format.size(); i++) {
			if (wFormattedPacket.size()) {
				wFormattedPacket += L" ";
			}
			wFormattedPacket += GetFormatData(pd, pd.format[i]);

		}
		wText += wFormattedPacket + L"\r\n";
	}
	wText += L"\r\n";

	wText += L"[Format]\r\n";
	if (pd.packet.size() >= 2) {
		for (size_t i = 0; i < pd.format.size(); i++) {
			wText += GetFormat(pd, pd.format[i]) + L"\r\n";
		}
	}
	else {
		wText += L"ERROR\r\n";
	}

	return wText;
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
		text_header = text_packet;
		text_header.erase(text_header.begin() + 5, text_header.end());

		DWORD id = _wtoi(text_id.c_str());

		if (text_type.compare(L"Send") == 0) {
			for (size_t i = 0; i < packet_data_out.size(); i++) {
				if (packet_data_out[i].id == id) {
					a.SetText(EDIT_EXTRA, GetExtraInfo(packet_data_out[i]));
					a.SetText(EDIT_SEND_HEADER, text_header);
					a.SetText(EDIT_RECV_HEADER, L"");
					if (text_packet.length() < 1024) {
						a.SetText(EDIT_PACKET_SEND, text_packet);
						a.SetText(EDIT_PACKET_RECV, L"");
					}
					return true;
				}
			}
			return true;
		}
		if (text_type.compare(L"Recv") == 0) {
			for (size_t i = 0; i < packet_data_in.size(); i++) {
				if (packet_data_in[i].id == id) {
					a.SetText(EDIT_EXTRA, GetExtraInfo(packet_data_in[i]));
					a.SetText(EDIT_SEND_HEADER, L"");
					a.SetText(EDIT_RECV_HEADER, text_header);
					if (text_packet.length() < 1024) {
						a.SetText(EDIT_PACKET_SEND, L"");
						a.SetText(EDIT_PACKET_RECV, text_packet);
					}
					return true;
				}
			}
			return true;
		}

		return false;
	}

	// フィルタ
	if (nIDDlgItem == LISTVIEW_HEADERS) {
		std::wstring text_type;
		std::wstring text_filter;
		std::wstring text_header;
		bool check = true;

		check &= a.ListView_Copy(LISTVIEW_HEADERS, HV_TYPE, text_type, false);
		check &= a.ListView_Copy(LISTVIEW_HEADERS, HV_FILTER, text_filter, false);
		check &= a.ListView_Copy(LISTVIEW_HEADERS, HV_HEADER, text_header, true);

		if (!check) {
			return false;
		}

		if (text_type.compare(L"Send") == 0) {
			if (text_filter.compare(L"Ignore") == 0 || text_filter.compare(L"Block") == 0) {
				a.SetText(EDIT_SEND_HEADER, text_header);
				a.SetText(EDIT_RECV_HEADER, L"");
				return true;
			}
		}

		if (text_type.compare(L"Recv") == 0) {
			if (text_filter.compare(L"Ignore") == 0 || text_filter.compare(L"Block") == 0) {
				a.SetText(EDIT_SEND_HEADER, L"");
				a.SetText(EDIT_RECV_HEADER, text_header);
				return true;
			}
		}

		return true;
	}
	return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
#ifdef _WIN64
	Alice a(L"PacketEditorClass64", L"Rire PE x64", 1024, 768, hInstance);
#else
	Alice a(L"PacketEditorClass", L"Rire PE x86", 1024, 768, hInstance);
#endif
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.Run();
	ga = &a;
	a.Wait();
	return 0;
}