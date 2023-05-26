#include"../RirePE/MainGUI.h"
std::vector<PacketData> packet_data_out;
std::vector<PacketData> packet_data_in;

void ClearAll() {
	packet_data_out.clear();
	packet_data_in.clear();
}

std::vector<PacketData>& GetOutPacketFormat() {
	return packet_data_out;
}

std::vector<PacketData>& GetInPacketFormat() {
	return packet_data_in;
}

bool AddFormat(PacketData &pd, PacketEditorMessage &pem) {
	// パケットロック済み
	if (pd.lock) {
		return false;
	}

	// パケットの復号検出
	if (pem.Extra.update == FORMAT_UPDATE) {
		if (pem.Extra.pos + pem.Extra.size <= pd.packet.size()) {
			for (auto &pf : pd.format) {
				if (pf.pos == pem.Extra.pos && pf.size == pem.Extra.size) {
					for (DWORD i = 0; i < pem.Extra.size; i++) {
						if (pd.packet[pem.Extra.pos + i] != pem.Extra.data[i]) {
							pf.modified = true;
							memcpy_s(&pd.packet[pem.Extra.pos], pem.Extra.size, &pem.Extra.data[0], pem.Extra.size);
							return true;
						}
					}
					return false;
				}
			}
		}
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
				PacketFormat unk = {};
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
		}
		return true;
	}

	// パケットロック
	if (pem.header == DECODE_END) {
		pd.lock = TRUE;
		if (pd.used < pd.packet.size()) {
			PacketFormat unk = {};
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
		PacketFormat unk = {};
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
	PacketFormat pf = {};
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

// クライアントからのパケットの処理
bool LoggerCommunicate(PipeServerThread& psh) {
	SetInfo(L"Connected");

	std::vector<BYTE> data;
	bool bBlock = false;
	while (psh.Recv(data)) {
		PacketEditorMessage &pem = (PacketEditorMessage&)data[0];

		bBlock = false;

		if (pem.header == SENDPACKET) {
			UpdateLogger(pem, bBlock);
			if (bBlock) {
				psh.Send(L"Block");
			}
			else {
				psh.Send(L"OK");
			}
			AddSendPacket(pem);
			UpdateStatus(pem);
			continue;
		}

		if (pem.header == RECVPACKET) {
			UpdateLogger(pem, bBlock);
			if (bBlock) {
				psh.Send(L"Block");
			}
			else {
				psh.Send(L"OK");
			}
			AddRecvPacket(pem);
			continue;
		}

		if (ENCODE_BEGIN <= pem.header && pem.header <= ENCODE_END) {
			AddSendPacket(pem);
			continue;
		}

		if (DECODE_BEGIN <= pem.header && pem.header <= DECODE_END) {
			AddRecvPacket(pem);

			if(pem.header == DECODE_END) {
				UpdateStatus(pem);
			}
			continue;
		}
	}
	SetInfo(L"Disconnected");
	return true;
}

bool RunPacketLoggerPipe() {
	PipeServer ps(PE_LOGGER_PIPE_NAME);
	ps.SetCommunicate(LoggerCommunicate);
	return ps.Run();
}

bool PacketLogger() {
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)RunPacketLoggerPipe, NULL, NULL, NULL);
	if (!hThread) {
		return false;
	}
	CloseHandle(hThread);
	return true;
}