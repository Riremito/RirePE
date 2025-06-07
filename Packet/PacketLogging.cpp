#include"PacketLogging.h"

//DWORD packet_id_out = (GetCurrentProcessId() << 16); // 偶数
//DWORD packet_id_in = (GetCurrentProcessId() << 16) + 1; // 奇数
DWORD packet_id_out = 2; // 偶数
DWORD packet_id_in = 1; // 奇数

DWORD CountUpPacketID(DWORD &id) {
	id += 2;
	return id;
}

bool InPacketLogging(MessageHeader type, InPacket *ip, void *retAddr) {
	switch (type) {
	case ENCODE_BEGIN:
	{
		// count up
		// tracking start
		return true;
	}
	case ENCODE_END:
	{
		// notify encoded size
		return true;
	}
	default: {
		break;
	}
	}
	return false;
}

bool OutPacketLogging(MessageHeader type, OutPacket *op, void *retAddr) {
	switch (type) {
	case DECODE_BEGIN:
	{
		// count up
		// tracking start
		return true;
	}
	case DECODE_END:
	{
		// notify decoded size
		return true;
	}
	default: {
		break;
	}
	}
	return false;
}


void AddExtra(PacketExtraInformation &pxi) {
	//EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + pxi.size];

	if (!pem) {
		//LeaveCriticalSection(&cs);
		return;
	}

	pem->header = pxi.fmt;
	pem->id = pxi.id;
	pem->addr = pxi.addr;
	pem->Extra.pos = pxi.pos;
	pem->Extra.size = pxi.size;

	if (!pxi.data) {
		pem->Extra.update = FORMAT_NO_UPDATE;
	}
	else {
		pem->Extra.update = FORMAT_UPDATE;
		memcpy_s(&pem->Extra.data[0], pxi.size, &pxi.data[0], pxi.size);
	}

	if (!pc->Send(b, sizeof(PacketEditorMessage) + pxi.size)) {
		RestartPipeClient();
		pc->Send(b, sizeof(PacketEditorMessage) + pxi.size); // retry
	}

	delete pem;
	//LeaveCriticalSection(&cs);
}

// for SendPacket format
std::vector<PacketExtraInformation> list_pei;

void ClearQueue(OutPacket *op) {
	auto itr = list_pei.begin();
	while (itr != list_pei.end()) {
		if (itr->tracking == (ULONG_PTR)op) {
			itr = list_pei.erase(itr);
		}
		else {
			itr++;
		}
	}
}

void AddQueue(PacketExtraInformation &pxi) {
	//DEBUG(L"debug... ID : " + std::to_wstring(pxi.id) + L", " + std::to_wstring(pxi.pos) + L", " + std::to_wstring(pxi.size));
	list_pei.push_back(pxi);
}

void AddExtraAll(OutPacket *op) {
	for (auto &pei : list_pei) {
		// check tracking id (struct addr)
		if (pei.tracking == (ULONG_PTR)op) {
			pei.id = packet_id_out; // fix
			AddExtra(pei);
			pei.tracking = 0;
		}
	}
	//DEBUG(L"list_st = " + std::to_wstring(list_pei.size()));

	auto itr = list_pei.begin();
	while (itr != list_pei.end()) {
		if (itr->tracking == 0) {
			itr = list_pei.erase(itr);
		}
		else {
			itr++;
		}
	}
	//DEBUG(L"list_rm = " + std::to_wstring(list_pei.size()));
}

void AddSendPacket(OutPacket *op, ULONG_PTR addr, bool &bBlock) {
	AddExtraAll(op);
	//EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + op->encoded];

	if (!b) {
		//LeaveCriticalSection(&cs);
		return;
	}

	pem->header = SENDPACKET;
	pem->id = packet_id_out;
	pem->addr = addr;
	pem->Binary.length = op->encoded;
	memcpy_s(pem->Binary.packet, op->encoded, op->packet, op->encoded);
	CountUpPacketID(packet_id_out); // SendPacketとEnterSendPacketがあるのでここでカウントアップ

#ifdef _WIN64
	if (op->header) {
		*(WORD *)&pem->Binary.packet[0] = op->header;
	}
#endif

	if (!pc->Send(b, sizeof(PacketEditorMessage) + op->encoded)) {
		RestartPipeClient();
	}
	else {
		std::wstring wResponse;
		pc->Recv(wResponse);
		if (wResponse.compare(L"Block") == 0) {
			bBlock = true;
		}
		else {
			bBlock = false;
		}
	}

	delete[] b;
	//LeaveCriticalSection(&cs);
}

void AddRecvPacket(InPacket *ip, ULONG_PTR addr, bool &bBlock) {
	//EnterCriticalSection(&cs);
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + ip->size];
	if (!b) {
		//LeaveCriticalSection(&cs);
		return;
	}

	pem->header = RECVPACKET;
	pem->id = packet_id_in;
	pem->addr = addr;
	pem->Binary.length = ip->size;
	memcpy_s(pem->Binary.packet, ip->size, &ip->packet[4], ip->size);

	if (!pc->Send(b, sizeof(PacketEditorMessage) + ip->size)) {
		RestartPipeClient();
	}
	else {
		std::wstring wResponse;
		pc->Recv(wResponse);
		if (wResponse.compare(L"Block") == 0) {
			bBlock = true;
		}
		else {
			bBlock = false;
		}
	}

	delete[] b;
	//LeaveCriticalSection(&cs);
}

PipeClient *pc = NULL;

bool StartPipeClient() {
	pc = new PipeClient(GetPipeNameLogger());
	return pc->Run();
}

bool RestartPipeClient() {
	if (pc) {
		delete pc;
		pc = NULL;
	}
	return StartPipeClient();
}