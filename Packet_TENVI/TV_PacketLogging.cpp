#include"TV_PacketLogging.h"

PipeClient *gPipeClient = NULL;
int gTarget_pid = 0;// logger
DWORD g_packet_id_out = 2; // 偶数
DWORD g_packet_id_in = 1; // 奇数

bool StartPipeClient() {
	gPipeClient = new PipeClient(GetPipeNameLogger());
	return gPipeClient->Run();
}

bool RestartPipeClient() {
	if (gPipeClient) {
		delete gPipeClient;
		gPipeClient = NULL;
	}
	return StartPipeClient();
}

int get_target_pid() {
	return gTarget_pid;
}

void set_target_pid(int pid) {
	gTarget_pid = pid;
}

std::wstring GetPipeNameLogger() {
	if (get_target_pid()) {
		return PE_LOGGER_PIPE_NAME + std::to_wstring(get_target_pid());
	}
	return PE_LOGGER_PIPE_NAME;
}

std::wstring GetPipeNameSender() {
	if (get_target_pid()) {
		return PE_SENDER_PIPE_NAME + std::to_wstring(get_target_pid());
	}
	return PE_SENDER_PIPE_NAME;
}

bool TV_RunRirePE_Thread(TenviHookConfig &thc) {
	std::wstring wDir;
	if (GetDir(wDir, thc.hinstDLL)) {
		std::wstring param = std::to_wstring(get_target_pid()) + L" EngineClass";
		ShellExecuteW(NULL, NULL, (wDir + L"\\RirePE.exe").c_str(), param.c_str(), wDir.c_str(), SW_SHOW);
	}

	StartPipeClient();
	RunPacketSender();
	return true;
}

bool TV_RunRirePE(TenviHookConfig &thc) {
	set_target_pid(GetCurrentProcessId());
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)TV_RunRirePE_Thread, &thc, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}

DWORD count_up_packet_id_in() {
	g_packet_id_in += 2;
	return g_packet_id_in;
}

DWORD get_packet_id_in() {
	return g_packet_id_in;
}

DWORD count_up_packet_id_out() {
	g_packet_id_out += 2;
	return g_packet_id_out;
}

DWORD get_packet_id_out() {
	return g_packet_id_out;
}

void AddExtra(PacketExtraInformation &pxi) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	pem = new PacketEditorMessage;

	if (!pem) {
		return;
	}

	pem->header = pxi.fmt;
	pem->id = pxi.id;
	pem->addr = pxi.addr;
	pem->Extra.pos = pxi.pos;
	pem->Extra.size = pxi.size;

	if (pxi.fmt == TV_ENCODEHEADER) {
		count_up_packet_id_out();
	}

	if (!gPipeClient->Send(b, sizeof(PacketEditorMessage))) {
		RestartPipeClient();
	}

	delete pem;
}

void AddSendPacket(TV_OutPacket *oPacket, ULONG_PTR addr, bool &bBlock) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + oPacket->encoded];

	if (!b) {
		return;
	}

	pem->header = SENDPACKET;
	pem->id = get_packet_id_out();
	pem->addr = addr;
	pem->Binary.length = oPacket->encoded;
	memcpy_s(pem->Binary.packet, oPacket->encoded, oPacket->packet, oPacket->encoded);

	if (!gPipeClient->Send(b, sizeof(PacketEditorMessage) + oPacket->encoded)) {
		RestartPipeClient();
	}
	else {
		std::wstring wResponse;
		gPipeClient->Recv(wResponse);
		if (wResponse.compare(L"Block") == 0) {
			bBlock = true;
		}
		else {
			bBlock = false;
		}
	}

	delete[] b;
}

void AddRecvPacket(TV_InPacket *iPacket, ULONG_PTR addr, bool &bBlock) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};
	b = new BYTE[sizeof(PacketEditorMessage) + iPacket->length - 0x04];
	if (!b) {
		return;
	}

	pem->header = RECVPACKET;
	pem->id = count_up_packet_id_in();
	pem->addr = addr;
	pem->Binary.length = iPacket->length - 0x04;
	memcpy_s(pem->Binary.packet, iPacket->length - 0x04, &iPacket->packet[4], iPacket->length - 0x04);

	//DEBUG(std::to_wstring(pem->id) + L" -> " + DatatoString(&iPacket->packet[4], iPacket->length - 4));

	if (!gPipeClient->Send(b, sizeof(PacketEditorMessage) + iPacket->length - 0x04)) {
		RestartPipeClient();
	}
	else {
		std::wstring wResponse;
		gPipeClient->Recv(wResponse);
		if (wResponse.compare(L"Block") == 0) {
			bBlock = true;
		}
		else {
			bBlock = false;
		}
	}

	delete[] b;
}