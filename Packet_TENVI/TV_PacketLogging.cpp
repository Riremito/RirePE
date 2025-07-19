#include"TV_PacketLogging.h"

PipeClient *gPipeClient = NULL;
int gTarget_pid = 0;

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
	//RunPacketSender();
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

// logger
DWORD packet_id_out = 2; // 偶数
DWORD packet_id_in = 1; // 奇数

DWORD CountUpPacketID(DWORD &id) {
	id += 2;
	return id;
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

	if (!gPipeClient->Send(b, sizeof(PacketEditorMessage))) {
		RestartPipeClient();
	}

	delete pem;
}

void AddSendPacket(TV_OutPacket *p, ULONG_PTR addr, bool &bBlock) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};

	b = new BYTE[sizeof(PacketEditorMessage) + p->encoded];

	if (!b) {
		return;
	}

	pem->header = SENDPACKET;
	pem->id = packet_id_out; // ???
	pem->addr = addr;
	pem->Binary.length = p->encoded;
	memcpy_s(pem->Binary.packet, p->encoded, p->packet, p->encoded);

	if (!gPipeClient->Send(b, sizeof(PacketEditorMessage) + p->encoded)) {
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

void AddRecvPacket(TV_InPacket *p, ULONG_PTR addr, bool &bBlock) {
	union {
		PacketEditorMessage *pem;
		BYTE *b;
	};
	b = new BYTE[sizeof(PacketEditorMessage) + p->length - 0x04];
	if (!b) {
		return;
	}

	pem->header = RECVPACKET;
	pem->id = packet_id_in;
	pem->addr = addr;
	pem->Binary.length = p->length - 0x04;
	memcpy_s(pem->Binary.packet, p->length - 0x04, &p->packet[4], p->length - 0x04);
	if (!gPipeClient->Send(b, sizeof(PacketEditorMessage) + p->length - 0x04)) {
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
