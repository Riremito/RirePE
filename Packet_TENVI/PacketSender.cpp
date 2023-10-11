#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#include"../RirePE/RirePE.h"
#include"PacketHook.h"

bool bInjectorCallback = false;
bool bToBeInject = false;
std::vector<BYTE> global_data;
VOID CALLBACK PacketInjector(HWND, UINT, UINT_PTR, DWORD) {
	if (!bToBeInject) {
		return;
	}
	std::vector<BYTE> data = global_data;
	bToBeInject = false;

	PacketEditorMessage *pcm = (PacketEditorMessage *)&data[0];
	if (pcm->header == SENDPACKET) {
		OutPacket tp;
		COutPacket_Hook(&tp, 0, pcm->Binary.packet[0], 0);

		OutPacket p = { 0x00, &pcm->Binary.packet[0] , 0, 0, 0, pcm->Binary.length};
		EnterSendPacket_Hook(&p);
	}
	else {
		std::vector<BYTE> packet;
		packet.resize(pcm->Binary.length + 0x04);
		packet[0] = 0xF7;
		packet[1] = 0x39;
		packet[2] = 0xEF;
		packet[3] = 0x39;
		memcpy_s(&packet[4], pcm->Binary.length, &pcm->Binary.packet[0], pcm->Binary.length);
		InPacket p = { 0x00, 0x02, &packet[0], 0x01, 0, 0, (WORD)packet.size(), 0, 0, 0x04 };
		//packet_id_in++;
		MyProcessPacket(&p);


		//packet_id_in++;
	}
}

decltype(CreateWindowExA) *_CreateWindowExA = NULL;
HWND WINAPI CreateWindowExA_Hook(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
	if (lpClassName && (strcmp(lpClassName, "EngineClass") == 0 || strcmp(lpClassName, "TenviXEngine") == 0)) {
		HWND hRet = _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
		if (!bInjectorCallback) {
			bInjectorCallback = true;
			SetTimer(hRet, 1337, 50, PacketInjector);
			DEBUG(L"main thread is found by CreateWindowExA");
		}
		return hRet;
	}
	return _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

BOOL CALLBACK SearchMaple(HWND hwnd, LPARAM lParam) {
	DWORD pid = 0;
	WCHAR wcClassName[256] = { 0 };
	if (GetWindowThreadProcessId(hwnd, &pid)) {
		if (pid == GetCurrentProcessId()) {
			if (GetClassNameW(hwnd, wcClassName, _countof(wcClassName) - 1)) {
				if (wcscmp(wcClassName, L"EngineClass") == 0 || wcscmp(wcClassName, L"TenviXEngine") == 0) {
					if (!bInjectorCallback) {
						bInjectorCallback = true;
						SetTimer(hwnd, 1337, 50, PacketInjector);
						DEBUG(L"main thread is found by EnumWindows");
					}
				}
				return FALSE;
			}
		}
	}
	return TRUE;
}

bool SetCallBack() {
	if (bInjectorCallback) {
		return true;
	}

	EnumWindows(SearchMaple, NULL);
	return bInjectorCallback;
}

bool CommunicateThread(PipeServerThread& psh) {
	std::vector<BYTE> data;
	if (psh.Recv(data) && !bToBeInject) {
		global_data.clear();
		global_data = data;
		bToBeInject = true;
	}
	return true;
}

bool PacketSender() {
	PipeServer ps(PE_SENDER_PIPE_NAME);
	ps.SetCommunicate(CommunicateThread);
	return ps.Run();
}

bool SetCallBackThread() {
	while (bInjectorCallback == false) {
		SetCallBack();
		Sleep(1000);
	}

	return true;
}

bool SetBackdoor() {
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SetCallBackThread, NULL, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	SHook(CreateWindowExA);
	return true;
}

bool RunPacketSender() {
	SetBackdoor();

	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)PacketSender, NULL, NULL, NULL);

	if (!hThread) {
		return false;
	}

	CloseHandle(hThread);
	return true;
}