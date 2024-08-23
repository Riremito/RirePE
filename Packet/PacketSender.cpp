#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"
#include"../Packet/PacketHook.h"
#include"../RirePE/RirePE.h"

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
#ifdef _WIN64
		WORD wHeader = *(WORD *)&pcm->Binary.packet[0];
		OutPacket p;
		memset(&p, 0, sizeof(p));
		COutPacket_Hook(&p, wHeader);

		WORD wEncryptedHeader = *(WORD *)&p.packet[0];
		p.encoded = (DWORD)pcm->Binary.length;
#if MAPLE_VERSION <= 414
		p.packet = &pcm->Binary.packet[0];
#else
		memcpy_s(&p.packet[0], pcm->Binary.length, &pcm->Binary.packet[0], pcm->Binary.length);
#endif
		if (wHeader != wEncryptedHeader) {
			*(WORD *)&p.packet[0] = wEncryptedHeader;
			SendPacket_EH_Hook(&p);
		}
		else {
			SendPacket_Hook(_CClientSocket(), &p);
		}
#else
		OutPacket tp;
		COutPacket_Hook(&tp, 0, *(WORD *)&pcm->Binary.packet[0]);

		OutPacket p = { 0x00, &pcm->Binary.packet[0] , pcm->Binary.length, 0x00 };
		EnterSendPacket_Hook(&p);
#endif
	}
	else {
		std::vector<BYTE> packet;
		packet.resize(pcm->Binary.length + 0x04);
		packet[0] = 0xF7;
		packet[1] = 0x39;
		packet[2] = 0xEF;
		packet[3] = 0x39;
		memcpy_s(&packet[4], pcm->Binary.length, &pcm->Binary.packet[0], pcm->Binary.length);
#ifdef _WIN64
		WORD wHeader = *(WORD *)&pcm->Binary.packet[0];
		wHeader = *(WORD *)&packet[0];
		InPacket p = { 0x00, 0x02, &packet[0], (DWORD)packet.size(), wHeader, (DWORD)pcm->Binary.length, 0x04 };
		ProcessPacket_Hook(_CClientSocket(), &p);
#else
		InPacket p = { 0x00, 0x02, &packet[0], (WORD)packet.size(), 0x00, (WORD)pcm->Binary.length, 0x00, 0x04 };
		ProcessPacket_Hook((void *)GetCClientSocket(), 0, &p);
#endif
	}
}

decltype(CreateWindowExA) *_CreateWindowExA = NULL;
HWND WINAPI CreateWindowExA_Hook(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
	if (lpClassName && strcmp(lpClassName, "MapleStoryClass") == 0) {
		HWND hRet = _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
		if (!bInjectorCallback) {
			bInjectorCallback = true;
			SetTimer(hRet, 1337, 50, PacketInjector);
			DEBUG(L"MAIN THREAD OK 2");
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
				if (wcscmp(wcClassName, L"MapleStoryClass") == 0) {
					if (!bInjectorCallback) {
						bInjectorCallback = true;
						SetTimer(hwnd, 1337, 50, PacketInjector);
						DEBUG(L"MAIN THREAD OK 1");
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
	PipeServer ps(GetPipeNameSender());
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