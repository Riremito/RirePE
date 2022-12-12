#include"PacketHook.h"
#include"../Share/Simple/Simple.h"
#include"../RirePE/RirePE.h"
//innclude"../Share/Hook/SimpleHook.h"

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
		COutPacket_Hook(&tp, 0, *(WORD *)&pcm->Binary.packet[0]);

		OutPacket p = { 0x00, &pcm->Binary.packet[0] , pcm->Binary.length, 0x00 };
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
		InPacket p = { 0x00, 0x02, &packet[0], (DWORD)packet.size(), 0x00, (DWORD)pcm->Binary.length, 0x00, 0x04 };
		ProcessPacket_Hook((void *)GetCClientSocket(), 0, &p);
	}
}

decltype(CreateWindowExA) *_CreateWindowExA = NULL;
HWND WINAPI CreateWindowExA_Hook(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
	if (lpClassName && strcmp(lpClassName, "MapleStoryClass") == 0) {
		HWND hRet = _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
		SetTimer(hRet, 1337, 50, PacketInjector);
		return hRet;
	}
	return _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
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
	PipeServer ps(L"PacketSender");
	ps.SetCommunicate(CommunicateThread);
	return ps.Run();
}

bool SetBackdoor() {
	//SHook(CreateWindowExA);
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