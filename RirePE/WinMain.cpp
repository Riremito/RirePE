#include"../RirePE/MainGUI.h"

int target_pid = 0;
std::wstring target_window_class; // MapleStoryClass

int get_target_pid() {
	return target_pid;
}

std::wstring& get_target_window_class() {
	return target_window_class;
}

std::wstring GetPipeNameLogger() {
	if (target_pid) {
		return PE_LOGGER_PIPE_NAME + std::to_wstring(target_pid);
	}
	return PE_LOGGER_PIPE_NAME;
}

std::wstring GetPipeNameSender() {
	if (target_pid) {
		return PE_SENDER_PIPE_NAME + std::to_wstring(target_pid);
	}
	return PE_SENDER_PIPE_NAME;
}

bool SetupMultiPEMode() {
	LPWSTR *szArglist = NULL;
	int nArgs = 0;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

	if (!szArglist) {
		return false;
	}

	if (2 <= nArgs) {
		target_pid = _wtoi(szArglist[1]);
	}

	if (3 <= nArgs) {
		target_window_class = szArglist[2];
	}

	LocalFree(szArglist);

	if (target_pid == 0) {
		return false;
	}

	return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	SetupMultiPEMode();
	LoadConfig();
	MainGUI(hInstance);
	return 0;
}