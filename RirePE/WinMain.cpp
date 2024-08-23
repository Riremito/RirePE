#include"../RirePE/MainGUI.h"

int target_pid = 0;
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