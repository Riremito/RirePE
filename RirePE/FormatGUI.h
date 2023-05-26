#ifndef __FORMATGUI_H__
#define __FORMATGUI_H__

#define FV_WIDTH 800
#define FV_HEIGHT 600

enum FVSubControl {
	FV_LISTVIEW_FORMAT = 100,
	FV_EDIT_INFO,
};

enum FVListViewIndex {
	FV_LV_INDEX,
	FV_LV_RETURN,
	FV_LV_POSITION,
	FV_LV_TYPE,
	FV_LV_SIZE,
	FV_LV_MODIFIED,
	FV_LV_DATA,
	FV_LV_DATA_INT,
};

bool InitFormatGUI(HINSTANCE hInstance);
bool OpenFormatGUI();
HWND FVGet();
bool UpdateFV(PacketData &pd);
bool SetExtraInfo(std::vector<PacketData>& vpd, DWORD id);
std::wstring GetFormatData(PacketData &pd, PacketFormat &pf);

#endif