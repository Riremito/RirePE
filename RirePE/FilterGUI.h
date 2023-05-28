#ifndef __FILTERGUI_H__
#define __FILTERGUI_H__

#define IG_WIDTH 400
#define IG_HEIGHT 300

enum FilterType {
	NORMAL_PACKET,
	IGNORE_PACKET,
	BLOCK_PACKET,
};

enum IGSubControl {
	IG_LISTVIEW_FORMAT = 100,
	IG_BUTTON_SAVE_CONFIG,
	IG_STATIC_SEND,
	IG_EDIT_HEADER_SEND,
	IG_BUTTON_IGNORE_SEND,
	IG_BUTTON_BLOCK_SEND,
	IG_BUTTON_DELETE_SEND,
	IG_STATIC_RECV,
	IG_EDIT_HEADER_RECV,
	IG_BUTTON_IGNORE_RECV,
	IG_BUTTON_BLOCK_RECV,
	IG_BUTTON_DELETE_RECV,
};

enum IGListViewIndex {
	IG_LV_PACKET_TYPE,
	IG_LV_FILTER_TYPE,
	IG_LV_HEADER,
};


bool InitFilterGUI(HINSTANCE hInstance);
bool OpenFilterGUI();
bool CheckFilter(PacketEditorMessage &pem, FilterType &ft);
bool SetFilterHeader(MessageHeader type, std::wstring wHeader);
bool AutoIgnore(PacketEditorMessage &pem);
bool LoadFilterList(MessageHeader mh, FilterType ft, std::wstring Input);
bool GetFilterList(MessageHeader mh, FilterType ft, std::wstring &wOutput);

#endif