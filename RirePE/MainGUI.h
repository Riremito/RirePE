#ifndef __MAINGUI_H__
#define __MAINGUI_H__

#include"../Share/Simple/Simple.h"
#include"../RirePE/ControlList.h"
#include"../RirePE/RirePE.h"
#include"../RirePE/PacketLogger.h"
#include"../RirePE/PacketSender.h"
#include"../RirePE/FormatGUI.h"
#include"../RirePE/FilterGUI.h"
#include"../RirePE/Config.h"

#define PE_WIDTH 800
#define PE_HEIGHT 600

#define PE_DEBUG 1


bool MainGUI(HINSTANCE hInstance);
Alice& GetMainGUI();
bool UpdateLogger(PacketEditorMessage &pem, bool &bBlock);
bool UpdateStatus(PacketEditorMessage &pem);
void SetInfo(std::wstring wText);
int GetHeaderSize();
bool SetHeaderSize(int header_size);

std::wstring GetPipeNameLogger();
std::wstring GetPipeNameSender();

#endif