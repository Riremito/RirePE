#ifndef __MAINGUI_H__
#define __MAINGUI_H__

#include"../Share/Simple/Simple.h"
#include"../RirePE/ControlList.h"
#include"../RirePE/RirePE.h"
#include"../RirePE/PacketLogger.h"
#include"../RirePE/PacketSender.h"

#define PE_WIDTH 800
#define PE_HEIGHT 768

#define PE_DEBUG 1


bool MainGUI(HINSTANCE hInstance);
Alice& GetMainGUI();
bool UpdateLogger(PacketEditorMessage &pem, bool bBlock);
void SetInfo(std::wstring wText);

#endif