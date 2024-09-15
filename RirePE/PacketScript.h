#ifndef __PACKETSCRIPT_H__
#define __PACKETSCRIPT_H__

#include<Windows.h>
#include<string>
#include<vector>
#include<regex>
#include<sstream>
#include<istream>
#include<iostream>

// originally written for Tenvi
class ServerPacket {
private:
	std::vector<BYTE> packet;
	bool UTF16toShiftJIS(std::wstring utf16, std::string &sjis);
public:
	std::vector<BYTE>& get();
	void Header(WORD val);
	void Encode1(BYTE val);
	void Encode2(WORD val);
	void Encode4(DWORD val);
	void EncodeFloat(float val);
	void Encode8(ULONGLONG val);
	bool EncodeStr(std::wstring val);
	bool EncodeBuffer(std::wstring val); // no size header
};


class RScript {
private:
	std::vector<std::wstring> src;
	ServerPacket sp;

	bool DataParse(std::wstring data, ULONGLONG &uData);
	bool DataParseFloat(std::wstring data, float &fData);
	bool WStrParse(std::wstring data, std::wstring &wData);
	bool Parse(std::wstring input);

public:
	RScript(std::wstring wScript);
	~RScript();
	std::wstring getRaw(); // GetText
	bool Parse();
};

#endif