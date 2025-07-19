#include"../RirePE/PacketScript.h"
#include"../Share/Simple/Simple.h"

// ServerPacket
std::vector<BYTE>& ServerPacket::get() {
	return packet;
}

void ServerPacket::Header(WORD val) {
	return Encode2(val);
}

void ServerPacket::Encode1(BYTE val) {
	packet.push_back(val);
}
void ServerPacket::Encode2(WORD val) {
	packet.push_back(val & 0xFF);
	packet.push_back((val >> 8) & 0xFF);
}
void ServerPacket::Encode4(DWORD val) {
	packet.push_back(val & 0xFF);
	packet.push_back((val >> 8) & 0xFF);
	packet.push_back((val >> 16) & 0xFF);
	packet.push_back((val >> 24) & 0xFF);
}

void ServerPacket::EncodeFloat(float val) {
	Encode4(*(DWORD *)&val);
}

void ServerPacket::Encode8(ULONGLONG val) {
	Encode4((DWORD)val);
	Encode4((DWORD)(val >> 32));
}


bool ServerPacket::UTF16toShiftJIS(std::wstring utf16, std::string &sjis) {
	try {
		//  get sjis length
		int len = WideCharToMultiByte(CP_ACP, 0, utf16.c_str(), -1, 0, 0, 0, 0);
		if (!len) {
			return false;
		}
		// convert utf16 to sjis or your codepage settings
		std::vector<BYTE> b(len + 1);
		if (!WideCharToMultiByte(CP_ACP, 0, utf16.c_str(), -1, (char *)&b[0], len, 0, 0)) {
			return false;
		}
		sjis = std::string((char *)&b[0]);
	}
	catch (...) {
		return false;
	}

	return true;
}

bool ServerPacket::EncodeStr(std::wstring val) {
	std::string str;

	if (val.length() != 0) {
		if (!UTF16toShiftJIS(val, str)) {
			return false;
		}
	}

	if (0xFFFF < str.length()) {
		str = ""; // not supported
	}

	Encode2((WORD)str.length());
	for (size_t i = 0; i < str.length(); i++) {
		Encode1((BYTE)str.at(i));
	}

	return true;
}

bool ServerPacket::EncodeBuffer(BYTE *val, size_t size) {
	if (size == 0) {
		return false;
	}

	for (size_t i = 0; i < size; i++) {
		Encode1(val[i]);
	}

	return true;
}

bool ServerPacket::EncodeStrW1(std::wstring val) {
	Encode1((BYTE)val.length());
	for (size_t i = 0; i < val.length(); i++) {
		Encode2((WORD)val.at(i));
	}
	return true;
}

bool ServerPacket::EncodeStrW2(std::wstring val) {
	Encode2((WORD)val.length());
	for (size_t i = 0; i < val.length(); i++) {
		Encode2((WORD)val.at(i));
	}
	return true;
}


// RScript
RScript::RScript(std::wstring wScript, int hs) {
	//input = wScript;
	header_size = hs;

	std::wistringstream MyStream(wScript);
	std::wstring s;

	while (std::getline(MyStream, s)) {
		src.push_back(s);
		std::wcout << s << std::endl;
	}
}

RScript::~RScript() {
}

enum FORMAT_TYPE {
	TYPE_UNK,
	TYPE_ENCODE_1,
	TYPE_ENCODE_2,
	TYPE_ENCODE_4,
	TYPE_ENCODE_FLOAT,
	TYPE_ENCODE_8,
	TYPE_ENCODE_STR,
	TYPE_ENCODE_BUFFER,
	TYPE_ENCODE_STRW1,
	TYPE_ENCODE_STRW2,
};

bool RScript::DataParse(std::wstring data, ULONGLONG &uData) {
	uData = 0;

	std::wsmatch match;
	// hex
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(0x|@|)([0-9A-Fa-f]+))")) && match.size() >= 2) {
		swscanf_s(match[2].str().c_str(), L"%llX", &uData);
		//DEBUG(L"DataParse hex : " + match[2].str());
		return true;
	}
	// int
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(#-)(\d+))")) && match.size() >= 2) {
		swscanf_s(match[2].str().c_str(), L"%lld", &uData);
		uData = ~uData + 1;
		//DEBUG(L"DataParse int- : " + match[2].str());
		return true;
	}
	// int
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(#)(\d+))")) && match.size() >= 2) {
		swscanf_s(match[2].str().c_str(), L"%lld", &uData);
		//DEBUG(L"DataParse int+ : " + match[2].str());
		return true;
	}

	DEBUG(L"DataParse : Error");
	return false;
}

bool RScript::DataParseFloat(std::wstring data, float &fData) {
	fData = 0;
	ULONGLONG uData = 0;

	std::wsmatch match;
	// hex
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(0x|@|)([0-9A-Fa-f]+))")) && match.size() >= 2) {
		swscanf_s(match[2].str().c_str(), L"%llX", &uData);
		//DEBUG(L"DataParse hex : " + match[2].str());
		return true;
	}
	// int
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(#-)(\d+))")) && match.size() >= 2) {
		swscanf_s(match[2].str().c_str(), L"%lld", &uData);
		uData = ~uData + 1;
		fData = (float)((int)uData);
		//DEBUG(L"DataParseFloat- : " + match[2].str());
		return true;
	}
	// int
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(#)(\d+))")) && match.size() >= 2) {
		swscanf_s(match[2].str().c_str(), L"%lld", &uData);
		fData = (float)((int)uData);
		//DEBUG(L"DataParseFloat+ : " + match[2].str());
		return true;
	}

	DEBUG(L"DataParseFloat : Error");
	return false;
}

bool RScript::DataParseStr(std::wstring data, std::wstring &wData) {
	wData = L"";

	std::wsmatch match;

	// "Str"
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(L|)\"(.*)\")")) && match.size() >= 2) {
		wData = match[2].str();
		//DEBUG(L"DataParseStr : " + match[2].str());
		return true;
	}

	DEBUG(L"DataParseStr : Error");
	return false;
}

bool RScript::DataParseBuffer(std::wstring data, std::vector<BYTE> &vData) {
	vData.clear();

	std::wsmatch match;

	// "Str"
	if (std::regex_search(data, match, std::wregex(LR"(^\s*(\'|)([0-9A-Fa-f]+)(\'|))")) && match.size() >= 3) {
		std::wstring bufstr = match[2].str();

		DWORD byte = 0;
		if (bufstr.length() % 2 != 0) {
			//DEBUG(L"DataParseBuffer : Error (half byte)");
			return false;
		}

		size_t loop = bufstr.length() / 2;
		for (size_t i = 0; i < loop; i++) {
			swscanf_s(&bufstr.c_str()[i*2], L"%02X", &byte);
			vData.push_back((BYTE)byte);
		}
		//DEBUG(L"DataParseBuffer : " + match[2].str());
		return true;
	}

	DEBUG(L"DataParseBuffer : Error");
	return false;
}


bool RScript::Parse() {
	for (auto src_line : src) {
		Parse(src_line);
	}
	return true;
}

bool RScript::Parse(std::wstring input) {
	std::wsmatch match;

	FORMAT_TYPE type = TYPE_UNK;
	std::wstring data;

	// LR"(^\s*(Encode1)\s*\(([0-9A-Fa-f]+)\))"
	if (std::regex_search(input, match, std::wregex(LR"(^\s*(Header)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_2;
		if (header_size == 1) {
			type = TYPE_ENCODE_1;
		}
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(Encode1)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_1;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(Encode2)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_2;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(Encode4)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_4;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(EncodeFloat)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_FLOAT;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(Encode8)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_8;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(EncodeStr)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_STR;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(EncodeBuffer)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_BUFFER;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(EncodeStrW1)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_STRW1;
		data = match[2];
	}
	else if (std::regex_search(input, match, std::wregex(LR"(^\s*(EncodeStrW2)\s*\((.*)\))")) && match.size() >= 2) {
		type = TYPE_ENCODE_STRW2;
		data = match[2];
	}
	else {
		return false;
	}

	switch (type) {
	case TYPE_ENCODE_1:
	{
		ULONGLONG val = 0;
		if (!DataParse(data, val)) {
			return false;
		}
		sp.Encode1((BYTE)val);
		return true;
	}
	case TYPE_ENCODE_2:
	{
		ULONGLONG val = 0;
		if (!DataParse(data, val)) {
			return false;
		}
		sp.Encode2((WORD)val);
		return true;
	}
	case TYPE_ENCODE_4:
	{
		ULONGLONG val = 0;
		if (!DataParse(data, val)) {
			return false;
		}
		sp.Encode4((DWORD)val);
		return true;
	}
	case TYPE_ENCODE_8:
	{
		ULONGLONG val = 0;
		if (!DataParse(data, val)) {
			return false;
		}
		sp.Encode8(val);
		return true;
	}
	case TYPE_ENCODE_STR: {
		std::wstring val;
		DataParseStr(data, val);
		sp.EncodeStr(val);
		return true;
	}
	case TYPE_ENCODE_BUFFER: {
		std::wstring val;
		std::vector<BYTE> v;
		DataParseBuffer(data, v);
		sp.EncodeBuffer(&v[0], v.size());
		return true;
	}
	case TYPE_ENCODE_FLOAT:
	{
		float val = 0;
		if (!DataParseFloat(data, val)) {
			return false;
		}
		sp.EncodeFloat(val);
		return true;
	}
	case TYPE_ENCODE_STRW1:
	{
		std::wstring val;
		DataParseStr(data, val);
		sp.EncodeStrW1(val);
		return true;
	}
	case TYPE_ENCODE_STRW2:
	{
		std::wstring val;
		DataParseStr(data, val);
		sp.EncodeStrW2(val);
		return true;
	}
	default:
	{
		return false;
	}
	}

	return false;
}


std::wstring RScript::getRaw() {
	std::wstring rp;

	if (sp.get().size() < header_size) {
		rp = L"ERROR (too short)";
		return rp;
	}

	switch (header_size) {
	case 1:
	{
		// header
		rp = L"@" + BYTEtoString(sp.get()[0]);
		break;
	}
	default:
	{
		// header
		rp = L"@" + WORDtoString(*(WORD *)&sp.get()[0]);
		break;
	}
	}

	if (header_size < sp.get().size()) {
		rp += L" " + DatatoString(&sp.get()[header_size], sp.get().size() - header_size, true);
	}

	return rp;
}