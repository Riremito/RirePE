# RirePE
+ Packet Editor for MapleStory
+ creating private server needs to understand packet format, so this tool helps understanding packet format
+ if this PE says OK, the packet format is correct, but real server has some NG format because server and client is not good coded
+ tested versions, JMS v164.0, v186.0, v409.2 (x64)
	+ v20x client has SendPacket Hook detection and send packet detection, it is also bypassed

## how to use
+ Run RirePE.exe and Inject Packet.dll to game client
	+ you have to remove or bypass mscrc and HackShield/xigncode/BlackCipher before injecting dll