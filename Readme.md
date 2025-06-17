# RirePE
## How to use
+ setup
	+ put Packet.dll and RirePE.exe in same folder.
	+ inject Packet.dll to the process.
+ usage
	+ you can send/recv packet by pressing button.
	+ you can check packet format by opening format viewer.
	+ if your client gets crash by receiving packet, last packet seems something wrong.
		+ you can easily understand where you should fix.
+ format viewer
	+ this shows packet format that you selected in main window.
	+ you can check the packet format is correct or not by checking status.
		+ OK means packet buffer is fully used, it means packet length is correct.
		+ NG means packet buffer is not fully decoded, it means packet length is incorrect.
	+ return address is used to check where client uses the packet data.
		+ you can easily find which address you should see.

## How this tool works
+ Packet.dll hooks functions related to writing and reading packets to detect packet formats.
+ Packet.dll runs RirePE.exe to start logging packets.
+ RirePE.exe is just for UI.

## Config
+ TODO

## Note
+ around BB updates client started protecting SendPacket function, you need to bypass check to hook the function.