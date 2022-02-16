#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <TlHelp32.h>
#include <tuple>
#include <fstream>
#include "mem.h"

int __cdecl main(int argc, char** argv)
{
	/*SOCKET sockfd; if ((sockfd = server::start()) == 0) return -1;
	char buf[512];
	int retv = 0;
	do {
		retv = recv(sockfd, buf, 512, 0);
	} while (!retv);

	for (uint32_t i = 0u; i < strlen(buf); i++)
		std::printf("%c\n", buf[i]);*/

	std::string argv_str(argv[0]);
	std::string _proc_name = std::string(argv_str.begin() + argv_str.find_last_of('\\') + 1, argv_str.end());
	std::printf("%s\n", argv_str.c_str());

	if (argv_str.find("_") == -1)
	{
		std::printf("[-] bad name, usage: dll_proc\n");
		std::getchar();
		return -1;
	}
	std::string dll_path = std::string(argv_str.begin(), argv_str.begin() + argv_str.find_last_of("\\") + 1).append(
		std::string(_proc_name.begin(), _proc_name.begin() + _proc_name.find_last_of("_"))).append(".dll");
	std::string proc_name = std::string(_proc_name.begin() + _proc_name.find_last_of("_") + 1, _proc_name.end());

	std::printf("%s, %s\n", dll_path.c_str(), proc_name.c_str());

	auto [pid, handle] = mem::get_pid(proc_name.c_str());
	//std::printf("%s, %i, %p\n", dll_path, pid, handle);

	//auto [pid, handle] = mem::get_pid(_xor_("hl2.exe"));
	if (!handle || handle == INVALID_HANDLE_VALUE || !pid)
	{
		std::printf("[-] process not found...\n");
		std::getchar();
		return -1;
	}

	//std::printf("pid: %p, handle: %p\n", pid, handle);

	if (!mem::manual_map(handle, dll_path.c_str()))
	{
		std::printf("[-] couldn't inject dll...\n");
		CloseHandle(handle);
		std::getchar();
		return -1;
	}

	CloseHandle(handle);
	return 1;
}
