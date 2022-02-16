#pragma once

//#define DUMP_DLL_BYTES

typedef struct
{
	HMODULE(__stdcall* load_library) (const char*);
	FARPROC(__stdcall* get_proc_address) (HMODULE, const char*);
	void* module;

} manual_map_data;

namespace mem
{
	__forceinline auto get_pid(const char* proc) noexcept -> std::tuple<std::uint32_t, void*>
	{
		void* procs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!procs) return std::make_tuple(0, nullptr);

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		std::uint32_t pid = 0;
		void* handle = nullptr;

		if (Process32First(procs, &entry))
		{
			do {
				if (!_strcmpi(proc, entry.szExeFile))
				{
					pid = entry.th32ProcessID;
					handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
				}
			} while (Process32Next(procs, &entry));
		}

		CloseHandle(procs);
		return std::make_tuple(pid, handle);
	}

	__forceinline auto get_Iinfo() noexcept -> std::tuple<const char*, std::uint32_t, void*>
	{
		void* procs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!procs) return std::make_tuple(nullptr, 0, nullptr);

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		std::uint32_t pid = 0;
		void* handle = nullptr;
		std::string name = "";

		if (Process32First(procs, &entry))
		{
			do {
				if (strlen(name.c_str()) != 0)
				{
					if (!_strcmpi(name.c_str(), entry.szExeFile))
					{
						std::printf("found\n");
						pid = entry.th32ProcessID;
						handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
					}
				}
				
				std::int32_t retv = std::string_view(entry.szExeFile).find(".exe");

				if ((GetModuleHandle(entry.szExeFile) == GetModuleHandle(0)) && retv != -1 && strlen(name.c_str()) == 0)
				{
					std::printf("name: %s, wname: 0x%.2x, wnull: 0x%.2x\n", entry.szExeFile, GetModuleHandle(entry.szExeFile), GetModuleHandle(0));

					if (strlen(name.c_str()) == 0)
					{
						std::string_view _name = entry.szExeFile;
						name = _name.substr(2, _name.size()).data();
						
						std::printf("%s\n", name.data());
						
						std::printf("reseting\n");
						Process32First(procs, &entry);
					}
				}
			} while (Process32Next(procs, &entry));
		}

		CloseHandle(procs);
		return std::make_tuple(name.c_str(), pid, handle);
	}

	bool manual_map(void*, const char*);
	bool manual_map(void*, std::uint8_t*);
	void __stdcall shellcode(manual_map_data*);

#ifdef DUMP_DLL_BYTES
	__forceinline void dump_dll_bytes(const char* path_dll)
	{
		if (!GetFileAttributes(path_dll)) return;

		std::ifstream file(path_dll, std::ios::binary | std::ios::ate);
		if (file.fail()) return;

		std::streampos dll_size = file.tellg();
		if (dll_size < 4096) return;

		std::uint8_t* raw_dll = new std::uint8_t[static_cast<uint32_t>(dll_size)];

		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char*>(raw_dll), dll_size);

		file.close();
		
		FILE* txtfile = std::fopen("raw_binary_2.txt", "w");

		std::fprintf(txtfile, "constexpr std::uint8_t raw_binary[] =\n{\n\t");
		for (std::uint32_t i = 0u; i < dll_size; i++)
		{
			if (i != 0 && !(i % 12))
				std::fprintf(txtfile, "\n\t");

			if (i != (static_cast<std::uint32_t>(dll_size) - 1u))
				std::fprintf(txtfile, "0x%.2X, ", raw_dll[i]);
			else if (i == (static_cast<std::uint32_t>(dll_size) - 1u))
				std::fprintf(txtfile, "0x%.2X\n", raw_dll[i]);
		}
		std::fprintf(txtfile, "};");

		std::fclose(txtfile);
	} 
#endif
}
