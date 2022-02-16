#include <windows.h>
#include <TlHelp32.h>
#include <tuple>
#include <fstream>
#include "xorstr.h"
#include "mem.h"

static void stub() { }

namespace mem
{
	bool manual_map(void* handle, const char* path_dll)
	{
		if (!GetFileAttributes(path_dll)) return 0;

		std::ifstream file(path_dll, std::ios::binary | std::ios::ate);

		if (file.fail()) return 0;

		std::streampos dll_size = file.tellg();
		if (dll_size < 4096)
		{
			//std::printf(_xor_("Size too small\n").c_str());
			file.close();
			return 0;
		}

		std::uint8_t* raw_dll = new std::uint8_t[static_cast<std::uint32_t>(dll_size)];
		if (!raw_dll)
		{
			//std::printf(_xor_("Creating byte array failed\n").c_str());
			file.close();
			return 0;
		}

		file.seekg(0, std::ios::beg); // tellg sets the file pointer to the end.
		file.read(reinterpret_cast<char*>(raw_dll), dll_size);

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(raw_dll)->e_magic != 0x5A4D)
		{
			//std::printf(_xor_("Not a dll\n").c_str());
			file.close();
			delete[] raw_dll;
			return 0;
		}

		// get pointer to the nt header.
		IMAGE_NT_HEADERS* old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(raw_dll + reinterpret_cast<IMAGE_DOS_HEADER*>(raw_dll)->e_lfanew);
		IMAGE_OPTIONAL_HEADER* old_opt_header = &old_nt_header->OptionalHeader;
		IMAGE_FILE_HEADER* old_file_header = &old_nt_header->FileHeader;

		int8_t* target_base = reinterpret_cast<int8_t*>(VirtualAllocEx(handle, reinterpret_cast<void*>(old_opt_header->ImageBase), old_opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!target_base)
		{
			target_base = (int8_t*)VirtualAllocEx(handle, nullptr, old_opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!target_base)
			{
				//std::printf("Target base is null\n");
				file.close();
				delete[] raw_dll;
				return 0;
			}
		}

		manual_map_data data;
		data.load_library = LoadLibraryA;
		data.get_proc_address = GetProcAddress;

		IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(old_nt_header);
		for (std::uint32_t i = 0u; i != old_file_header->NumberOfSections; i++, section_header++)
		{
			if (section_header->SizeOfRawData)
			{
				if (!WriteProcessMemory(handle, target_base + section_header->VirtualAddress, raw_dll + section_header->PointerToRawData, section_header->SizeOfRawData, nullptr))
				{
					//std::printf("Failed to map sections\n");
					file.close();
					delete[] raw_dll;
					VirtualFreeEx(handle, target_base, 0, MEM_RELEASE);
					return 0;
				}
			}
		}

		memcpy(raw_dll, &data, sizeof(data));
		WriteProcessMemory(handle, target_base, raw_dll, 4096, nullptr); // fine

		delete[] raw_dll;

		void* shellcode_addr = VirtualAllocEx(handle, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellcode_addr)
		{
			//std::printf("Couldn't allocate shellcode memory\n");
			file.close();
			VirtualFreeEx(handle, target_base, 0, MEM_RELEASE);
			return 0;
		}

		WriteProcessMemory(handle, shellcode_addr, mem::shellcode, 4096, nullptr);

		void* thread = CreateRemoteThread(handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_addr), target_base, 0, nullptr);
		if (!thread || thread == INVALID_HANDLE_VALUE)
		{
			//std::printf("Couldn't create thread\n");
			file.close();
			VirtualFreeEx(handle, target_base, 0, MEM_RELEASE);
			VirtualFreeEx(handle, shellcode_addr, 0, MEM_RELEASE);
			return 0;
		}

		CloseHandle(thread);

		while (true)
		{
			manual_map_data data;
			ReadProcessMemory(handle, target_base, &data, sizeof(data), nullptr);
			if (data.module) break;
			Sleep(50);
		}

		CloseHandle(handle);
		VirtualFreeEx(handle, shellcode, 0, MEM_RELEASE);
		return 1;
	}

	bool manual_map(void* handle, std::uint8_t* raw_dll)
	{
		if (reinterpret_cast<IMAGE_DOS_HEADER*>(raw_dll)->e_magic != 0x5A4D)
		{
			//std::printf("Not a dll\n");
			return 0;
		}

		// get pointer to the nt header.
		IMAGE_NT_HEADERS* old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(raw_dll + reinterpret_cast<IMAGE_DOS_HEADER*>(raw_dll)->e_lfanew);
		IMAGE_OPTIONAL_HEADER* old_opt_header = &old_nt_header->OptionalHeader;
		IMAGE_FILE_HEADER* old_file_header = &old_nt_header->FileHeader;

		int8_t* target_base = reinterpret_cast<int8_t*>(VirtualAllocEx(handle, NULL, old_opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!target_base)
		{
			target_base = (int8_t*)VirtualAllocEx(handle, nullptr, old_opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!target_base)
			{
				//std::printf("Target base is null\n");
				return 0;
			}
		}

		manual_map_data data;
		data.load_library = LoadLibraryA;
		data.get_proc_address = GetProcAddress;

		IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(old_nt_header);
		for (std::uint32_t i = 0u; i != old_file_header->NumberOfSections; i++, section_header++)
		{
			// Make sure the section doesn't have only uninitialized data.
			if (section_header->SizeOfRawData)
			{
				if (!WriteProcessMemory(handle, target_base + section_header->VirtualAddress, raw_dll + section_header->PointerToRawData, section_header->SizeOfRawData, nullptr))
				{
					VirtualFreeEx(handle, target_base, 0, MEM_RELEASE);
					return 0;
				}
			}
		}

		// Write the manual_map_data struct pointer into the memory of the target process, as it's used by the shellcode function.

		memcpy(raw_dll, &data, sizeof(data));
		WriteProcessMemory(handle, target_base, raw_dll, 4096, nullptr); // fine

		void* shellcode_addr = VirtualAllocEx(handle, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellcode_addr)
		{
			//std::printf("Couldn't allocate shellcode memory\n");
			VirtualFreeEx(handle, target_base, 0, MEM_RELEASE);
			return 0;
		}

		WriteProcessMemory(handle, shellcode_addr, mem::shellcode, 0x1000, nullptr);

		// Pass in target base as the handle of module.
		void* thread = CreateRemoteThread(handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_addr), target_base, 0, nullptr);
		if (!thread || thread == INVALID_HANDLE_VALUE)
		{
			//std::printf("Couldn't create thread\n");
			VirtualFreeEx(handle, target_base, 0, MEM_RELEASE);
			VirtualFreeEx(handle, shellcode_addr, 0, MEM_RELEASE);
			return 0;
		}

		CloseHandle(thread);

		while (true)
		{
			manual_map_data data;
			ReadProcessMemory(handle, target_base, &data, sizeof(data), nullptr);
			if (data.module) break; // this checks if the shellcode succeeded.
			Sleep(50);
		}

		CloseHandle(handle);
		VirtualFreeEx(handle, shellcode, 0, MEM_RELEASE);
		return 1;
	}

	void __stdcall shellcode(manual_map_data* data)
	{
		if (!data) return;

		int8_t* base = (int8_t*)data;
		auto opt_header = &reinterpret_cast<IMAGE_NT_HEADERS*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew)->OptionalHeader;

		auto _load_library = data->load_library;
		auto _get_proc_address = data->get_proc_address;
		auto _dll_main = reinterpret_cast<bool(__stdcall*) (void*, DWORD, LPVOID)>(base + opt_header->AddressOfEntryPoint);

		int8_t* loc_delta = base - opt_header->ImageBase;
		if (loc_delta)
		{
			if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

			auto reloc = (IMAGE_BASE_RELOCATION*)(base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (reloc->VirtualAddress)
			{
				PWORD reloc_info = reinterpret_cast<PWORD>(reloc + 1);
				for (std::uint32_t i = 0u, entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					i < entries;
					i++)
				{
					if ((reloc_info[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
						*(std::uint32_t*)(base + (reloc->VirtualAddress + (reloc_info[i] & 0xFFF))) += reinterpret_cast<std::uint32_t>(loc_delta);
				}

				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>((LPBYTE)reloc + reloc->SizeOfBlock);
			}

			reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>((PBYTE)reloc + reloc->SizeOfBlock);
		}

		if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto import_dir = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (import_dir->Characteristics)
			{
				auto original_first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + import_dir->OriginalFirstThunk);
				auto first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + import_dir->FirstThunk);

				HMODULE module = _load_library(reinterpret_cast<char*>(base + import_dir->Name)); // import_dir->Name gives the rva to the dll name.
				if (!module) return; 
				if (!original_first_thunk) original_first_thunk = first_thunk;

				// can load by ordinal number or name.
				while (original_first_thunk->u1.AddressOfData)
				{
					std::uint32_t function;
					if (original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						function = (std::uint32_t)_get_proc_address(module, (LPSTR)(original_first_thunk->u1.Ordinal & 0xFFFF));
					else
						function = (std::uint32_t)_get_proc_address(module, ((IMAGE_IMPORT_BY_NAME*)((PBYTE)base + original_first_thunk->u1.AddressOfData))->Name);

					if (!function) return;
					first_thunk->u1.Function = function;

					original_first_thunk++;
					first_thunk++;
				}

				import_dir++;
			}
		}

		if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			// TLS callback is called right before the main/dllmain function.
			auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
			for (; callback && *callback; callback++)
				(*callback)(base, DLL_PROCESS_ATTACH, nullptr);
		}

		_dll_main(base, DLL_PROCESS_ATTACH, nullptr);

		data->module = base;
	}
}
