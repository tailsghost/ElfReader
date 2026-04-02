#pragma once
#define NOMINMAX

#include <stdexcept>
#include <filesystem>
#include <cstdint>

#include <NinjaCallback.h>
#include "elfio/elfio.hpp"

#ifdef _MSC_VER
#   define API_ELF __stdcall
#else
#   define API_ELF
#endif

#ifdef ELFREADER_EXPORTS
#   define ELFREADER_API __declspec(dllexport)
#else
#   define ELFREADER_API __declspec(dllimport)
#endif

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#ifdef new_size
#undef new_size
#endif
#ifdef new_data_size
#undef new_data_size
#endif

using namespace callback;

namespace elfreader
{
	typedef struct CLineEntry {
		char* file;
		char* address;
		uint32_t line;
		int is_stmt;
		int basic_block;
		uint32_t view_val;
		uint32_t hexAddress;
		mutable int32_t isStartFunction;
	} CLineEntry;

	struct MemberInfoC
	{
		const wchar_t* name;
		const wchar_t* type;
		uint64_t byte_offset;
		uint64_t bit_size;

		MemberInfoC* fields;
		size_t fields_count;
	};

	struct StructInfoC
	{
		const wchar_t* name;
		uint64_t size;

		MemberInfoC* members;
		size_t members_count;
	};


	struct MemorySizes {
		int32_t text = 0;
		int32_t data = 0;
		int32_t bss = 0;
		int32_t flash = 0;
		int32_t ram = 0;
		int32_t binSize = 0;
		int32_t dec = 0;
	};

	struct LineEntry
	{
		std::string file;
		std::string address;

		uint32_t hexAddress;

		uint32_t line;
		//флаг "statement", является ли данная точка адреса началом исполняемого выражения
		bool is_stmt;
		//флаг "начало basic block" (DW_LNS_set_basic_block), эта точка адреса является началом нового basic в машинном коде
		bool basic_block;
		uint32_t view;

		mutable int32_t isStartFunction = 0;
	};

	class ELFREADER_API  ElfReader {
	public:
		ElfReader(build_callback cb) : m_cb(cb) {}
		MemorySizes* Analyze(const std::filesystem::path& elfPath);
		int ParseDebugLine(const std::filesystem::path& elfPath, std::vector<LineEntry>& out_lines, std::vector<std::string>& filteredName, int only_stmt);

		void FindFunctionLine(
			ELFIO::elfio& reader,
			const std::string& funcName,
			std::vector<LineEntry>& lines);
	private:
		build_callback m_cb;

		static MemorySizes* AllocateMemorySizes();

		static bool FiltredResult(std::vector<std::string>& filteredName, const std::string& name);
		static void ReadLineHeader(const char* data, uint8_t& value, const size_t& size, size_t& offset);
		static uint64_t ReadUleb(const char* data, const size_t size, size_t& offset);
		static int64_t ReadSleb(const char* data, const size_t size, size_t& offset);
		static uint32_t ReadU32(const char* data, const size_t size, size_t& offset);
		static uint64_t ReadAddrBytes(const char* data, size_t size, size_t& offset, size_t n);
		static std::string ExtractFilename(const std::string& path);
		static std::string ToHexAddr(uint64_t value);

	};


	extern "C" {

		ELFREADER_API int API_ELF GetSymbols(const wchar_t** filters, size_t filterCount,
			callback::build_callback cb,
			CLineEntry** outArray, size_t* outCount,
			const wchar_t* path, int only_stmt);

		ELFREADER_API void API_ELF FreeSymbols(CLineEntry* arr, size_t count);

		ELFREADER_API int API_ELF ElfAnalyze(const wchar_t* path, callback::build_callback cb, MemorySizes** memory);


		ELFREADER_API void API_ELF DeleteMemory(MemorySizes* memory);

		ELFREADER_API int API_ELF GetStructInfo(const wchar_t* path,const wchar_t* structName, StructInfoC** info, callback::build_callback cb);
		ELFREADER_API void API_ELF RemoveStructInfo(StructInfoC* info, callback::build_callback cb);
	}
}
