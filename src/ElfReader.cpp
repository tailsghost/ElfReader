#include <ElfReader.h>
#include <stdexcept>
#include <filesystem>

#include <elfio/elfio.hpp>

MemorySizes* ElfReader::AllocateMemorySizes()
{
	auto size = sizeof(MemorySizes);
	auto mem = static_cast<MemorySizes*>(CoTaskMemAlloc(size));
	if (mem) memset(mem, 0, size);
	return mem;
}

uint64_t ElfReader::ReadUleb(const char* data, const size_t size, size_t& offset)
{
	uint64_t result = 0;
	int32_t shift = 0;
	while (offset < size)
	{
		auto byte = static_cast<uint8_t>(data[offset++]);
		result |= static_cast<uint64_t>(byte & 0x7F) << shift;        //сбрасываем старший бит
		if ((byte & 0x80) == 0) break;								//проверяем старший бит (Формат LEB128)
		shift += 7;
	}
	return result;
}

int64_t ElfReader::ReadSleb(const char* data, const size_t size, size_t& offset)
{
	int64_t result = 0;
	int32_t shift = 0;
	uint8_t byte = 0;

	do
	{
		if (offset >= size) break;
		byte = static_cast<uint8_t>(data[offset++]);
		result |= static_cast<int64_t>(byte & 0x7F) << shift;
		shift += 7;
	} while (byte & 0x80);
	if (shift < 64 && (byte & 0x40))								// Проверяем 6 бит, если он установлен, то переворачиваем значение
		result |= -(static_cast<int64_t>(1) << shift);
	return result;
}

uint32_t ElfReader::ReadU32(const char* data, const size_t size, size_t& offset)
{
	if (offset + 4 > size) { offset = size; return 0; }
	const uint32_t result = (static_cast<uint8_t>(data[offset]))
		| (static_cast<uint8_t>(data[offset + 1]) << 8)
		| (static_cast<uint8_t>(data[offset + 2]) << 16)
		| (static_cast<uint8_t>(data[offset + 3]) << 24);
	offset += 4;
	return result;
}

uint64_t ElfReader::ReadAddrBytes(const char* data, size_t size, size_t& offset, size_t addr_size)
{
	uint64_t result = 0;
	if (offset + addr_size > size) { offset = size; return result; }
	for (size_t i = 0; i < addr_size && i < 8; ++i)
		result |= static_cast<uint64_t>(static_cast<uint8_t>(data[offset++])) << (8 * i);
	if (addr_size > 8) offset += (addr_size - 8);
	return result;
}

std::string ElfReader::ExtractFilename(const std::string& path)
{
	auto pos = path.find_last_of("/\\");
	if (pos != std::string::npos) return path.substr(pos + 1);
	return path;
}

std::string ElfReader::ToHexAddr(uint64_t value)
{
	char buf[32];
	std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
	return std::string(buf);
}

MemorySizes* ElfReader::Analyze(const std::filesystem::path& elfPath)
{
	auto mem = AllocateMemorySizes();
	ELFIO::elfio reader;
	if (!reader.load(elfPath.string())) {
		throw std::runtime_error("Не удалось открыть ELF: " + elfPath.string());
	}

	for (int i = 0; i < reader.segments.size(); ++i) {
		const ELFIO::segment* seg = reader.segments[i];

		if (seg->get_type() != ELFIO::PT_LOAD) continue;

		auto filesz = static_cast<int32_t>(seg->get_file_size());
		auto memsz = static_cast<int32_t>(seg->get_memory_size());
		auto flags = seg->get_flags();

		if (flags & ELFIO::PF_X) {
			mem->text += filesz;
		}
		else if (flags & ELFIO::PF_W) {
			mem->data += filesz;
			if (memsz > filesz) mem->bss += (memsz - filesz);
		}
	}

	mem->flash = mem->text;
	mem->ram = mem->data + mem->bss;
	mem->binSize = mem->text + mem->data;
	mem->dec = mem->text + mem->data + mem->bss;

	return mem;
}


void ElfReader::ReadLineHeader(const char* data, uint8_t& value, const size_t& size, size_t& offset)
{
	if (offset < size) value = static_cast<uint8_t>(data[offset++]);
}

bool ElfReader::FiltredResult(std::vector<std::string>& filteredName, const std::string& name)
{
	if (filteredName.empty())
		return true;

	std::string nameLower = name;
	std::ranges::transform(nameLower, nameLower.begin(), [](const unsigned char c) {return std::tolower(c); });

	for (const auto& fname : filteredName)
	{
		std::string fNameLower = fname;
		std::ranges::transform(fNameLower, fNameLower.begin(), [](const unsigned char c) {return std::tolower(c); });
		if (fNameLower == nameLower)
			return true;
	}

	return false;
}

int ElfReader::ParseDebugLine(const std::filesystem::path& elfPath, std::vector<LineEntry>& out_lines, std::vector<std::string>& filteredName)
{
	ELFIO::elfio reader;
	if (!reader.load(elfPath.string()))
	{
		std::wstring message = L"Не удалось открыть ELF: " + elfPath.wstring();
		callback::SendCallback(message.c_str(), Err, m_cb);
		return -1;
	}

	const ELFIO::section* debug_line = reader.sections[".debug_line"];
	if (!debug_line) {
		callback::SendCallback(L".debug_line not found", Err, m_cb);
		return -1;
	}

	const char* data = debug_line->get_data();
	size_t size = debug_line->get_size();

	size_t offset = 0;


	std::string last_emitted_file;
	uint64_t last_emitted_address = UINT64_MAX;
	size_t repeat_counter = 0;

	while (offset + 4 <= size)
	{
		uint32_t unit_length = ReadU32(data, size, offset);
		if (unit_length == 0) break;
		if (offset + unit_length > size) break;
		size_t unit_start = offset;
		size_t unit_end = unit_start + unit_length;

		if (offset + 2 > size) break;
		uint16_t version = static_cast<uint8_t>(data[offset]) | (static_cast<uint8_t>(data[offset + 1]) << 8);
		offset += 2;

		uint32_t header_length = ReadU32(data, size, offset);
		size_t header_start = offset;
		size_t header_end = header_start + header_length;
		if (header_end > unit_end) break;

		if (offset >= size) break;
		uint8_t min_insn_len = static_cast<uint8_t>(data[offset++]);

		uint8_t default_is_stmt = 0;
		ReadLineHeader(data, default_is_stmt, size, offset);

		int8_t line_base = 0;
		if (offset < size) line_base = static_cast<int8_t>(data[offset++]);

		uint8_t line_range = 0;
		ReadLineHeader(data, line_range, size, offset);

		uint8_t opcode_base = 0;
		ReadLineHeader(data, opcode_base, size, offset);

		std::vector<uint8_t> standard_opcode_lengths;
		if (opcode_base >= 1) {
			size_t count = static_cast<size_t>(opcode_base - 1);
			standard_opcode_lengths.resize(count);
			for (size_t i = 0; i < count && offset < header_end; ++i)
				standard_opcode_lengths[i] = static_cast<uint8_t>(data[offset++]);
		}

		std::vector<std::string> include_dirs;
		while (offset < header_end)
		{
			std::string dir;
			while (offset < header_end && data[offset] != 0) dir.push_back(data[offset++]);
			if (offset >= header_end) break;
			offset++;
			if (dir.empty()) break;
			include_dirs.push_back(dir);
		}

		std::vector<std::string> file_list;
		while (offset < header_end)
		{
			std::string fname;
			while (offset < header_end && data[offset] != 0) fname.push_back(data[offset++]);
			if (offset >= header_end) break;
			offset++;
			if (fname.empty()) break;

			uint64_t dir_index = ReadUleb(data, size, offset);
			ReadUleb(data, size, offset);
			ReadUleb(data, size, offset);

			std::string fullpath = fname;
			if (dir_index > 0 && (dir_index - 1) < include_dirs.size()) {
				if (!include_dirs[dir_index - 1].empty())
					fullpath = include_dirs[dir_index - 1] + "/" + fname;
			}
			file_list.push_back(ExtractFilename(fullpath));
		}

		offset = header_end;

		uint64_t address = 0;
		uint32_t line = 1;
		bool is_stmt = default_is_stmt ? true : false; //считается ли текущая позиция "началом исполняемого оператора" (statement)
		bool basic_block = false; // Флаг "начало базового блока"
		size_t file_index = 0;
		uint64_t sequence_base = UINT64_MAX;

		while (offset < unit_end)
		{
			if (offset >= size) break;
			uint8_t opcode = static_cast<uint8_t>(data[offset++]);

			if (opcode == 0)
			{
				uint64_t ex_len = ReadUleb(data, size, offset);
				if (offset >= size) break;
				if (ex_len == 0) continue;
				uint8_t ex_opcode = static_cast<uint8_t>(data[offset++]);

				if (ex_opcode == 1) // DW_LNE_end_sequence
				{
					basic_block = false;
					address = 0;
					line = 1;
					is_stmt = default_is_stmt ? true : false;
					file_index = 0;
					sequence_base = UINT64_MAX;
					last_emitted_file.clear();
					last_emitted_address = UINT64_MAX;
					repeat_counter = 0;
				}
				else if (ex_opcode == 2) // DW_LNE_set_address
				{
					size_t addr_bytes = (ex_len > 1) ? ex_len - 1 : 0;
					if (addr_bytes == 0) {
						address = ReadU32(data, size, offset);
					}
					else {
						address = ReadAddrBytes(data, size, offset, addr_bytes);
					}
					if (sequence_base == UINT64_MAX) sequence_base = address;
				}
				else
				{
					size_t to_skip = (ex_len > 1) ? ex_len - 1 : 0;
					offset += to_skip;
				}
			}
			else if (opcode < opcode_base)
			{
				switch (opcode)
				{
				case 1: // DW_LNS_copy -> EMIT
				{
					if (file_index < file_list.size())
					{
						auto current_file = file_list[file_index];
						auto current_address = address;

						uint32_t view_val = 0;
						if (current_file == last_emitted_file && current_address == last_emitted_address) {
							++repeat_counter;
							view_val = static_cast<uint32_t>(repeat_counter);
						}
						else {
							last_emitted_file = current_file;
							last_emitted_address = current_address;
							repeat_counter = 0;
							view_val = 0;
						}

						if (FiltredResult(filteredName, file_list[file_index]))
							out_lines.push_back({ file_list[file_index], ToHexAddr(address), line, is_stmt, basic_block, view_val });
					}
					basic_block = false;
					break;
				}
				case 2: // DW_LNS_advance_pc
				{
					auto adv = ReadUleb(data, size, offset);
					address += adv * static_cast<uint64_t>(min_insn_len);
					break;
				}
				case 3: // DW_LNS_advance_line
				{
					int64_t adv = ReadSleb(data, size, offset);
					if (adv < 0) {
						int64_t newl = static_cast<int64_t>(line) + adv;
						line = (newl > 0) ? static_cast<uint32_t>(newl) : 1u;
					}
					else {
						line = static_cast<uint32_t>(static_cast<int64_t>(line) + adv);
					}
					break;
				}
				case 4: // DW_LNS_set_file
				{
					uint64_t fidx = ReadUleb(data, size, offset);
					size_t new_file_index = (fidx == 0) ? 0 : static_cast<size_t>(fidx - 1);
					if (new_file_index >= file_list.size()) new_file_index = file_list.empty() ? 0 : file_list.size() - 1;

					file_index = new_file_index;
					break;
				}
				case 5: // DW_LNS_set_column
				{
					ReadUleb(data, size, offset);
					break;
				}
				case 6: // DW_LNS_negate_stmt
				{
					is_stmt = !is_stmt;
					break;
				}
				case 7: // DW_LNS_set_basic_block
				{
					basic_block = true;
					break;
				}
				default:
				{
					size_t idx = static_cast<size_t>(opcode - 1);
					if (idx < standard_opcode_lengths.size()) {
						uint8_t ops = standard_opcode_lengths[idx];
						for (uint8_t k = 0; k < ops && offset < unit_end; ++k) {
							ReadUleb(data, size, offset);
						}
					}
					break;
				}
				}
			}
			else
			{
				int adj = static_cast<int>(opcode) - static_cast<int>(opcode_base);
				int line_inc = static_cast<int>(line_base) + (adj % static_cast<int>(line_range));
				int addr_inc = (adj / static_cast<int>(line_range)) * static_cast<int>(min_insn_len);

				int64_t new_line = static_cast<int64_t>(line) + line_inc;
				line = (new_line > 0) ? static_cast<uint32_t>(new_line) : 1u;
				address += static_cast<uint64_t>(addr_inc);

				if (file_index < file_list.size())
				{
					auto current_file = file_list[file_index];
					auto current_address = address;

					uint32_t view_val = 0;
					if (current_file == last_emitted_file && current_address == last_emitted_address) {
						++repeat_counter;
						view_val = static_cast<uint32_t>(repeat_counter);
					}
					else {
						last_emitted_file = current_file;
						last_emitted_address = current_address;
						repeat_counter = 0;
						view_val = 0;
					}

					if (FiltredResult(filteredName, file_list[file_index]))
						out_lines.push_back({ file_list[file_index], ToHexAddr(address), line, is_stmt, basic_block, view_val });
				}
				basic_block = false;
			}
		}

		offset = unit_end;
	}

	return 0;
}

extern "C" {

	ELFREADER_API int API_ELF GetSymbols(const wchar_t* path, const wchar_t** filters, size_t filterCount,
		callback::build_callback cb,
		CLineEntry** outArray, size_t* outCount,
		const wchar_t* basePathW)
	{
		try
		{
			std::vector<std::string> filter;
			for (size_t i = 0; i < filterCount; ++i)
			{
				if (filters[i] == nullptr) continue;
				std::wstring ws(filters[i]);
				std::string str;
				str.resize(ws.size() * 4);
				str = std::string(ws.begin(), ws.end());
				filter.push_back(str);
			}

			std::vector<LineEntry> results;
			ElfReader reader(cb);
			auto result = reader.ParseDebugLine(std::wstring(path), results, filter);

			size_t size = results.size();
			if (size == 0)
			{
				*outArray = nullptr;
				*outCount = 0;
				return 0;
			}

			auto arr = static_cast<CLineEntry*>(std::malloc(sizeof(CLineEntry) * size));
			if (!arr)
			{
				callback::SendCallback(L"Ошибка выделения памяти!", Err, cb);
				return 2;
			}


			for (size_t i = 0; i < size; ++i)
			{
				const auto& entry = results[i];
				const std::string& file = entry.file;
				arr[i].file = static_cast<char*>(std::malloc(file.size() + 1));
				if (arr[i].file) std::memcpy(arr[i].file, file.c_str(), file.size() + 1);

				const std::string& addr = entry.address;
				arr[i].address = static_cast<char*>(std::malloc(addr.size() + 1));
				if (arr[i].address) std::memcpy(arr[i].address, addr.c_str(), addr.size() + 1);

				arr[i].line = entry.line;
				arr[i].is_stmt = entry.is_stmt ? 1 : 0;
				arr[i].basic_block = entry.basic_block ? 1 : 0;
				arr[i].view_val = entry.view;
			}

			*outArray = arr;
			*outCount = size;
			return 0;

		}
		catch (const std::exception& ex)
		{
			std::wstring msg = L"Ошибка!: ";
			std::string what = ex.what();
			std::wstring wwhat(what.begin(), what.end());
			msg += wwhat;
			callback::SendCallback(msg.c_str(), Err, cb);
			return 3;
		}
		catch (...)
		{
			callback::SendCallback(L"Неизвестная ошибка!", Err, cb);
			return -4;
		}
	}
}
