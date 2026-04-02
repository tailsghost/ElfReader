#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <elfio/elfio.hpp>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <cstring>

#include "NinjaCallback.h"

#ifdef _MSC_VER
#   define API_ELFDWARF __stdcall
#else
#   define API_ELFDWARF
#endif

#ifdef ELFDWARF_EXPORTS
#   define ELFDWARF_API __declspec(dllexport)
#else
#   define ELFDWARF_API __declspec(dllimport)
#endif

using namespace callback;


namespace elf_dwarf_parser {
	struct MemberInfo
	{
		std::string name;
		std::string type;
		uint64_t byte_offset = UINT64_MAX;
		uint64_t bit_size = 0;
		std::vector<MemberInfo> fields;
	};

	struct StructInfo
	{
		std::string name;
		uint64_t size = 0;
		std::vector<MemberInfo> members;
	};

	enum : uint64_t {
		DW_TAG_structure_type = 0x13,
		DW_TAG_member = 0x0d,
		DW_TAG_base_type = 0x24,
		DW_TAG_typedef = 0x16,
		DW_TAG_const_type = 0x26,
		DW_TAG_variable = 0x28,
		DW_TAG_pointer_type = 0x0f
	};

	enum : uint64_t {
		DW_AT_name = 0x03,
		DW_AT_byte_size = 0x0b,
		DW_AT_bit_offset = 0x0c,
		DW_AT_bit_size = 0x0d,
		DW_AT_abstract_origin = 0x31,
		DW_AT_data_member_location = 0x38,
		DW_AT_specification = 0x47,
		DW_AT_type = 0x49,
	};

	enum : uint64_t {
		DW_OP_plus_const = 0x23
	};

	enum : uint64_t {
		DW_FORM_addr = 0x01,
		DW_FORM_block2 = 0x03,
		DW_FORM_block4 = 0x04,
		DW_FORM_data2 = 0x05,
		DW_FORM_data4 = 0x06,
		DW_FORM_data8 = 0x07,
		DW_FORM_string = 0x08,
		DW_FORM_block = 0x09,
		DW_FORM_block1 = 0x0a,
		DW_FORM_data1 = 0x0b,
		DW_FORM_flag = 0x0c,
		DW_FORM_sdata = 0x0d,
		DW_FORM_strp = 0x0e,
		DW_FORM_udata = 0x0f,
		DW_FORM_ref_addr = 0x10,
		DW_FORM_ref1 = 0x11,
		DW_FORM_ref2 = 0x12,
		DW_FORM_ref4 = 0x13,
		DW_FORM_ref8 = 0x14,
		DW_FORM_ref_udata = 0x15,
		DW_FORM_indirect = 0x16,
		DW_FORM_sec_offset = 0x17,
		DW_FORM_exprloc = 0x18,
		DW_FORM_flag_present = 0x19,

		DW_FORM_strx = 0x1a,
		DW_FORM_addrx = 0x1b,
		DW_FORM_ref_sup4 = 0x1c,
		DW_FORM_strp_sup = 0x1d,
		DW_FORM_data16 = 0x1e,
		DW_FORM_line_strp = 0x1f,
		DW_FORM_ref_sig8 = 0x20,
		DW_FORM_implicit_const = 0x21,
		DW_FORM_loclistx = 0x22,
		DW_FORM_rnglistx = 0x23,
		DW_FORM_ref_sup8 = 0x24,

		DW_FORM_strx1 = 0x25,
		DW_FORM_strx2 = 0x26,
		DW_FORM_strx3 = 0x27,
		DW_FORM_strx4 = 0x28,
		DW_FORM_addrx1 = 0x29,
		DW_FORM_addrx2 = 0x2a,
		DW_FORM_addrx3 = 0x2b,
		DW_FORM_addrx4 = 0x2c,
	};


	struct AttrRaw {
		uint64_t form;
		std::vector<uint8_t> data;
	};


	class ELFDWARF_API ElfDwarfParser
	{
	public:
		ElfDwarfParser(build_callback cb) : m_cb(cb) {
			die_by_offset_.reserve(100000);
			allocated_dies_.reserve(100000);
			debug_info_.reserve(1000000);
			debug_abbrev_.reserve(100000);
			debug_str_.reserve(200000);
		}
		~ElfDwarfParser() {
			for (auto p : allocated_dies_) delete p;

			debug_str_.clear();
			debug_abbrev_.clear();
			debug_info_.clear();
			allocated_dies_.clear();
			die_by_offset_.clear();
		}
		bool loadFile(const std::string& elfPath);
		bool parseStructByName(const std::string& structName, StructInfo& out_structs);
 
	private:
		build_callback m_cb;

		std::unordered_map<uint64_t, std::string> last_typedef_map_;

		std::vector<uint8_t> debug_info_;
		std::vector<uint8_t> debug_abbrev_;
		std::vector<uint8_t> debug_str_;

		struct DIE {
			uint64_t offset = 0;
			uint64_t tag = 0;
			uint8_t hasChildren = 0;
			std::vector<std::pair<uint64_t, std::vector<uint8_t>>> rawAttributes;
			std::unordered_map<uint64_t, AttrRaw> attrRawByName;
			std::vector<DIE*> children;

			uint32_t cuOffset = 0;
		};

		std::unordered_map<uint64_t, DIE*> die_by_offset_;
		std::vector<DIE*> allocated_dies_;

		struct AbbrevAttr {
			uint64_t name;
			uint64_t form;
			int64_t implicitConst = 0;
		};

		struct AbbrevEntry {
			uint64_t code;
			uint64_t tag; uint8_t hasChildren;
			std::vector<AbbrevAttr> attrs;
		};

		bool containAttr(DIE* die, uint64_t en, std::vector<uint8_t>* result = nullptr);
		bool containAttrName(DIE* die, uint64_t en, std::vector<uint8_t>* result = nullptr);
		uint64_t readULEB(size_t& pos, const std::vector<uint8_t>& data);
		int64_t  readSLEB(size_t& pos, const std::vector<uint8_t>& data);
		uint64_t readUintN(size_t& pos, const std::vector<uint8_t>& data, size_t n);
		uint64_t readLEToUint64(const std::vector<uint8_t>& raw);
		std::string readStringAt(const uint32_t& offset);
		bool parseAbbrevTable(const uint32_t& abbrevOffset, std::unordered_map<uint64_t, AbbrevEntry>& out);

		std::string readNameFromAttr(const std::vector<uint8_t>& attr);

		DIE* setTypedefDie(DIE* type, size_t size, uint32_t& cuStart);
		bool parseCU(uint32_t& cuStart, size_t& cuEnd, const std::string& targetName, bool& foundInThisCU, DIE*& foundDIE);
		DIE* parseDIE(size_t& pos, const size_t& cuStart, const std::unordered_map<uint64_t, AbbrevEntry>& abbrevMap, uint8_t& address_size);
		std::string resolveTypeNameFromRef(uint64_t& refVal, uint32_t& cuStart);
		void buildStructInfoRecursive(DIE* die, uint32_t& cuStart, std::vector<StructInfo>& collector, std::unordered_map<std::string, bool>& added);
		DIE* findStructDIEByName(const std::string& name);
		uint64_t getSizeForTypeDie(DIE* typeDie);
		DIE* resolveDieFromRef(const uint64_t& ref, const uint32_t& cuStart);
		void populateMemberInfo(DIE* memberDie, uint32_t& cuStart, MemberInfo& outMember, std::unordered_set<uint64_t>& visitedTypes);

	};
}