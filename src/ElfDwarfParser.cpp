#include <ElfDwarfParser.h>

#include <NinjaCallback.h>

using namespace elf_dwarf_parser;


bool ElfDwarfParser::loadFile(const std::string& elfPath) {
	ELFIO::elfio reader;
	if (!reader.load(elfPath)) {
		SendCallback(L"Ошибка при загрузке ELF файла!", Err, m_cb);
		return false;
	}

	auto sec_info = reader.sections[".debug_info"];
	if (!sec_info) {
		SendCallback(L"Нет debug_info секции!", Err, m_cb);
		return false;
	}

	auto info_data = sec_info->get_data();
	debug_info_.assign(info_data, info_data + sec_info->get_size());

	auto sec_addbrev = reader.sections[".debug_abbrev"];
	if (!sec_addbrev) {
		SendCallback(L"Нет debug_abbrev секции!", Err, m_cb);
		return false;
	}

	auto addbrev_data = sec_addbrev->get_data();
	debug_abbrev_.assign(addbrev_data, addbrev_data + sec_addbrev->get_size());

	auto sec_str = reader.sections[".debug_str"];
	if (sec_str) {
		auto str_data = sec_str->get_data();
		debug_str_.assign(str_data, str_data + sec_str->get_size());
	}
	else debug_str_.clear();

	for (auto p : allocated_dies_) delete p;
	allocated_dies_.clear();
	die_by_offset_.clear();

	return true;
}

uint64_t ElfDwarfParser::readULEB(size_t& pos, const std::vector<uint8_t>& data) {
	uint64_t result = 0;
	unsigned shift = 0;
	while (pos < data.size()) {
		uint8_t byte = data[pos++];
		result |= static_cast<uint64_t>(byte & 0x7f) << shift;
		if ((byte & 0x80) == 0) break;
		shift += 7;
	}
	return result;
}


int64_t ElfDwarfParser::readSLEB(size_t& pos, const std::vector<uint8_t>& data) {
	int64_t result = 0;
	unsigned shift = 0;
	uint8_t byte = 0;

	while (pos < data.size()) {
		byte = data[pos++];
		result |= static_cast<int64_t>(byte & 0x7f) << shift;
		shift += 7;
		if ((byte & 0x80) == 0) break;
	}
	if ((shift < static_cast<unsigned>(8 * sizeof(result))) && (byte & 0x40)) {
		result |= -(static_cast<int64_t>(1) << shift);
	}
	return result;
}


uint64_t ElfDwarfParser::readUintN(size_t& pos, const std::vector<uint8_t>& data, size_t n) {
	uint64_t val = 0;
	if (pos + n > data.size()) return 0;
	for (size_t i = 0; i < n; ++i) {
		val |= static_cast<uint64_t>(data[pos++]) << (8 * i);
	}
	return val;
}


uint64_t ElfDwarfParser::readLEToUint64(const std::vector<uint8_t>& raw) {
	uint64_t v = 0;
	size_t n = std::min<size_t>(raw.size(), 8);
	for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(raw[i]) << (8 * i);
	return v;
}


std::string ElfDwarfParser::readStringAt(const uint32_t& offset) {
	if (offset >= debug_str_.size()) return {};
	const auto start = reinterpret_cast<const char*>(debug_str_.data() + offset);
	size_t rem = debug_str_.size() - offset;
	const auto z = std::memchr(start, '\0', rem);
	if (z) return std::string(start, static_cast<const char*>(z));
	return std::string(start, start + rem);
}

bool ElfDwarfParser::parseAbbrevTable(const uint32_t& abbrevOffset, std::unordered_map<uint64_t, AbbrevEntry>& out) {
	if (abbrevOffset >= debug_abbrev_.size()) return false;
	size_t pos = abbrevOffset;
	while (pos < debug_abbrev_.size()) {
		auto  code = readULEB(pos, debug_abbrev_);
		if (code == 0) break;
		AbbrevEntry ent;
		ent.code = code;
		ent.tag = readULEB(pos, debug_abbrev_);
		if (pos >= debug_abbrev_.size()) return false;
		ent.hasChildren = debug_abbrev_[pos++];
		while (true) {
			auto name = readULEB(pos, debug_abbrev_);
			auto form = readULEB(pos, debug_abbrev_);
			if (name == 0 && form == 0) break;
			ent.attrs.push_back({ name, form });
		}
		out[ent.code] = ent;
	}
	return true;
}


std::string ElfDwarfParser::readNameFromAttr(const std::vector<uint8_t>& attr) {
	if (attr.empty()) return {};
	if (attr.size() >= 4) {
		size_t size = 0;

		auto data = attr.data();
		auto off = static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) | (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
		if (off < debug_str_.size()) {
			auto str = readStringAt(off);
			if (!str.empty()) return str;
		}
	}

	const auto p = reinterpret_cast<const char*>(attr.data());
	auto n = attr.size();
	const void* z = std::memchr(p, '\0', n);
	if (z) return std::string(p, static_cast<const char*>(z));
	return std::string(p, p + n);
}

ElfDwarfParser::DIE* ElfDwarfParser::resolveDieFromRef(const uint64_t& ref, const uint32_t& cuStart) {
	if (ref == 0) return nullptr;

	auto tryResolve = [&](uint64_t key)->DIE* {
		auto it = die_by_offset_.find(key);
		if (it != die_by_offset_.end()) return it->second;
		return nullptr;
		};


	DIE* die = tryResolve(static_cast<uint64_t>(cuStart) + ref);
	if (!die) return nullptr;

	auto safety = 0;
	while (die && safety++ < 16) {
		if (!die->children.empty()) return die;
		if (containAttrName(die, DW_AT_byte_size)) return die;
		uint64_t nextRef = 0;
		std::vector<uint8_t>* specIt = nullptr;
		if (containAttr(die, DW_AT_specification, specIt)) {
			nextRef = readLEToUint64(*specIt);
		}
		else {
			std::vector<uint8_t>* absIt = nullptr;
			if (containAttr(die, DW_AT_abstract_origin, absIt))
				nextRef = readLEToUint64(*absIt);
		}
		if (nextRef == 0) break;
		DIE* next = tryResolve(nextRef + cuStart);
		if (!next) break;
		die = next;
	}

	return die;
}


bool ElfDwarfParser::containAttrName(DIE* die, uint64_t en, std::vector<uint8_t>* result) {
	auto it = die->attrRawByName.find(en);
	if (it == die->attrRawByName.end()) return false;
	if (result) *result = it->second.data;
	return true;
}

bool ElfDwarfParser::containAttr(DIE* die, uint64_t en, std::vector<uint8_t>* result) {
	auto it = die->attrRawByName.find(en);
	if (it == die->attrRawByName.end() || it->second.data.empty()) return false;
	if (result) *result = it->second.data;
	return true;
}


void ElfDwarfParser::populateMemberInfo(DIE* memberDie, uint32_t& cuStart, MemberInfo& outMember, std::unordered_set<uint64_t>& visitedTypes) {
	if (!memberDie) return;


	std::vector<uint8_t> name;
	if (containAttrName(memberDie, DW_AT_name, &name)) {
		outMember.name = readNameFromAttr(name);
	}
	else {
		outMember.name = "<anon>";
	}

	outMember.byte_offset = UINT64_MAX;

	std::vector<uint8_t> offa;
	if (containAttr(memberDie, DW_AT_data_member_location, &offa)) {
		const auto& raw = offa;
		size_t pos = 1;
		if (raw.size() >= pos && raw[0] == DW_OP_plus_const) {
			auto res = readULEB(pos, raw);
			outMember.byte_offset = res;
		}
		else {
			outMember.byte_offset = readLEToUint64(raw);
		}
	}

	outMember.type = "<unknown>";
	DIE* memberTypeDie = nullptr;
	auto attrType = memberDie->attrRawByName.find(DW_AT_type);
	if (attrType != memberDie->attrRawByName.end() && !attrType->second.data.empty()) {
		auto ref = readLEToUint64(attrType->second.data);

		memberTypeDie = resolveDieFromRef(ref, cuStart);
		auto tn = resolveTypeNameFromRef(ref, cuStart);
		if ((tn == "<anon_struct>" || tn == "<unknown>") && memberTypeDie) {
			auto it_alias = last_typedef_map_.find(memberTypeDie->offset);
			if (it_alias != last_typedef_map_.end())
				tn = it_alias->second;
		}

		outMember.type = tn;
	}

	outMember.bit_size = 0;
	std::vector<uint8_t> mbits;
	if (containAttr(memberDie, DW_AT_bit_size, &mbits)) {
		outMember.bit_size = readLEToUint64(mbits);
	}
	else {
		if (!memberTypeDie && attrType != memberDie->attrRawByName.end() && !attrType->second.data.empty()) {
			auto ref = readLEToUint64(attrType->second.data);
			memberTypeDie = resolveDieFromRef(ref, cuStart);
		}

		auto sizeBits = getSizeForTypeDie(memberTypeDie);
		if (sizeBits > 0) outMember.bit_size = sizeBits;
		else {
			std::vector<uint8_t> sbits;
			if (containAttr(memberDie, DW_AT_byte_size, &sbits)) {
				outMember.bit_size = readLEToUint64(sbits) * 8;
			}
		}

		if (memberTypeDie) {
			DIE* type = memberTypeDie;
			int safety = 0;
			while (type && (type->tag == DW_TAG_typedef || type->tag == DW_TAG_const_type) && safety++ < 128) {
				auto f = type->attrRawByName.find(DW_AT_type);
				if (f == type->attrRawByName.end()) break;

				uint64_t ref = readLEToUint64(f->second.data);
				DIE* next = resolveDieFromRef(ref, cuStart);
				if (!next) break;
				type = next;
			}

			if (type && (type->children.empty() || (type->attrRawByName.find(DW_AT_byte_size) == type->attrRawByName.end()))) {
				auto specIt = type->attrRawByName.find(DW_AT_specification);
				uint64_t specRef = 0;
				if (specIt != type->attrRawByName.end() && !specIt->second.data.empty()) specRef = readLEToUint64(specIt->second.data);
				else {
					std::vector<uint8_t> absIt;
					if (containAttr(type, DW_AT_abstract_origin, &absIt)) specRef = readLEToUint64(absIt);
				}
				if (specRef != 0) {
					DIE* specDie = resolveDieFromRef(specRef, cuStart);
					if (specDie) type = specDie;
				}
			}

			if (type && type->tag == DW_TAG_structure_type) {
				if (visitedTypes.find(type->offset) == visitedTypes.end()) {
					visitedTypes.insert(type->offset);
					for (DIE* child : type->children)
					{
						if (child->tag != DW_TAG_member) continue;
						MemberInfo sub;
						populateMemberInfo(child, cuStart, sub, visitedTypes);
						outMember.fields.push_back(std::move(sub));
					}
					visitedTypes.erase(type->offset);
				}
			}
		}
	}

}

void ElfDwarfParser::buildStructInfoRecursive(DIE* die, uint32_t& cuStart, std::vector<StructInfo>& collector, std::unordered_map<std::string, bool>& added) {
	if (!die) return;

	std::string name = "<anon_struct>";
	auto attrIt = die->attrRawByName.find(DW_AT_name);
	if (attrIt != die->attrRawByName.end()) {
		if (attrIt->second.data.size() == 4) {
			uint32_t off;
			std::memcpy(&off, attrIt->second.data.data(), 4);
			name = readStringAt(off);
		}
		else name = std::string(reinterpret_cast<const char*>(attrIt->second.data.data()));
	}
	else {
		auto it_alias = last_typedef_map_.find(die->offset);
		if (it_alias != last_typedef_map_.end()) name = it_alias->second;
	}

	if (added.find(name) != added.end()) return;

	StructInfo info;
	info.name = name;

	std::vector<uint8_t> bsize;
	if (containAttr(die, DW_AT_byte_size, &bsize)) info.size = readLEToUint64(bsize);
	else {
		auto bits = getSizeForTypeDie(die);
		if (bits > 0 && bits % 8 == 0) info.size = bits / 8;
	}

	std::unordered_set<uint64_t> visited;
	for (DIE* child : die->children)
	{
		if (child->tag != DW_TAG_member) continue;
		MemberInfo mInfo;
		populateMemberInfo(child, cuStart, mInfo, visited);
		info.members.push_back(mInfo);
	}


	collector.push_back(info);
	added[name] = true;
}

std::string ElfDwarfParser::resolveTypeNameFromRef(uint64_t& refVal, uint32_t& cuStart) {
	if (refVal == 0) return "<unknown>";

	auto die = resolveDieFromRef(refVal, cuStart);
	if (!die) return "<unknown>";

	auto safety = 0;
	auto ptrDepth = 0;

	while (die && safety++ < 128) {
		if (die->tag == DW_TAG_typedef || die->tag == DW_TAG_const_type || die->tag == DW_TAG_variable) {

			std::vector<uint8_t> attributeIt;
			if (!containAttrName(die, DW_AT_type, &attributeIt)) break;
			auto ref = readLEToUint64(attributeIt);
			auto next = resolveDieFromRef(ref, cuStart);
			if (!next) break;
			die = next;
			continue;
		}

		if (die->tag == DW_TAG_pointer_type) {
			auto attributeIt = die->attrRawByName.find(DW_AT_type);
			if (attributeIt == die->attrRawByName.end()) {
				std::string base = "<ptr>";
				for (auto i = 0; i < ptrDepth; ++i) base += '*';
				return base;
			}
			auto ref = readLEToUint64(attributeIt->second.data);
			auto next = resolveDieFromRef(ref, cuStart);
			ptrDepth++;
			if (!next) break;
			die = next;
			continue;
		}

		break;
	}

	if (!die) return "<unknown>";

	if (die->tag == DW_TAG_base_type) {
		std::string type;
		std::vector<uint8_t> attributeIt;
		if (containAttrName(die, DW_AT_name, &attributeIt)) type = readNameFromAttr(attributeIt);

		uint64_t byte_size = 0;
		std::vector<uint8_t> bsa;
		if (containAttrName(die, DW_AT_byte_size, &bsa)) byte_size = readLEToUint64(bsa);
		uint64_t bit_size = 0;
		std::vector<uint8_t> bita;
		if (containAttrName(die, DW_AT_bit_size, &bita)) bit_size = readLEToUint64(bita);
		if (bit_size == 0 && byte_size > 0) bit_size = byte_size * 8;

		std::string strOut;
		if (!type.empty()) {
			if (type.find("bool") != std::string::npos) strOut = "bool";
			if (type.find("__") != std::string::npos) strOut = "bool";
			else if (type.find("long long") != std::string::npos || type.find("int64_t") != std::string::npos) strOut = "long";
			else if (type.find("char") != std::string::npos) strOut = "byte";
			else if (type.find("short") != std::string::npos) strOut = "short";
			else strOut = type;
		}
		else {
			if (bit_size == 8) strOut = "byte";
			else if (bit_size == 64) strOut = "long";
			else if (bit_size > 0 && bit_size <= 32) strOut = "int";
			else strOut = "int";
		}
		for (auto i = 0; i < ptrDepth; ++i) strOut += '*';
		return strOut;
	}

	if (die->tag == DW_TAG_structure_type) {
		std::string name;
		std::vector<uint8_t> attributeIt;
		if (containAttrName(die, DW_AT_name, &attributeIt))
			name = readNameFromAttr(attributeIt);
		if (name.empty()) {
			auto it_alias = last_typedef_map_.find(die->offset);
			if (it_alias != last_typedef_map_.end()) name = it_alias->second;
		}
		if (name.empty()) name = "<anon_struct>";
		for (auto i = 0; i < ptrDepth; ++i) name += '*';

		return name;
	}

	std::string fallback = "<type>";
	for (auto i = 0; i < ptrDepth; ++i) fallback += '*';
	return fallback;
}

ElfDwarfParser::DIE* ElfDwarfParser::parseDIE(
	size_t& pos,
	const size_t& cuStart,
	const std::unordered_map<uint64_t, AbbrevEntry>& abbrevMap,
	uint8_t& address_size)
{
	if (pos >= debug_info_.size()) return nullptr;

	auto dieOffset = pos;
	auto abbrevCode = readULEB(pos, debug_info_);
	if (abbrevCode == 0) {
		return nullptr;
	}

	auto it = abbrevMap.find(abbrevCode);
	if (it == abbrevMap.end()) {
		return nullptr;
	}

	const AbbrevEntry& ab = it->second;

	auto die = new DIE();
	die->offset = dieOffset;
	die->tag = ab.tag;
	die->hasChildren = ab.hasChildren;
	die->cuOffset = static_cast<uint32_t>(cuStart);
	allocated_dies_.push_back(die);

	auto appendLE = [](std::vector<uint8_t>& out, uint64_t v, size_t n) {
		out.resize(n);
		for (size_t i = 0; i < n; ++i) {
			out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
		}
		};

	auto readFixedBytes = [&](size_t n) -> std::vector<uint8_t> {
		std::vector<uint8_t> raw;
		if (pos + n <= debug_info_.size()) {
			raw.insert(raw.end(), &debug_info_[pos], &debug_info_[pos + n]);
			pos += n;
		}
		return raw;
		};

	for (const auto& a : ab.attrs) {
		uint64_t form = a.form;
		uint64_t attrName = a.name;

		if (form == DW_FORM_indirect) {
			form = readULEB(pos, debug_info_);
		}

		std::vector<uint8_t> raw;

		switch (form) {
		case DW_FORM_addr: {
			uint64_t v = readUintN(pos, debug_info_, address_size);
			appendLE(raw, v, address_size);
			break;
		}

		case DW_FORM_addrx:
		case DW_FORM_strx:
		case DW_FORM_loclistx:
		case DW_FORM_rnglistx: {
			uint64_t v = readULEB(pos, debug_info_);
			raw.resize(sizeof(v));
			std::memcpy(raw.data(), &v, sizeof(v));
			break;
		}

		case DW_FORM_addrx1:
		case DW_FORM_strx1: {
			uint64_t v = readUintN(pos, debug_info_, 1);
			appendLE(raw, v, 1);
			break;
		}
		case DW_FORM_addrx2:
		case DW_FORM_strx2: {
			uint64_t v = readUintN(pos, debug_info_, 2);
			appendLE(raw, v, 2);
			break;
		}
		case DW_FORM_addrx3:
		case DW_FORM_strx3: {
			uint64_t v = readUintN(pos, debug_info_, 3);
			appendLE(raw, v, 3);
			break;
		}
		case DW_FORM_addrx4:
		case DW_FORM_strx4: {
			uint64_t v = readUintN(pos, debug_info_, 4);
			appendLE(raw, v, 4);
			break;
		}

		case DW_FORM_data1: {
			uint64_t v = readUintN(pos, debug_info_, 1);
			appendLE(raw, v, 1);
			break;
		}
		case DW_FORM_data2: {
			uint64_t v = readUintN(pos, debug_info_, 2);
			appendLE(raw, v, 2);
			break;
		}
		case DW_FORM_data4: {
			uint64_t v = readUintN(pos, debug_info_, 4);
			appendLE(raw, v, 4);
			break;
		}
		case DW_FORM_data8: {
			uint64_t v = readUintN(pos, debug_info_, 8);
			appendLE(raw, v, 8);
			break;
		}
		case DW_FORM_data16: {
			raw = readFixedBytes(16);
			break;
		}

		case DW_FORM_string: {
			size_t start = pos;
			while (pos < debug_info_.size() && debug_info_[pos] != 0) pos++;
			if (pos < debug_info_.size()) pos++;
			raw.insert(raw.end(), &debug_info_[start], &debug_info_[pos]);
			break;
		}

		case DW_FORM_block:
		case DW_FORM_exprloc: {
			uint64_t len = readULEB(pos, debug_info_);
			if (pos + len <= debug_info_.size()) {
				raw.insert(raw.end(), &debug_info_[pos], &debug_info_[pos + len]);
				pos += len;
			}
			break;
		}
		case DW_FORM_block1: {
			uint64_t len = readUintN(pos, debug_info_, 1);
			if (pos + len <= debug_info_.size()) {
				raw.insert(raw.end(), &debug_info_[pos], &debug_info_[pos + len]);
				pos += len;
			}
			break;
		}
		case DW_FORM_block2: {
			uint64_t len = readUintN(pos, debug_info_, 2);
			if (pos + len <= debug_info_.size()) {
				raw.insert(raw.end(), &debug_info_[pos], &debug_info_[pos + len]);
				pos += len;
			}
			break;
		}
		case DW_FORM_block4: {
			uint64_t len = readUintN(pos, debug_info_, 4);
			if (pos + len <= debug_info_.size()) {
				raw.insert(raw.end(), &debug_info_[pos], &debug_info_[pos + len]);
				pos += len;
			}
			break;
		}

		case DW_FORM_flag: {
			uint64_t v = readUintN(pos, debug_info_, 1);
			appendLE(raw, v, 1);
			break;
		}
		case DW_FORM_flag_present: {
			raw.clear();
			break;
		}

		case DW_FORM_sdata: {
			int64_t v = readSLEB(pos, debug_info_);
			raw.resize(sizeof(v));
			std::memcpy(raw.data(), &v, sizeof(v));
			break;
		}
		case DW_FORM_udata: {
			uint64_t v = readULEB(pos, debug_info_);
			raw.resize(sizeof(v));
			std::memcpy(raw.data(), &v, sizeof(v));
			break;
		}

		case DW_FORM_strp:
		case DW_FORM_strp_sup:
		case DW_FORM_line_strp:
		case DW_FORM_sec_offset: {
			uint64_t off = readUintN(pos, debug_info_, sizeof(uint32_t));
			raw.resize(4);
			std::memcpy(raw.data(), &off, 4);
			break;
		}

		case DW_FORM_ref_addr: {
			uint64_t val = readUintN(pos, debug_info_, address_size);
			raw.resize(address_size);
			for (size_t i = 0; i < address_size; ++i) {
				raw[i] = static_cast<uint8_t>((val >> (8 * i)) & 0xff);
			}
			break;
		}

		case DW_FORM_ref1: {
			uint64_t val = readUintN(pos, debug_info_, 1);
			appendLE(raw, val, 1);
			break;
		}
		case DW_FORM_ref2: {
			uint64_t val = readUintN(pos, debug_info_, 2);
			appendLE(raw, val, 2);
			break;
		}
		case DW_FORM_ref4: {
			uint64_t val = readUintN(pos, debug_info_, 4);
			appendLE(raw, val, 4);
			break;
		}
		case DW_FORM_ref8: {
			uint64_t val = readUintN(pos, debug_info_, 8);
			appendLE(raw, val, 8);
			break;
		}
		case DW_FORM_ref_udata: {
			uint64_t val = readULEB(pos, debug_info_);
			raw.resize(sizeof(val));
			std::memcpy(raw.data(), &val, sizeof(val));
			break;
		}

		case DW_FORM_ref_sup4: {
			uint64_t val = readUintN(pos, debug_info_, 4);
			appendLE(raw, val, 4);
			break;
		}
		case DW_FORM_ref_sup8: {
			uint64_t val = readUintN(pos, debug_info_, 8);
			appendLE(raw, val, 8);
			break;
		}

		case DW_FORM_ref_sig8: {
			raw = readFixedBytes(8);
			break;
		}

		case DW_FORM_implicit_const: {
			int64_t v = a.implicitConst;
			raw.resize(sizeof(v));
			std::memcpy(raw.data(), &v, sizeof(v));
			break;
		}

		default: {
			uint64_t v = readULEB(pos, debug_info_);
			raw.resize(sizeof(v));
			std::memcpy(raw.data(), &v, sizeof(v));
			break;
		}
		}

		die->rawAttributes.emplace_back(attrName, raw);
		die->attrRawByName[attrName] = AttrRaw{ form, raw };
	}

	if (die->hasChildren) {
		while (true) {
			DIE* child = parseDIE(pos, cuStart, abbrevMap, address_size);
			if (!child) break;
			die->children.push_back(child);
		}
	}

	die_by_offset_[die->offset] = die;
	return die;
}



uint64_t ElfDwarfParser::getSizeForTypeDie(DIE* typeDie) {
	if (!typeDie) return 0;

	std::vector<uint8_t> bita;
	std::vector<uint8_t> bsa;
	if (containAttr(typeDie, DW_AT_bit_size, &bita))return readLEToUint64(bita);
	if (containAttr(typeDie, DW_AT_byte_size, &bsa))return readLEToUint64(bsa) * 8;

	int32_t safety = 0;
	DIE* cur = typeDie;
	while (cur && safety++ < 64) {
		if (cur->tag == DW_TAG_typedef || cur->tag == DW_TAG_const_type) {
			auto attributeIt = cur->attrRawByName.find(DW_AT_type);
			if (attributeIt == cur->attrRawByName.end() || attributeIt->second.data.empty()) break;

			auto ref = readLEToUint64(attributeIt->second.data);
			DIE* next = nullptr;

			auto itAbs = die_by_offset_.find(ref);
			if (itAbs != die_by_offset_.end()) next = itAbs->second;
			else {
				auto absFromCu = static_cast<uint64_t>(cur->cuOffset) + ref;
				auto itCu = die_by_offset_.find(absFromCu);
				if (itCu != die_by_offset_.end()) next = itCu->second;
			}

			if (!next) break;

			cur = next;
			auto bita2 = cur->attrRawByName.find(DW_AT_bit_size);
			if (bita2 != cur->attrRawByName.end() && !bita2->second.data.empty()) return readLEToUint64(bita2->second.data);
			auto bsa2 = cur->attrRawByName.find(DW_AT_byte_size);
			if (bsa2 != cur->attrRawByName.end() && !bsa2->second.data.empty()) return readLEToUint64(bsa2->second.data) * 8;

			continue;
		}

		auto bita2 = cur->attrRawByName.find(DW_AT_bit_size);
		if (bita2 != cur->attrRawByName.end() && !bita2->second.data.empty()) return readLEToUint64(bita2->second.data);
		auto bsa2 = cur->attrRawByName.find(DW_AT_byte_size);
		if (bsa2 != cur->attrRawByName.end() && !bsa2->second.data.empty()) return readLEToUint64(bsa2->second.data) * 8;

		break;
	}

	return 0;
}

bool ElfDwarfParser::parseCU(uint32_t& cuStart, size_t& cuEnd, const std::string& targetName, bool& foundInThisCU, DIE*& foundDIE) {
	if (cuStart + 11 > debug_info_.size()) return false;
	size_t pos = cuStart;

	auto unit_length = static_cast<uint32_t>(readUintN(pos, debug_info_, 4));
	bool is_64bit = false;
	uint64_t unit_end = 0;
	if (unit_length == 0xffffffffu) {
		auto ext_len = readUintN(pos, debug_info_, 8);
		is_64bit = true;
		unit_end = cuStart + 4 + 8 + ext_len;
	}
	else {
		unit_end = cuStart + 4 + unit_length;
	}

	auto version = static_cast<uint16_t>(readUintN(pos, debug_info_, 2));
	auto abbrev_offset = static_cast<uint32_t>(readUintN(pos, debug_info_, 4));
	auto address_size = static_cast<uint8_t>(readUintN(pos, debug_info_, 1));

	std::unordered_map<uint64_t, AbbrevEntry> abbrevMap;
	parseAbbrevTable(abbrev_offset, abbrevMap);

	foundInThisCU = false;
	foundDIE = nullptr;

	std::vector<DIE*> dies_in_cu;
	dies_in_cu.reserve(100);
	while (pos < unit_end) {
		auto before = pos;
		DIE* die = parseDIE(pos, cuStart, abbrevMap, address_size);
		if (!die) {
			if (pos == before) break;
			continue;
		}
		dies_in_cu.push_back(die);
	}



	auto resolve_ref_to_die = [&](uint64_t ref, uint32_t cuBase) -> DIE* {
		auto it = die_by_offset_.find(ref);
		if (it != die_by_offset_.end()) return it->second;
		auto it2 = die_by_offset_.find(static_cast<uint64_t>(cuBase) + ref);
		if (it2 != die_by_offset_.end()) return it2->second;
		return nullptr;
		};

	auto follow_typedef_chain = [&](DIE* start)->DIE* {
		DIE* cur = start;
		int safety = 0;
		while (cur && (cur->tag == DW_TAG_typedef || cur->tag == DW_TAG_const_type) && safety++ < 64) {
			auto fa = cur->attrRawByName.find(DW_AT_type);
			if (fa == cur->attrRawByName.end()) break;
			auto ref = readLEToUint64(fa->second.data);
			DIE* next = resolve_ref_to_die(ref, cuStart);
			if (!next) break;
			cur = next;
		}
		return cur;
		};


	std::unordered_map<uint64_t, std::string> typedef_map;
	std::vector<DIE*> structure_type;
	structure_type.reserve(static_cast<int32_t>(die_by_offset_.size() / 2));

	for (auto& p : die_by_offset_) {
		auto td = p.second;
		if (td->cuOffset != cuStart) continue;
		if (td->tag == DW_TAG_structure_type)
			structure_type.push_back(td);
		if (td->tag != DW_TAG_typedef) continue;
		auto name_it = td->attrRawByName.find(DW_AT_name);
		auto type_it = td->attrRawByName.find(DW_AT_type);
		if (name_it == td->attrRawByName.end() || type_it == td->attrRawByName.end()) continue;
		std::string td_name = readNameFromAttr(name_it->second.data);
		auto ref = readLEToUint64(type_it->second.data);
		auto pointed = resolve_ref_to_die(ref, cuStart);
		if (!pointed) continue;
		auto final_target = follow_typedef_chain(pointed);
		auto target_off = final_target ? final_target->offset : pointed->offset;
		if (typedef_map.find(target_off) == typedef_map.end()) typedef_map[target_off] = td_name;
	}




	for (auto& d : structure_type) {
		std::string nm;
		auto itn = d->attrRawByName.find(DW_AT_name);
		if (itn != d->attrRawByName.end())
			nm = readNameFromAttr(itn->second.data);
		else {
			auto it_alias = typedef_map.find(d->offset);
			if (it_alias != typedef_map.end())
				nm = it_alias->second;
			else {
				auto specIt = d->attrRawByName.find(DW_AT_specification);
				if (specIt != d->attrRawByName.end() && !specIt->second.data.empty()) {
					uint64_t specRef = readLEToUint64(specIt->second.data);
					auto specDie = resolve_ref_to_die(specRef, cuStart);
					if (specDie) {
						auto nn = specDie->attrRawByName.find(DW_AT_name);
						if (nn != specDie->attrRawByName.end())
							nm = readNameFromAttr(nn->second.data);
					}
				}
			}
		}
		if (!nm.empty()) {
			if (nm == targetName) {
				foundInThisCU = true;
				foundDIE = d;
				last_typedef_map_ = typedef_map;
				return true;
			}
		}
	}

	last_typedef_map_ = typedef_map;
	return true;
}

bool ElfDwarfParser::parseStructByName(const std::string& structName, StructInfo& out_structs) {
	if (debug_info_.empty()) {
		std::cerr << "No .debug_info loaded\n";
		return false;
	}

	size_t pos = 0;
	bool found = false;
	DIE* foundDIE = nullptr;
	uint32_t foundCUStart = 0;

	while (pos < debug_info_.size()) {
		uint32_t cuStart = pos;
		size_t tmp = pos;
		auto unit_length = static_cast<uint32_t>(readUintN(tmp, debug_info_, 4));;
		size_t cuEnd = 0;
		if (unit_length == 0xffffffffu) {
			size_t extpos = tmp;
			uint64_t ext_len = readUintN(extpos, debug_info_, 8);
			cuEnd = cuStart + 4 + 8 + (size_t)ext_len;
		}
		else {
			cuEnd = cuStart + 4 + static_cast<size_t>(unit_length);
		}
		if (cuEnd > debug_info_.size()) {
			std::cerr << "CU claims end beyond buffer\n";
			break;
		}

		bool foundInThisCU = false;
		DIE* diePtr = nullptr;

		size_t hdrPos = cuStart;
		auto tmpLen = static_cast<uint32_t>(readUintN(hdrPos, debug_info_, 4));
		bool is_64bit = (tmpLen == 0xffffffffu);
		if (is_64bit) {
			uint64_t ext_len = readUintN(hdrPos, debug_info_, 8);
		}

		if (!parseCU(cuStart, cuEnd, structName, foundInThisCU, diePtr)) {
		}

		if (foundInThisCU) {
			found = true;
			foundDIE = diePtr;
			foundCUStart = cuStart;
			break;
		}

		pos = cuEnd;
	}

	if (!found || !foundDIE) {
		return false;
	}

	StructInfo s;
	auto itn = foundDIE->attrRawByName.find(DW_AT_name);
	if (itn != foundDIE->attrRawByName.end()) {
		if (itn->second.data.size() == 4) { uint32_t off; std::memcpy(&off, itn->second.data.data(), 4); s.name = readStringAt(off); }
		else s.name = std::string(reinterpret_cast<const char*>(itn->second.data.data()));
	}
	else {
		auto it_alias = last_typedef_map_.find(foundDIE->offset);
		if (it_alias != last_typedef_map_.end()) s.name = it_alias->second;
		else s.name = "<anon_struct>";
	}


	auto bsize = foundDIE->attrRawByName.find(DW_AT_byte_size);
	if (bsize != foundDIE->attrRawByName.end() && !bsize->second.data.empty()) {
		s.size = readLEToUint64(bsize->second.data);
	}
	else {
		auto bits = getSizeForTypeDie(foundDIE);
		if (bits > 0 && bits % 8 == 0) s.size = bits / 8;
	}

	std::unordered_set<uint64_t> visited;
	for (DIE* child : foundDIE->children) {
		if (child->tag != DW_TAG_member) continue;
		MemberInfo mi;
		populateMemberInfo(child, foundCUStart, mi, visited);
		s.members.push_back(std::move(mi));
	}

	out_structs = std::move(s);
	return true;
}