#pragma once
#include <memory>
#include <cstring>
#include "ICore.hpp"

class AnubisCore final : public ICore {
private:
	uint8_t _sbox[32][8] = {
		{ 0xA7, 0xD3, 0xE6, 0x71, 0xD0, 0xAC, 0x4D, 0x79 },
		{ 0x3A, 0xC9, 0x91, 0xFC, 0x1E, 0x47, 0x54, 0xBD },
		{ 0x8C, 0xA5, 0x7A, 0xFB, 0x63, 0xB8, 0xDD, 0xD4 },
		{ 0xE5, 0xB3, 0xC5, 0xBE, 0xA9, 0x88, 0x0C, 0xA2 },
		{ 0x39, 0xDF, 0x29, 0xDA, 0x2B, 0xA8, 0xCB, 0x4C },
		{ 0x4B, 0x22, 0xAA, 0x24, 0x41, 0x70, 0xA6, 0xF9 },
		{ 0x5A, 0xE2, 0xB0, 0x36, 0x7D, 0xE4, 0x33, 0xFF },
		{ 0x60, 0x20, 0x08, 0x8B, 0x5E, 0xAB, 0x7F, 0x78 },
		{ 0x7C, 0x2C, 0x57, 0xD2, 0xDC, 0x6D, 0x7E, 0x0D },
		{ 0x53, 0x94, 0xC3, 0x28, 0x27, 0x06, 0x5F, 0xAD },
		{ 0x67, 0x5C, 0x55, 0x48, 0x0E, 0x52, 0xEA, 0x42 },
		{ 0x5B, 0x5D, 0x30, 0x58, 0x51, 0x59, 0x3C, 0x4E },
		{ 0x38, 0x8A, 0x72, 0x14, 0xE7, 0xC6, 0xDE, 0x50 },
		{ 0x8E, 0x92, 0xD1, 0x77, 0x93, 0x45, 0x9A, 0xCE },
		{ 0x2D, 0x03, 0x62, 0xB6, 0xB9, 0xBF, 0x96, 0x6B },
		{ 0x3F, 0x07, 0x12, 0xAE, 0x40, 0x34, 0x46, 0x3E },
		{ 0xDB, 0xCF, 0xEC, 0xCC, 0xC1, 0xA1, 0xC0, 0xD6 },
		{ 0x1D, 0xF4, 0x61, 0x3B, 0x10, 0xD8, 0x68, 0xA0 },
		{ 0xB1, 0x0A, 0x69, 0x6C, 0x49, 0xFA, 0x76, 0xC4 },
		{ 0x9E, 0x9B, 0x6E, 0x99, 0xC2, 0xB7, 0x98, 0xBC },
		{ 0x8F, 0x85, 0x1F, 0xB4, 0xF8, 0x11, 0x2E, 0x00 },
		{ 0x25, 0x1C, 0x2A, 0x3D, 0x05, 0x4F, 0x7B, 0xB2 },
		{ 0x32, 0x90, 0xAF, 0x19, 0xA3, 0xF7, 0x73, 0x9D },
		{ 0x15, 0x74, 0xEE, 0xCA, 0x9F, 0x0F, 0x1B, 0x75 },
		{ 0x86, 0x84, 0x9C, 0x4A, 0x97, 0x1A, 0x65, 0xF6 },
		{ 0xED, 0x09, 0xBB, 0x26, 0x83, 0xEB, 0x6F, 0x81 },
		{ 0x04, 0x6A, 0x43, 0x01, 0x17, 0xE1, 0x87, 0xF5 },
		{ 0x8D, 0xE3, 0x23, 0x80, 0x44, 0x16, 0x66, 0x21 },
		{ 0xFE, 0xD5, 0x31, 0xD9, 0x35, 0x18, 0x02, 0x64 },
		{ 0xF2, 0xF1, 0x56, 0xCD, 0x82, 0xC8, 0xBA, 0xF0 },
		{ 0xEF, 0xE9, 0xE8, 0xFD, 0x89, 0xD7, 0xC7, 0xB5 },
		{ 0xA4, 0x2F, 0x95, 0x13, 0x0B, 0xF3, 0xE0, 0x37 }
	};

	const uint8_t matrixH[16] = { 1, 2, 4, 6, 2, 1, 6, 4, 4, 6, 1, 2, 6, 4, 2, 1 };
	const uint8_t inv_matrixH[16] = { 153, 238, 116, 202, 238, 153, 202, 116, 116, 202, 153, 238, 202, 116, 238, 153 };
	
	const uint8_t matrixV[16] = { 1, 1, 1, 1, 1, 2, 4, 8, 1, 6, 36, 216, 1, 8, 64, 0 };
	const size_t _block_length = 16;
	size_t _round_number;
	std::unique_ptr<uint8_t[]> _ext_key = nullptr;

	auto _substitution_table(uint8_t* block) -> void;
	auto _inv_columns(uint8_t* block) -> void;
	auto _matrix_mul(uint8_t* matrix1, const uint8_t* matrix2) -> void;
	auto _key_extension(uint8_t* key) -> void;
	auto _xor_blocks(uint8_t* block1, const uint8_t* block2) -> void;
	auto _bit_shift(uint8_t* block, const uint8_t* round_key) -> void;
	inline auto _substitute(uint8_t chr) -> uint8_t;
	inline auto _set_key(const char* key) -> void;

public:
	AnubisCore(const char* key);
	AnubisCore(const AnubisCore& anubis_core);

	virtual auto cry_round(uint8_t* block) -> void override;
	virtual auto inv_cry_round(uint8_t* block) -> void override;
	virtual auto set_substitution_tables(const uint8_t** sbox, const uint8_t** inv_sbox) -> void override;
	virtual auto set_key(const char* key) -> void override;
	virtual auto get_block_length() -> size_t override;
};
