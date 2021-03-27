#include <stdexcept>
#include <cstring>
#include "AesCore.hpp"
#include "Auxilary.hpp"

using namespace ProjectCry;
using namespace ProjectCryAuxilary;

inline uint8_t AesCore::_mul(uint8_t first, uint8_t second) {
	uint8_t r = 0;
	for (int c = 7; c >= 0; c--) {
		r = r << 1;
		if ((first >> c) & 1) {
			r = r ^ second;
		}
	}
	return r;
}

inline auto AesCore::_mod(uint16_t num, uint16_t modulo) -> uint8_t {
	int i = 15;
	while (num >= modulo) {
		for (; i >= 0; i--) {
			bool tmp = (num >> i) & 1;
			if (tmp) {
				break;
			}
		}
		num = num ^ (modulo << (i - 8));
	}
	return static_cast<uint8_t>(num);
}

inline auto AesCore::_pol_mul(uint8_t f, uint8_t s) -> uint8_t {
	auto res = _mul(f, s);
	return _mod(res, 0b100011011);
}

inline auto AesCore::_key_extension(const char* key, uint8_t* ext_key) -> void {
	uint8_t Rcon[258]{ 0 };
	Rcon[0] = 1;

	for (size_t i = 1; i < 255; i++) {
		Rcon[i] = _pol_mul(2, Rcon[i - 1]);
	}

	for (size_t i = 0; i < AES_BLOCK_LENGTH; i++) {
		ext_key[i] = static_cast<uint8_t>(key[i]);
	}

	for (size_t c = AES_BLOCK_LENGTH; c < AES_EXT_KEY_LENGTH; c += 4) {
		size_t i = static_cast<size_t>(c / 4);
		if (!(i % 4)) {
			uint8_t rotated[4];

			_rot_byte(&ext_key[c - 4], rotated);

			for (size_t p = 0u; p < 4; p++) {
				_sub_byte(rotated[p]);
				ext_key[c + p] = rotated[p] ^ Rcon[i / 4];
			}
		} else {
			for (size_t p = 0; p < 4; p++) {
				ext_key[c + p] = ext_key[c - AES_BLOCK_LENGTH + p] ^ ext_key[c - 4 + p];
			}
		}
	}
}

inline auto AesCore::_shift(uint32_t from, uint8_t* state) -> void {
	for (uint32_t i = from; i < from + 3; i++) {
		std::swap(state[i], state[i + 1]);
	}
}

inline auto AesCore::_split_key(const char* key) -> void {
	uint8_t ext_key[AES_EXT_KEY_LENGTH];
	_key_extension(key, ext_key);
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = ext_key[c];
		_last[c] = ext_key[160 + c];
	}
	for (size_t c = 0; c < 9; c++) {
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_middle[c][p] = ext_key[AES_BLOCK_LENGTH + c * AES_BLOCK_LENGTH + p];
		}
	}
}

inline auto AesCore::_rot_byte(const uint8_t* byte, uint8_t* to) -> void {
	std::memcpy(to, byte, 4);
	std::swap(to[0], to[3]);
}

inline auto AesCore::_sub_byte(uint8_t& byte) -> void {
	uint8_t f = byte >> 4;
	uint8_t s = byte ^ (f << 4);
	byte = _sbox[f][s];
}

inline auto AesCore::_sub_bytes(uint8_t* state) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_sub_byte(state[c]);
	}
}

inline auto AesCore::_shift_rows(uint8_t* state) -> void {
	_shift(4, state);
	_shift(8, state);
	_shift(8, state);
	_shift(12, state);
	_shift(12, state);
	_shift(12, state);
}

inline auto AesCore::_mix_colums(uint8_t* state) -> void {  //a = 3x^3 + 1x^2 + 1x^2 + 2
	uint8_t new_state[AES_BLOCK_LENGTH]{ 0 }; // 01101001  x^6 + x^5 + x^3 + 1
	for (size_t i = 0; i < 4; i++) {
		new_state[i] = _pol_mul(2, state[i]) ^ _pol_mul(3, state[i + 4]) ^ state[i + 8] ^ state[i + 12];
		new_state[i + 4] = state[i] ^ _pol_mul(2, state[i + 4]) ^ _pol_mul(3, state[i + 8]) ^ state[i + 12];
		new_state[i + 8] = state[i] ^ state[i + 4] ^ _pol_mul(2, state[i + 8]) ^ _pol_mul(3, state[i + 12]);
		new_state[i + 12] = _pol_mul(3, state[i]) ^ state[i + 4] ^ state[i + 8] ^ _pol_mul(2, state[i + 12]);
	}
	std::memmove(state, new_state, AES_BLOCK_LENGTH);
}

inline auto AesCore::_inv_sub_byte(uint8_t& byte) -> void {
	uint8_t f = byte >> 4;
	uint8_t s = byte ^ (f << 4);
	byte = _inv_sbox[f][s];
}

inline auto AesCore::_inv_sub_bytes(uint8_t* state) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_inv_sub_byte(state[c]);
	}
}

inline auto AesCore::_inv_mix_colums(uint8_t* state) -> void {
	uint8_t new_state[AES_BLOCK_LENGTH]{ 0 };
	for (size_t i = 0; i < 4; i++) {
		new_state[i] =      _pol_mul(14, state[i]) ^ _pol_mul(11, state[i + 4]) ^ _pol_mul(13, state[i + 8]) ^ _pol_mul(9,  state[i + 12]);
		new_state[i + 4] =  _pol_mul(9,  state[i]) ^ _pol_mul(14, state[i + 4]) ^ _pol_mul(11, state[i + 8]) ^ _pol_mul(13, state[i + 12]);
		new_state[i + 8] =  _pol_mul(13, state[i]) ^ _pol_mul(9,  state[i + 4]) ^ _pol_mul(14, state[i + 8]) ^ _pol_mul(11, state[i + 12]);
		new_state[i + 12] = _pol_mul(11, state[i]) ^ _pol_mul(13, state[i + 4]) ^ _pol_mul(9,  state[i + 8]) ^ _pol_mul(14, state[i + 12]);
	}
	std::memmove(state, new_state, AES_BLOCK_LENGTH);
}

inline auto AesCore::_inv_shift_rows(uint8_t* state) -> void {
	_shift(4,  state);
	_shift(4,  state);
	_shift(4,  state);
	_shift(8,  state);
	_shift(8,  state);
	_shift(12, state);
}

AesCore::AesCore(const char* key) {
	if (std::strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
}

AesCore::AesCore(const AesCore& aesCore) {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = aesCore._first[c];
		_last[c] = aesCore._last[c];
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = aesCore._middle[c][p];
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = aesCore._sbox[c][p];
			_inv_sbox[c][p] = aesCore._inv_sbox[c][p];
		}
	}
}

inline auto AesCore::cry_round(uint8_t* block) -> void {
	xor_blocks(block, _first, AES_BLOCK_LENGTH);
	for (size_t k = 0; k < 9; k++) {
		_sub_bytes(block);
		_shift_rows(block);
		_mix_colums(block);
		xor_blocks(block, _middle[k], AES_BLOCK_LENGTH);
	}
	_sub_bytes(block);
	_shift_rows(block);
	xor_blocks(block, _last, AES_BLOCK_LENGTH);
}

inline auto AesCore::inv_cry_round(uint8_t* block) -> void {
	xor_blocks(block, _last, AES_BLOCK_LENGTH);
	_inv_shift_rows(block);
	_inv_sub_bytes(block);
	for (size_t c = 0; c < 9; c++) {
		xor_blocks(block, _middle[9 - c - 1], AES_BLOCK_LENGTH);
		_inv_mix_colums(block);
		_inv_shift_rows(block);
		_inv_sub_bytes(block);
	}
	xor_blocks(block, _first, AES_BLOCK_LENGTH);
}

auto AesCore::set_key(const char* key) -> void {
	if (std::strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
}

auto AesCore::set_substitution_tables(const uint8_t** sbox, const uint8_t** inv_sbox) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = sbox[c][p];
			_inv_sbox[c][p] = inv_sbox[c][p];
		}
	}
}

auto AesCore::get_block_length() -> size_t {
	return AES_BLOCK_LENGTH;
}

AesCore::~AesCore() {
	std::memset(_last, 0, AES_BLOCK_LENGTH);
	std::memset(_first, 0, AES_BLOCK_LENGTH);
	for (size_t c = 0; c < 9; c++) 		{
		std::memset(_middle[c], 0, AES_BLOCK_LENGTH);
	}
	for (size_t c = 0; c < 16; c++) 		{
		std::memset(_sbox[c], 0, AES_BLOCK_LENGTH);
		std::memset(_inv_sbox[c], 0, AES_BLOCK_LENGTH);
	}
}
