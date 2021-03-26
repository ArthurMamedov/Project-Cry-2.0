#include <stdexcept>
#include "BlowfishCore.hpp"

inline auto BlowfishCore::_split_block(const uint8_t* block, uint32_t& f, uint32_t& s) -> void {
	for (int c = 0; c < 4; c++) {
		f = (f << 8) | block[c];
		s = (s << 8) | block[c + 4];
	}
}

inline auto BlowfishCore::_xor_p_block_with_key(const char* key, const size_t key_size) -> void{
	uint32_t f = 0, s = 0, i = 0, buff = 0;
	while (s < 18) {
		if (i % 4 == 0 && i != 0) {
			_p_block[s] ^= buff;
			++s;
		}
		buff <<= 8;
		buff ^= key[f];
		++i;
		f = f < key_size ? f + 1 : 0;
	}
}

inline auto BlowfishCore::_key_extansion(const char* key) -> void {
	size_t key_size = strlen(key);

	if (key_size > 56 || key_size < 4) {
		throw std::runtime_error("Key's length must be bigger than 4 and less than 56 bytes.");
	}

	_xor_p_block_with_key(key, key_size);
	_key_encryption();
	_sbox_encryption();
}

inline auto BlowfishCore::_key_encryption() -> void {
	uint32_t right = 0, left = 0;
	for (size_t c = 0; c < 18; c += 2) {
		for (size_t p = 0; p < 16; p++) {
			_round(right, left, _p_block[p]);
		}
		right = _p_block[c] = right ^ _p_block[16];
		left = _p_block[c + 1] = left ^ _p_block[17];
	}
}

inline auto BlowfishCore::_sbox_encryption() -> void {
	auto enc = [&](size_t u) {
		uint32_t right = 0, left = 0;
		for (size_t c = 0; c < 256; c += 2) {
			for (size_t p = 0; p < 16; p++)
				_round(right, left, _p_block[p]);
			right = _sbox[u][c] = right ^ _p_block[16];
			left = _sbox[u][c + 1] = left ^ _p_block[17];
		}
	};
	enc(0);
	enc(1);
	enc(2);
	enc(3);
}

inline auto BlowfishCore::_round(uint32_t& block1, uint32_t& block2, const uint32_t& r_key) -> void {
	const auto res = block1 ^ r_key;
	const auto p = reinterpret_cast<const uint8_t*>(&res);  //(uint8_t*)(&res);
	uint32_t result = _sbox[0][p[0]];
	result += _sbox[1][p[1]];
	result ^= _sbox[2][p[2]];
	result += _sbox[3][p[3]];

	auto tmp = block1;
	block1 = result ^ block2;
	block2 = tmp;
}

inline auto BlowfishCore::_join_32b_block(const uint32_t& right, const uint32_t& left, uint8_t* block) -> void {
	for (int c = 3; c >= 0; c--) {
		block[c + 4] = static_cast<uint8_t>(right >> (8 * (3 - c)));
		block[c] = static_cast<uint8_t>(left >> (8 * (3 - c)));
	}
}

auto BlowfishCore::cry_round(uint8_t* block) -> void {
	uint32_t right, left;

	_split_block(block, right, left);

	for (size_t p = 0; p < 16; p++) {
		_round(right, left, _p_block[p]);
	}

	right ^= _p_block[16];
	left ^= _p_block[17];

	_join_32b_block(right, left, block);
}

auto BlowfishCore::inv_cry_round(uint8_t* block) -> void {
	uint32_t right, left;
	_split_block(block, right, left);
	right ^= _p_block[17];
	left ^= _p_block[16];
	for (int p = 15; p >= 0; p--) {
		_round(right, left, _p_block[p]);
	}
	_join_32b_block(right, left, block);
}

BlowfishCore::BlowfishCore(const char* key) {
	_key_extansion(key);
}

BlowfishCore::BlowfishCore(const BlowfishCore& blowfishCore) {
	for (size_t c = 0; c < 18; c++) {
		_p_block[c] = blowfishCore._p_block[c];
	}
	for (size_t c = 0; c < 4; c++) {
		for (size_t p = 0; p < 256; p++) {
			_sbox[c][p] = blowfishCore._sbox[c][p];
		}
	}
}

auto BlowfishCore::set_substitution_tables(const uint8_t** sbox, const uint8_t** inv_sbox) -> void {
	UNREFERENCED_PARAMETER(inv_sbox); //There is no inv_sbox in Blowfish algorithm, so we don't use it.
	for (size_t c = 0; c < 4; c++) {
		for (size_t p = 0; p < 256; p++) {
			_sbox[c][p] = sbox[c][p];
		}
	}
}

auto BlowfishCore::set_key(const char* key) -> void {
	_key_extansion(key);
}

auto BlowfishCore::get_block_length() -> size_t {
    return 8u;
}
