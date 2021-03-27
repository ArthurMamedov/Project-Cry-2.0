#include <stdexcept>
#include "AnubisCore.hpp"
#include "Auxilary.hpp"

using namespace ProjectCry;
using namespace ProjectCryAuxilary;

inline auto AnubisCore::_substitute(uint8_t chr) -> uint8_t {
	uint8_t left, right;
	left = (chr & 0b11111000) >> 3;
	right = chr & 0b00000111;
	return _sbox[left][right];
}

auto AnubisCore::_substitution_table(uint8_t* block) -> void {
	for (size_t c = 0; c < ANUBIS_BLOCK_LENGTH; c++) {
		block[c] = _substitute(block[c]);
	}
}

auto AnubisCore::_inv_columns(uint8_t* block) -> void {
	std::swap(block[1] , block[4] );
	std::swap(block[2] , block[8] );
	std::swap(block[3] , block[12]);
	std::swap(block[6] , block[9] );
	std::swap(block[7] , block[13]);
	std::swap(block[11], block[14]);
}

auto AnubisCore::_matrix_mul(uint8_t* matrix1, const uint8_t* matrix2) -> void {
	uint8_t res[16];
	
	std::memcpy(res, matrix1, ANUBIS_BLOCK_LENGTH);
	for (int c = 0; c < 4; ++c) {  //matrix multiplication
		for (int p = 0; p < 4; ++p) {
			uint8_t sum = 0;
			for (int u = 0; u < 4; ++u) {
				sum += matrix1[index(c, u, 4)] * matrix2[index(u, p, 4)];
			}
			res[index(c, p, 4)] = sum;
		}
	}
	std::memcpy(matrix1, res, ANUBIS_BLOCK_LENGTH);
}

auto AnubisCore::_key_extension(uint8_t* key) -> void {
	const size_t key_length = std::strlen(reinterpret_cast<char*>(key));
	if (key_length % 4 != 0) {
		throw std::runtime_error("Key length for Anubis must be devisible by 4 bytes.");
	} else if (key_length < 16 || key_length > 40) {
		throw std::runtime_error("Key length for Anubis must be more than 16 and less than 40 bytes long.");
	}

	_round_number = 8 + key_length / 4;
	_ext_key.reset(new uint8_t[_round_number * ANUBIS_BLOCK_LENGTH]);

	for (size_t c = 0; c < _round_number; c++) {
		std::memcpy(&_ext_key.get()[c * 16], key, ANUBIS_BLOCK_LENGTH);
		if (c == _round_number - 1) {
			break;
		}
		_substitution_table(key);
		_bit_shift(key, &_ext_key.get()[c * 16]);
		_matrix_mul(key, matrixH);
		key[0] = key[0] ^ _substitute(static_cast<uint8_t>(4 * c));
		key[1] = key[1] ^ _substitute(static_cast<uint8_t>(4 * c + 1));
		key[2] = key[2] ^ _substitute(static_cast<uint8_t>(4 * c + 2));
		key[3] = key[3] ^ _substitute(static_cast<uint8_t>(4 * c + 3));
		_substitution_table(key);
		_matrix_mul(key, matrixV);
		_inv_columns(key);
	}
	std::memset(key, 0, ANUBIS_BLOCK_LENGTH);
}

auto AnubisCore::_bit_shift(uint8_t* block, const uint8_t* round_key) -> void {
	uint64_t left   = reinterpret_cast<uint64_t*>(block)[0];
	uint64_t right  = reinterpret_cast<uint64_t*>(block)[1];
	uint64_t kleft  = reinterpret_cast<const uint64_t*>(round_key)[0];
	uint64_t kright = reinterpret_cast<const uint64_t*>(round_key)[1];
	right ^= ((left & kleft) << 1) | ((left & kleft) >> 63);
	left ^= right | kright;
	std::memcpy(&block[0], &left, 8);
	std::memcpy(&block[8], &right, 8);
}

inline auto AnubisCore::_set_key(const char* key) -> void {
	uint8_t _key[41]{ 0 };
	std::memcpy(_key, key, std::strlen(key));
	_key_extension(_key);
}

AnubisCore::AnubisCore(const char* key) {
	_set_key(key);
}

AnubisCore::AnubisCore(const AnubisCore& anubis_core) {
	for (size_t c = 0; c < 32; c++) {
		std::memcpy(_sbox[c], anubis_core._sbox[c], 8);
	}
	_round_number = anubis_core._round_number;
	_ext_key.reset(new uint8_t[_round_number + ANUBIS_BLOCK_LENGTH]);
	std::memcpy(_ext_key.get(), anubis_core._ext_key.get(), _round_number + ANUBIS_BLOCK_LENGTH);
}

auto AnubisCore::cry_round(uint8_t* block) -> void {
	xor_blocks(block, _ext_key.get(), ANUBIS_BLOCK_LENGTH);
	for (size_t c = 0; c < _round_number - 1; c++) {
		_substitution_table(block);
		_inv_columns(block);
		_matrix_mul(block, matrixH);
		xor_blocks(block, &_ext_key[c * ANUBIS_BLOCK_LENGTH], ANUBIS_BLOCK_LENGTH);
	}
	_substitution_table(block);
	_inv_columns(block);
	xor_blocks(block, &_ext_key[(_round_number - 1) * ANUBIS_BLOCK_LENGTH], ANUBIS_BLOCK_LENGTH);
}

auto AnubisCore::inv_cry_round(uint8_t* block) -> void {
	xor_blocks(block, &_ext_key[(_round_number - 1) * ANUBIS_BLOCK_LENGTH], ANUBIS_BLOCK_LENGTH);
	_inv_columns(block);
	_substitution_table(block);
	for (int c = static_cast<int>(_round_number) - 2; c >= 0; c--) {
		xor_blocks(block, &_ext_key[c * ANUBIS_BLOCK_LENGTH], ANUBIS_BLOCK_LENGTH);
		_matrix_mul(block, inv_matrixH);
		_inv_columns(block);
		_substitution_table(block);
	}
	xor_blocks(block, _ext_key.get(), ANUBIS_BLOCK_LENGTH);
}

auto AnubisCore::set_substitution_tables(const uint8_t** sbox, const uint8_t** inv_sbox) -> void {
	UNREFERENCED_PARAMETER(inv_sbox);
	for (size_t c = 0; c < 32; c++) {
		std::memcpy(_sbox[c], sbox[c], 8);
	}
}

auto AnubisCore::set_key(const char* key) -> void {
	_set_key(key);
}

auto AnubisCore::get_block_length() -> size_t {
	return ANUBIS_BLOCK_LENGTH;
}
