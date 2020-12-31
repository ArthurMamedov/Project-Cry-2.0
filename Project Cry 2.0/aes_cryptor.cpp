#include <stdexcept>
#include <cstring>
#include "aes_cryptor.hpp"

#define AES_EXT_KEY_LENGTH	176
#define AES_BLOCK_LENGTH	16

#pragma region AesCore
inline auto AesCore::_mul(uint8_t first, uint8_t second) -> uint8_t {
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
	uint8_t Rcon[258];
	Rcon[0] = 1; Rcon[257] = Rcon[256] = Rcon[255] = 0;

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

inline auto AesCore::_xor_blocks(uint8_t* block1, const uint8_t* block2) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		block1[c] ^= block2[c];
	}
}

inline auto AesCore::_shift(uint32_t from, uint8_t* state) -> void {
	for (size_t i = from; i < from + 3; i++) {
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
	uint8_t new_state[AES_BLOCK_LENGTH]; // 01101001  x^6 + x^5 + x^3 + 1
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
	uint8_t new_state[AES_BLOCK_LENGTH];
	for (size_t i = 0; i < 4; i++) {
		new_state[i] = _pol_mul(14, state[i]) ^ _pol_mul(11, state[i + 4]) ^ _pol_mul(13, state[i + 8]) ^ _pol_mul(9, state[i + 12]);
		new_state[i + 4] = _pol_mul(9, state[i]) ^ _pol_mul(14, state[i + 4]) ^ _pol_mul(11, state[i + 8]) ^ _pol_mul(13, state[i + 12]);
		new_state[i + 8] = _pol_mul(13, state[i]) ^ _pol_mul(9, state[i + 4]) ^ _pol_mul(14, state[i + 8]) ^ _pol_mul(11, state[i + 12]);
		new_state[i + 12] = _pol_mul(11, state[i]) ^ _pol_mul(13, state[i + 4]) ^ _pol_mul(9, state[i + 8]) ^ _pol_mul(14, state[i + 12]);
	}
	std::memmove(state, new_state, AES_BLOCK_LENGTH);
}

inline auto AesCore::_inv_shift_rows(uint8_t* state) -> void {
	_shift(4, state);
	_shift(4, state);
	_shift(4, state);
	_shift(8, state);
	_shift(8, state);
	_shift(12, state);
}

inline auto AesCore::_cry_round(uint8_t* block) -> void {
	_xor_blocks(block, _first);
	for (size_t k = 0; k < 9; k++) {
		_sub_bytes(block);
		_shift_rows(block);
		_mix_colums(block);
		_xor_blocks(block, _middle[k]);
	}
	_sub_bytes(block);
	_shift_rows(block);
	_xor_blocks(block, _last);
}

inline auto AesCore::_inv_cry_round(uint8_t* block) -> void {
	_xor_blocks(block, _last);
	_inv_shift_rows(block);
	_inv_sub_bytes(block);
	for (size_t c = 0; c < 9; c++) {
		_xor_blocks(block, _middle[9 - c - 1]);
		_inv_mix_colums(block);
		_inv_shift_rows(block);
		_inv_sub_bytes(block);
	}
	_xor_blocks(block, _first);
}

auto AesCore::set_key(const char* key) -> void {
	if (std::strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

auto AesCore::set_substitution_tables(uint8_t** sbox, uint8_t** inv_sbox) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = sbox[c][p];
			_inv_sbox[c][p] = inv_sbox[c][p];
		}
	}
}

AesCore::~AesCore() {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = 0;
		_last[c] = 0;
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = 0;
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = 0;
			_inv_sbox[c][p] = 0;
		}
	}
}
#pragma endregion // AesCore

#pragma region AesEcbCryptor
AesEcbCryptor::AesEcbCryptor() {
	_is_ready = false;
}

AesEcbCryptor::AesEcbCryptor(const char* key) {
	if (std::strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

AesEcbCryptor::AesEcbCryptor(const AesEcbCryptor& aesEcbCryptor) {
	_is_ready = aesEcbCryptor._is_ready;
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = aesEcbCryptor._first[c];
		_last[c] = aesEcbCryptor._last[c];
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = aesEcbCryptor._middle[c][p];
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = aesEcbCryptor._sbox[c][p];
			_inv_sbox[c][p] = aesEcbCryptor._inv_sbox[c][p];
		}
	}
}

auto AesEcbCryptor::encrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to encrypt with.");
	}
	_cry_round(block);
}

auto AesEcbCryptor::decrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to decrypt with.");
	}
	_inv_cry_round(block);
}

auto AesEcbCryptor::reset() -> void {
	return;
}
#pragma endregion //AesEcbCryptor

#pragma region AesCbcCryptor
AesCbcCryptor::AesCbcCryptor() {
	_is_ready = false;
}

AesCbcCryptor::AesCbcCryptor(const char* key) {
	if (std::strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

AesCbcCryptor::AesCbcCryptor(const AesCbcCryptor& aesCbcCryptor) {
	_is_ready = aesCbcCryptor._is_ready;
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(aesCbcCryptor._init_vec),
				16);
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(aesCbcCryptor._save_init_vec),
				16);
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = aesCbcCryptor._first[c];
		_last[c] = aesCbcCryptor._last[c];
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = aesCbcCryptor._middle[c][p];
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = aesCbcCryptor._sbox[c][p];
			_inv_sbox[c][p] = aesCbcCryptor._inv_sbox[c][p];
		}
	}
}

auto AesCbcCryptor::encrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to encrypt with.");
	}
	_xor_blocks(block, _init_vec);
	_cry_round(block);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(block),
				16);
}

auto AesCbcCryptor::decrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to decrypt with.");
	}
	uint8_t buf[16];
	std::memcpy(reinterpret_cast<void*>(buf),
				reinterpret_cast<const void*>(block),
				16);
	_inv_cry_round(block);
	_xor_blocks(block, _init_vec);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(buf),
				AES_BLOCK_LENGTH);
}

auto AesCbcCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				AES_BLOCK_LENGTH);
}

auto AesCbcCryptor::set_init_vec(uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(init_vec),
				AES_BLOCK_LENGTH);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				AES_BLOCK_LENGTH);
}
#pragma endregion //AesCbcCryptor

#pragma region AesCfbCryptor
AesCfbCryptor::AesCfbCryptor() {
	_is_ready = false;
}

AesCfbCryptor::AesCfbCryptor(const char* key) {
	if (std::strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

AesCfbCryptor::AesCfbCryptor(const AesCfbCryptor& aesCfbCryptor) {
	_is_ready = aesCfbCryptor._is_ready;
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(aesCfbCryptor._init_vec),
				16);
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(aesCfbCryptor._save_init_vec),
				16);
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = aesCfbCryptor._first[c];
		_last[c] = aesCfbCryptor._last[c];
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = aesCfbCryptor._middle[c][p];
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_sbox[c][p] = aesCfbCryptor._sbox[c][p];
			_inv_sbox[c][p] = aesCfbCryptor._inv_sbox[c][p];
		}
	}
}

auto AesCfbCryptor::encrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to encrypt with.");
	}
	_cry_round(_init_vec);
	_xor_blocks(block, _init_vec);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(block),
				AES_BLOCK_LENGTH);
}

auto AesCfbCryptor::decrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to encrypt with.");
	}
	uint8_t buf[AES_BLOCK_LENGTH];
	memcpy(buf, block, AES_BLOCK_LENGTH);
	_cry_round(_init_vec);
	_xor_blocks(block, _init_vec);
	memcpy(_init_vec, buf, AES_BLOCK_LENGTH);
}

auto AesCfbCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				AES_BLOCK_LENGTH);
}

auto AesCfbCryptor::set_init_vec(uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(init_vec),
				AES_BLOCK_LENGTH);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				AES_BLOCK_LENGTH);
}
#pragma endregion //AesCfbCryptor