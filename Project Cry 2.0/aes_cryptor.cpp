#include <stdexcept>
#include "aes_cryptor.hpp"

#define AES_EXT_KEY_LENGTH	176
#define AES_BLOCK_LENGTH	16

#pragma region AesCore
inline auto AesCore::_mul(uint8_t first, uint8_t second) -> uint8_t {
	uint8_t r = 0;
	for (int c = 7; c >= 0; c--) {
		r = r << 1;
		if ((first >> c) & 1)
			r = r ^ second;
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

	for (size_t i = 1; i < 255; i++)
		Rcon[i] = _pol_mul(2, Rcon[i - 1]);

	for (size_t i = 0; i < AES_BLOCK_LENGTH; i++)
		ext_key[i] = static_cast<uint8_t>(key[i]);

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
			for (size_t p = 0; p < 4; p++)
				ext_key[c + p] = ext_key[c - AES_BLOCK_LENGTH + p] ^ ext_key[c - 4 + p];
		}
	}
}

inline auto AesCore::_add_round_key(uint8_t* state, uint8_t* round_key) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		state[c] ^= round_key[c];
	}
}

inline auto AesCore::_shift(size_t from, uint8_t* state) -> void {
	for (size_t i = from; i < from + 3; i++)
		std::swap(state[i], state[i + 1]);
}

inline auto AesCore::_split_key(const char* key) -> void {
	uint8_t ext_key[AES_EXT_KEY_LENGTH];
	_key_extension(key, ext_key);
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = ext_key[c];
		_last[c] = ext_key[160 + c];
	}
	for (size_t c = 0; c < 9; c++)
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++)
			_middle[c][p] = ext_key[AES_BLOCK_LENGTH + c * AES_BLOCK_LENGTH + p];
}

inline auto AesCore::_rot_byte(const uint8_t* byte, uint8_t* to) -> void {
	memcpy(to, byte, 4);
	std::swap(to[0], to[3]);
}

inline auto AesCore::_sub_byte(uint8_t& byte) -> void {
	uint8_t f = byte >> 4;
	uint8_t s = byte ^ (f << 4);
	byte = _Sbox[f][s];
}

inline auto AesCore::_sub_bytes(uint8_t* state) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++)
		_sub_byte(state[c]);
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
	memmove(state, new_state, AES_BLOCK_LENGTH);
}

inline auto AesCore::_inv_sub_byte(uint8_t& byte) -> void {
	uint8_t f = byte >> 4;
	uint8_t s = byte ^ (f << 4);
	byte = _inv_Sbox[f][s];
}

inline auto AesCore::_inv_sub_bytes(uint8_t* state) -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++)
		_inv_sub_byte(state[c]);
}

inline auto AesCore::_inv_mix_colums(uint8_t* state) -> void {
	uint8_t new_state[AES_BLOCK_LENGTH];
	for (size_t i = 0; i < 4; i++) {
		new_state[i] = _pol_mul(14, state[i]) ^ _pol_mul(11, state[i + 4]) ^ _pol_mul(13, state[i + 8]) ^ _pol_mul(9, state[i + 12]);
		new_state[i + 4] = _pol_mul(9, state[i]) ^ _pol_mul(14, state[i + 4]) ^ _pol_mul(11, state[i + 8]) ^ _pol_mul(13, state[i + 12]);
		new_state[i + 8] = _pol_mul(13, state[i]) ^ _pol_mul(9, state[i + 4]) ^ _pol_mul(14, state[i + 8]) ^ _pol_mul(11, state[i + 12]);
		new_state[i + 12] = _pol_mul(11, state[i]) ^ _pol_mul(13, state[i + 4]) ^ _pol_mul(9, state[i + 8]) ^ _pol_mul(14, state[i + 12]);
	}
	memmove(state, new_state, AES_BLOCK_LENGTH);
}

inline auto AesCore::_inv_shift_rows(uint8_t* state) -> void {
	_shift(4, state);
	_shift(4, state);
	_shift(4, state);
	_shift(8, state);
	_shift(8, state);
	_shift(12, state);
}
#pragma endregion // AesCore

#pragma region AesEcbCryptor
AesEcbCryptor::AesEcbCryptor() {
	_is_ready = false;
}

AesEcbCryptor::AesEcbCryptor(const char* key) {
	if (strlen(key) != 16) {
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
			_Sbox[c][p] = aesEcbCryptor._Sbox[c][p];
			_inv_Sbox[c][p] = aesEcbCryptor._inv_Sbox[c][p];
		}
	}
}

AesEcbCryptor::~AesEcbCryptor() {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = 0;
		_last[c] = 0;
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = 0;
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_Sbox[c][p] = 0;
			_inv_Sbox[c][p] = 0;
		}
	}
}

auto AesEcbCryptor::set_key(const char* key) -> void {
	if (strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

auto AesEcbCryptor::encrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to encrypt with.");
	}
	_add_round_key(block, _first);
	for (size_t k = 0; k < 9; k++) {
		_sub_bytes(block);
		_shift_rows(block);
		_mix_colums(block);
		_add_round_key(block, _middle[k]);
	}
	_sub_bytes(block);
	_shift_rows(block);
	_add_round_key(block, _last);
}

auto AesEcbCryptor::decrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to decrypt with.");
	}
	_add_round_key(block, _last);
	_inv_shift_rows(block);
	_inv_sub_bytes(block);
	for (size_t c = 0; c < 9; c++) {
		_add_round_key(block, _middle[9 - c - 1]);
		_inv_mix_colums(block);
		_inv_shift_rows(block);
		_inv_sub_bytes(block);
	}
	_add_round_key(block, _first);
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
	if (strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

AesCbcCryptor::AesCbcCryptor(const AesCbcCryptor& aesCbcCryptor) {
	_is_ready = aesCbcCryptor._is_ready;
	memcpy(reinterpret_cast<void*>(_init_vector),
		   reinterpret_cast<const void*>(aesCbcCryptor._init_vector),
		   16);
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = aesCbcCryptor._first[c];
		_last[c] = aesCbcCryptor._last[c];
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = aesCbcCryptor._middle[c][p];
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_Sbox[c][p] = aesCbcCryptor._Sbox[c][p];
			_inv_Sbox[c][p] = aesCbcCryptor._inv_Sbox[c][p];
		}
	}
}

AesCbcCryptor::~AesCbcCryptor() {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_first[c] = 0;
		_last[c] = 0;
		for (size_t p = 0; p < AES_BLOCK_LENGTH && c < 9; p++) {
			_middle[c][p] = 0;
		}
		for (size_t p = 0; p < AES_BLOCK_LENGTH; p++) {
			_Sbox[c][p] = 0;
			_inv_Sbox[c][p] = 0;
		}
	}
}

auto AesCbcCryptor::set_key(const char* key) -> void {
	if (strlen(key) != 16) {
		throw std::runtime_error("Key length for AES must be 16 bytes.");
	}
	_split_key(key);
	_is_ready = true;
}

auto AesCbcCryptor::encrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to encrypt with.");
	}
	_add_round_key(block, _init_vector);
	_add_round_key(block, _first);
	for (size_t k = 0; k < 9; k++) {
		_sub_bytes(block);
		_shift_rows(block);
		_mix_colums(block);
		_add_round_key(block, _middle[k]);
	}
	_sub_bytes(block);
	_shift_rows(block);
	_add_round_key(block, _last);
	memcpy(reinterpret_cast<void*>(_init_vector),
		   reinterpret_cast<const void*>(block),
		   16);
}

auto AesCbcCryptor::decrypt(uint8_t* block) -> void {
	if (!_is_ready) {
		throw std::runtime_error("There is no key to decrypt with.");
	}
	uint8_t buf[16];
	memcpy(reinterpret_cast<void*>(buf),
		   reinterpret_cast<const void*>(block),
		   16);
	_add_round_key(block, _last);
	_inv_shift_rows(block);
	_inv_sub_bytes(block);
	for (size_t c = 0; c < 9; c++) {
		_add_round_key(block, _middle[9 - c - 1]);
		_inv_mix_colums(block);
		_inv_shift_rows(block);
		_inv_sub_bytes(block);
	}
	_add_round_key(block, _first);
	_add_round_key(block, _init_vector);
	memcpy(reinterpret_cast<void*>(_init_vector),
		   reinterpret_cast<const void*>(buf),
		   16);
}
auto AesCbcCryptor::reset() -> void {
	for (size_t c = 0; c < AES_BLOCK_LENGTH; c++) {
		_init_vector[c] = 0;
	}
}
#pragma endregion //AesCbcCryptor
