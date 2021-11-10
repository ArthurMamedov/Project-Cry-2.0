#include "ICryptor.hpp"

void ICryptor::xor_blocks(uint8_t* block1, const uint8_t* block2) {
	for (size_t c = 0; c < 16; c++) {
		block1[c] ^= block2[c];
	}
}

size_t ICryptor::get_block_length() {
	return _algo->get_block_length();
}

size_t ICryptor::get_key_length() {
	return _algo->get_key_length();
}
