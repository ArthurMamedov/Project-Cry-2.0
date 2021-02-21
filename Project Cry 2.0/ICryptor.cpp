#include "ICryptor.hpp"

auto ICryptor::xor_blocks(uint8_t* block1, const uint8_t* block2) -> void {
	for (size_t c = 0; c < 16; c++) {
		block1[c] ^= block2[c];
	}
}

auto ICryptor::get_block_length() -> size_t {
	return _algo->get_block_length();
}
