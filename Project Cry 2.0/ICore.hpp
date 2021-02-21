#pragma once
#include <cstdint>

class ICore {
public:
	virtual auto cry_round(uint8_t* block)													-> void = 0;
	virtual auto inv_cry_round(uint8_t* block)												-> void = 0;
	virtual auto set_substitution_tables(const uint8_t** sbox, const uint8_t** inv_sbox)	-> void = 0;
	virtual auto set_key(const char* key)													-> void = 0;
	virtual auto get_block_length()															-> size_t = 0;
	virtual ~ICore() = default;
};