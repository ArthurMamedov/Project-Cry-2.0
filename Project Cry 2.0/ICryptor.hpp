#pragma once
#include <memory>
#include <cstdint>

class ICore {
public:
	virtual auto cry_round(uint8_t* block)										-> void = 0;
	virtual auto inv_cry_round(uint8_t* block)									-> void = 0;
	virtual auto set_substitution_tables(uint8_t** sbox, uint8_t** inv_sbox)	-> void = 0;
	virtual auto set_key(const char* key)										-> void = 0;
	virtual auto get_block_length()												-> size_t = 0;
	virtual ~ICore() = default;
};

class ICryptor {
protected:
	std::unique_ptr<ICore> _algo;
	auto xor_blocks(uint8_t* block1, const uint8_t* block2)						-> void;
public:
	virtual auto encrypt(uint8_t* block)										-> void = 0;
	virtual auto decrypt(uint8_t* block)										-> void = 0;
	virtual auto get_block_length()												-> size_t;
	virtual auto reset()														-> void = 0;

	virtual ~ICryptor() = default;
};
