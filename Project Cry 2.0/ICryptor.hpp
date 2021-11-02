#pragma once
#include <memory>
#include <cstdint>
#include "ICore.hpp"

class ICryptor {
protected:
	std::unique_ptr<ICore> _algo;
	auto xor_blocks(uint8_t* block1, const uint8_t* block2);
public:
	virtual void encrypt(uint8_t* block) = 0;
	virtual void decrypt(uint8_t* block) = 0;
	virtual size_t get_block_length();
	virtual void reset() = 0;

	virtual ~ICryptor() = default;
};
