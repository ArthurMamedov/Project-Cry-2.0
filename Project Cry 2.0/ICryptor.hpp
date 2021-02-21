#pragma once
#include <memory>
#include <cstdint>
#include "ICore.hpp"

class ICryptor {
protected:
	std::unique_ptr<ICore> _algo;
	auto xor_blocks(uint8_t* block1, const uint8_t* block2)									-> void;
public:
	virtual auto encrypt(uint8_t* block)													-> void = 0;
	virtual auto decrypt(uint8_t* block)													-> void = 0;
	virtual auto get_block_length()															-> size_t;
	virtual auto reset()																	-> void = 0;

	virtual ~ICryptor() = default;
};
