#pragma once
#include <memory>
#include <cstdint>
#include "i_core.hpp"

class ICryptor {
protected:
	std::unique_ptr<ICore> _algo;
	unsigned int _parallelization_power;
	auto _xor_blocks(uint8_t* block1, const uint8_t* block2)								-> void;
public:
	virtual auto encrypt(uint8_t* block)													-> void = 0;
	virtual auto decrypt(uint8_t* block)													-> void = 0;
	virtual auto get_block_length()															-> size_t;
	virtual auto get_parallelization_power()												-> size_t;
	virtual auto set_parallelization_power(unsigned int parallelization_power)				-> void {};
	virtual auto reset()																	-> void = 0;

	virtual ~ICryptor() = default;
};
