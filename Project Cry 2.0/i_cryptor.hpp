#pragma once
#include <memory>
#include <cstdint>
#include "i_core.hpp"

class ICryptor {
public:
	virtual ~ICryptor() = default;

	virtual auto encrypt(uint8_t* block)													-> void = 0;
	virtual auto decrypt(uint8_t* block)													-> void = 0;
	virtual auto get_block_length()															-> size_t;
	virtual auto get_parallelization_power()												-> size_t;
	virtual auto set_parallelization_power(const size_t parallelization_power)				-> void = 0;
	virtual auto reset()																	-> void = 0;

protected:
	auto _xor_blocks(uint8_t* block1, const uint8_t* block2)								-> void;

protected:
	std::unique_ptr<ICore> _algo;
	size_t _parallelization_power = 1;
};
