#pragma once
#include <memory>
#include <cstdint>
#include "ICore.hpp"

namespace ProjectCry {
	class ICryptor {
	protected:
		std::unique_ptr<ICore> _algo;
	public:
		virtual auto encrypt(uint8_t* block)	-> void = 0;
		virtual auto decrypt(uint8_t* block)	-> void = 0;
		virtual auto get_block_length()			-> size_t;
		virtual auto reset()					-> void = 0;

		virtual ~ICryptor() = default;
	};
}