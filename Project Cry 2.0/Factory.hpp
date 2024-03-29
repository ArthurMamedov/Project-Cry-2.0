#pragma once
#include <string>
#include <stdexcept>
#include "AesCore.hpp"
#include "GostCore.hpp"
#include "BlowfishCore.hpp"
#include "AnubisCore.hpp"
#include "cryptors.hpp"

class Factory final {
private:
	Factory() = default;
	static auto _get_algo_core(const char* algorithm, const char* key) -> std::unique_ptr<ICore>;
	static auto _get_cryptor(const char* emode, std::unique_ptr<ICore>&& core) -> std::unique_ptr<ICryptor>;
public:
	static auto make_algorithm(char* algorithm, char* emode, const char* key) -> std::unique_ptr<ICryptor>;
};
