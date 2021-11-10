#include <sstream>
#include "Factory.hpp"
#include "PasswordEqualizer.hpp"

auto Factory::_get_algo_core(const char* algorithm, const char* key) -> std::unique_ptr<ICore> {
	PasswordEqualizer pe;
	std::unique_ptr<ICore> result;
	if (!strcmp(algorithm, "aes")) {
		result = std::make_unique<AesCore>();
	} else if (!strcmp(algorithm, "gost") || !strcmp(algorithm, "gost28147-89")) {
		result = std::make_unique<GostCore>();
	} else if (!strcmp(algorithm, "blowfish")) {
		result = std::make_unique<BlowfishCore>();
	} else if (!strcmp(algorithm, "anubis")) {
		result = std::make_unique<AnubisCore>();
	} else {
		throw std::runtime_error(std::string("Unknown algorithm: ") + algorithm);
	}
	std::string equalized = std::move(pe.normalize_key_to_appropriate_length(key, result->get_key_length()));
	result->set_key(equalized.c_str());
	return std::move(result);
}

auto Factory::_get_cryptor(const char* emode, std::unique_ptr<ICore>&& core) -> std::unique_ptr<ICryptor> {
	if (!strcmp(emode, "ecb")) {
		return std::make_unique<EcbCryptor>(std::move(core));
	} else if (!strcmp(emode, "cbc")) {
		return std::make_unique<CbcCryptor>(std::move(core));
	} else if (!strcmp(emode, "cfb")) {
		return std::make_unique<CfbCryptor>(std::move(core));
	} else if (!strcmp(emode, "ofb")) {
		return std::make_unique<OfbCryptor>(std::move(core));
	} else if (!strcmp(emode, "ctr")) {
		return std::make_unique<CtrCryptor>(std::move(core));
	} else {
		std::stringstream ss;
		ss << "Unknown encryptino mode: " << emode;
		throw std::runtime_error(ss.str());
	}
}

auto Factory::make_algorithm(char* algorithm, char* emode, const char* key) -> std::unique_ptr<ICryptor> {
	for (size_t c = 0; c < std::strlen(algorithm); c++) {
		algorithm[c] = static_cast<char>(std::tolower(static_cast<int>(algorithm[c])));
	}
	for (size_t c = 0; c < strlen(emode); c++) {
		emode[c] = static_cast<char>(std::tolower(static_cast<int>(emode[c])));
	}
	std::unique_ptr<ICore> core = _get_algo_core(algorithm, key);
	return _get_cryptor(emode, std::move(core));
}
