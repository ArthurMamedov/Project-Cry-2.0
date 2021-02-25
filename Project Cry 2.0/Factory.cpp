#include "factory.hpp"

auto Factory::_get_algo_core(const char* algorithm, const char* key) -> std::unique_ptr<ICore> {
	if (!strcmp(algorithm, "aes")) {
		return std::make_unique<AesCore>(key);
	} else if (!strcmp(algorithm, "gost") || !strcmp(algorithm, "gost28147-89")) {
		return std::make_unique<GostCore>(key);
	} else if (!strcmp(algorithm, "blowfish")) {
		return std::make_unique<BlowfishCore>(key);
	} else if (!strcmp(algorithm, "anubis")) {
		return std::make_unique<AnubisCore>(key);
	} else {
		throw std::runtime_error(std::string("Unknown algorithm: ") + algorithm);
	}
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
		throw std::runtime_error(std::string("Unknown encryption mode: ") + emode);
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
