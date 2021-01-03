#pragma once
#include <iostream>
#include <functional>
#include <numeric>
#include <immintrin.h>
#include "cryptors.hpp"
#include "aes_core.hpp"
#include "gost_core.hpp"
#include "blowfish_core.hpp"
#include "file_cryptor.hpp"

class Factory final {
private:
	static std::unique_ptr<ICore> _get_algo_core(const char* algorithm, const char* key) {
		if (!strcmp(algorithm, "aes")) {
			return std::make_unique<AesCore>(key);
		} else if (!strcmp(algorithm, "gost") || !strcmp(algorithm, "gost28147-89")) {
			return std::make_unique<GostCore>(key);
		} else if (!strcmp(algorithm, "blowfish")) {
			return std::make_unique<BlowfishCore>(key);
		} else {
			throw std::runtime_error("Unknown algorithm.");
		}
	}
	static std::unique_ptr<ICryptor> _get_cryptor(const char* emode, std::unique_ptr<ICore>&& core) {
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
			throw std::runtime_error("Unknown encryption mode.");
		}
	}
public:
	static std::unique_ptr<ICryptor> make_algorithm(char* algorithm, char* emode, const char* key) {
		for (size_t c = 0; c < strlen(algorithm); c++) {
			algorithm[c] = static_cast<char>(tolower(static_cast<int>(algorithm[c])));
		}
		for (size_t c = 0; c < strlen(emode); c++) {
			emode[c] = static_cast<char>(tolower(static_cast<int>(emode[c])));
		}
		std::unique_ptr<ICore> core = _get_algo_core(algorithm, key);
		return _get_cryptor(emode, std::move(core));
	}
};

int main(int argc, char** argv) {
	//cry [encrypt/decrypt/help/enc/dec] [filepath1 filepath2 ...] [aes/gost/blowfish] [ecb/cbc/cfb/ofb/ctr] [key]
	if (argc < 6 && argv[1] != "help") {
		std::cout << "Not enought arguments." << std::endl;
		return 0;
	} else if (argc < 6 && argv[1] == "help") {
		std::cout << "Here will be some help..." << std::endl;
		return 0;
	}
	char* mode = argv[1];
	char* key	= argv[argc - 1];
	char* emode = argv[argc - 2];
	char* algorithm = argv[argc - 3];

	try {
		std::unique_ptr<ICryptor> cryptor = Factory::make_algorithm(algorithm, emode, key);
		FileCryptor file(std::move(cryptor));
		for (size_t c = 2; c < argc - 3; c++) {
			if (!strcmp(mode, "encrypt")) {
				file.encrypt_file(argv[c]);
			} else if (!strcmp(mode, "decrypt")) {
				file.decrypt_file(argv[c]);
			} else {
				throw std::runtime_error("Unknown mode.");
			}
		}
	} catch (const std::exception& ex) {
		std::cout << ex.what() << std::endl;
	}

	return 0;
}