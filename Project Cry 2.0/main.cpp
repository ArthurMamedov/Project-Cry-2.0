#pragma once
#include <iostream>
#include <functional>
#include <numeric>
#include "cryptors.hpp"
#include "aes_core.hpp"
#include "gost_core.hpp"
#include "blowfish_core.hpp"
#include "file_cryptor.hpp"
#include "factory.hpp"

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