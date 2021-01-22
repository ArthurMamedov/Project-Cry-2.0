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
	//char p[] = "Hello there!";
	//std::cout << (int*)p << std::endl;
	//auto lmbd = [&p]() {
	//	p[0] = 'T';
	//	std::cout << (int*)p << std::endl;
	//};
	//lmbd();
	//std::cout << p << std::endl;
	
	std::unique_ptr<ICore> core(new AesCore("1234567890abcdef"));
	std::unique_ptr<ICryptor> cryptor(new CfbCryptor(std::move(core)));
	/*auto p = dynamic_cast<CfbCryptor*>(cryptor.get());
	p->set_init_vec((uint8_t*)"abcdef0123456789");*/
	FileCryptor file(std::move(cryptor));
	file.encrypt_file("D:\\Projects\\C++\\ProjectCry 2.0\\Project Cry 2.0\\Project Cry 2.0\\tuxedo.txt");
	file.decrypt_file("D:\\Projects\\C++\\ProjectCry 2.0\\Project Cry 2.0\\Project Cry 2.0\\tuxedo.txt.enc");
	std::cout << "FINISH!" << std::endl;

	
	/*if (argc < 6 && argv[1] != "help") {
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
	}*/

	return 0;
}