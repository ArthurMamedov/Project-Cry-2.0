#pragma once
#include <iostream>
#include <functional>
#include <numeric>
#include <immintrin.h>
#include "cryptors.hpp"
#include "aes_core.hpp"
#include "gost_core.hpp"
#include "file_cryptor.hpp"

int main() {
	//EcbCryptor
	//CbcCryptor
	//CfbCryptor
	//OfbCryptor
	//CtrCryptor
	try {
		std::unique_ptr<ICryptor> aesCryptor(new CfbCryptor(std::make_unique<Gost28147_89>("1234567890abcdef1234567890abcdef")));
		FileCryptor file(std::move(aesCryptor));
		file.encrypt_file("tuxedo.txt");
		file.decrypt_file("tuxedo.txt.enc");
	} catch (const std::exception& ex) {
		std::cout << ex.what() << std::endl;
	}

	return 0;
}