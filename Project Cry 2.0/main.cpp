#pragma once
#include <iostream>
#include <functional>
#include "aes_cryptor.hpp"

int main() {
	try {
		char arr[] = "Hello there!1234";
		char arr2[] = "Hello there!1234";
		uint8_t* t = reinterpret_cast<uint8_t*>(arr);
		uint8_t* p = reinterpret_cast<uint8_t*>(arr2);

		ICryptor* aesCryptor = new AesCfbCryptor();
		aesCryptor->set_key("1234567890abcdef");
		aesCryptor->encrypt(t);
		aesCryptor->encrypt(p);
		aesCryptor->reset();
		std::cout << t << std::endl << p << std::endl;
		aesCryptor->decrypt(t);
		aesCryptor->decrypt(p);
		std::cout << t << std::endl << p << std::endl;
	} catch (const std::exception& ex) {
		std::cout << ex.what() << std::endl;
	}

	return 0;
}