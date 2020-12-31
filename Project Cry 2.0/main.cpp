#include <iostream>
#include <functional>
#include "aes_cryptor.hpp"



int main() {
	/*uint8_t arr[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, };
	uint8_t arr2[16];
	memcpy(reinterpret_cast<void*>(arr2),
		   reinterpret_cast<const void*>(arr),
		   16);
	for (int c = 0; c < 16; c++) {
		std::cout << (int)arr2[c] << std::endl;
	}*/
	try {
		char arr[] = "Hello there!1234";
		char arr2[] = "Hello there!1234";
		uint8_t* t = reinterpret_cast<uint8_t*>(arr);
		uint8_t* p = reinterpret_cast<uint8_t*>(arr2);

		ICryptor* aesCryptor = new AesEcbCryptor();
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