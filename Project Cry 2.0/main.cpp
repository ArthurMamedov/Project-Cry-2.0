#pragma once
#include <iostream>
//#include <functional>
//#include <numeric>
//#include <chrono>
//#include "FileCryptor.hpp"
//#include "Factory.hpp"
#include <conio.h>
#include "AnubisCore.hpp"

#define TAKE_TIME(func, arg, res) \
	auto start = std::chrono::high_resolution_clock::now(); \
	func(arg); \
	auto finish = std::chrono::high_resolution_clock::now(); \
	res = (std::chrono::duration_cast<std::chrono::milliseconds>(finish - start)).count();

void test_foo(uint8_t* block, const uint8_t* const_block) {
	block[0] = const_block[1];
	block[2] = const_block[0];
}

int main(int argc, char** argv) {
	//cry [encrypt/decrypt/help/enc/dec] [filepath1 filepath2 ...] [aes/gost/blowfish] [ecb/cbc/cfb/ofb/ctr] [key]
	using namespace std;

	uint8_t msg[] = { 171, 53, 61, 147, 178, 56, 147, 123, 229, 117, 203, 248, 168, 79, 148, 166 };

	uint8_t matrixH[17] = { 1, 2, 4, 6, 2, 1, 6, 4, 4, 6, 1, 2, 6, 4, 2, 1, 0 };
	for (size_t c = 0; c < 16; c++) {
		cout << (int)msg[c] << ' ';
	} cout << endl;
	//cout << strlen(reinterpret_cast<char*>(msg)) << endl;
	AnubisCore anubis;
	//anubis._matrix_mul(msg, matrixH);
	anubis._key_extension(matrixH);
	anubis.cry_round(msg);
	for (size_t c = 0; c < 16; c++) {
		cout << (int)msg[c] << ' ';
	} cout << endl;
	anubis.inv_cry_round(msg);

	for (size_t c = 0; c < 16; c++) {
		cout << (int)msg[c] << ' ';
	} cout << endl;
	//AnubisCore anubis;
	//for (size_t c = 0; c < 16; c++) {
	//	cout << (int)msg[c] << ' ';
	//} cout << endl;
	//for (size_t i = 0; i < 64; i++) {
	//	//cout << "Loop #" << i << ": ";
	//	//for (size_t c = 0; c < 16; c++) {
	//	//	cout << (int)msg[c] << ' ';
	//	//} cout << endl;
	//	anubis._matrix_mul(msg, matrixH);
	//}
	//for (size_t c = 0; c < 16; c++) {
	//	cout << (int)msg[c] << ' ';
	//} cout << endl;


	/*if (argc < 6 && 0 != strcmp(argv[1], "help")) {
		std::cerr << "Not enought arguments." << std::endl;
		return -1;
	}
	else if (argc < 6 && 0 == strcmp(argv[1], "help"))
	{
		std::string message =
			"Welcome to Project Cry 2.0!\n\n"
			"Project Cry is a simple program for encryption/decryption files.\n"
			"This aplicatoin was created for DEMONSTRATION PURPOSES ONLY and NOT RECOMENDED for using on a regular basis.\n"
			"It demonstrates the abylities of modern cryptography.\n\n"
			"Supported algorithms:\n"
			"\t- AES\n\t- GOST 28147-89\n\t- BLOWFISH\n\n"
			"Supported encryption modes:\n"
			"\t- ECB\n\t- CBC\n\t- CFB\n\t- OFB\n\t- CTR\n\n"
			"How to use:\n"
			"To use this application, run .exe file with the following parameters:\n"
			"\t- mode: encrypt/decrypt/help\n"
			"\t- file(s) to encrytp/decrypt (for example, 'file.txt')\n"
			"\t- algorithm name (listed in 'Supported algorithms' section)\n"
			"\t- encryption mode (listed in 'Supported encryption modes' section)\n"
			"\t- encryption key (for example, '1234567890abcdef'\n"
			"Example: Cry encrypt file.txt aes cbc 0123456789abcdef\n";
		std::cout << message << std::endl;
		return 0;
	}
	char* mode = argv[1];
	char* key	= argv[argc - 1];
	char* emode = argv[argc - 2];
	char* algorithm = argv[argc - 3];

	try {
		std::unique_ptr<ICryptor> cryptor = Factory::make_algorithm(algorithm, emode, key);
		FileCryptor file(std::move(cryptor));
		for (size_t c = 2; c < static_cast<size_t>(argc) - 3; c++) {
			try {
				size_t time = 0;
				if (!strcmp(mode, "encrypt")) {
					TAKE_TIME(file.encrypt_file, argv[c], time);
				} else if (!strcmp(mode, "decrypt")) {
					TAKE_TIME(file.decrypt_file, argv[c], time);
				} else {
					auto message = std::string("Unknown mode: ") + mode;
					std::cerr << message << std::endl;
					return -1;
				}
				std::cout << "File " << argv[c] << " succesfully " << mode << "ed!" << std::endl;
				std::cout << "Time spent: " << time << std::endl;
			} catch (const std::exception& ex) {
				std::cerr << ex.what() << std::endl;
			}
		}
	} catch (const std::exception& ex) {
		std::cerr << ex.what() << std::endl;
		return -1;
	}*/

	return 0;
}