#include <stdexcept>
#include <fstream>
#include "file_cryptor.hpp"
#define BLOCK_LENGTH 48


FileCryptor::FileCryptor() {
	this->crypting_algorithm = nullptr;
}

FileCryptor::FileCryptor(const std::shared_ptr<ICryptor>& cryptor) {
	this->crypting_algorithm = cryptor;
}

FileCryptor::FileCryptor(const FileCryptor& fileCryptor) {
	this->crypting_algorithm = fileCryptor.crypting_algorithm;
}

FileCryptor::FileCryptor(FileCryptor&& fileCryptor) noexcept {
	this->crypting_algorithm = std::move(fileCryptor.crypting_algorithm);
	fileCryptor.crypting_algorithm = nullptr;
}


void FileCryptor::set_crypting_algorithm(const std::shared_ptr<ICryptor>& cryptor) {
	this->crypting_algorithm = cryptor;
}


void FileCryptor::read_flag(std::ifstream& r) {
	uint8_t flag[49];
	r.read((char*)flag, BLOCK_LENGTH);
	crypting_algorithm->decrypt(flag);
	if (strcmp((char*)flag, "ckecking_message_ckecking_message_ckecking_mess\0")) { //Not safe. Need to be changed to hash.
		throw std::runtime_error("Didn't manage to decrypt file. Wrong key or algorithm.");
	}
}


void FileCryptor::write_flag(std::ofstream& w) {
	uint8_t flag[49] = "ckecking_message_ckecking_message_ckecking_mess\0";
	crypting_algorithm->encrypt(flag);
	w.write((char*)flag, BLOCK_LENGTH);
}


void FileCryptor::encrypt_file(const std::string& path_to_file) {
	std::ifstream reader(path_to_file, std::ifstream::in | std::ifstream::binary);

	if (!reader.is_open())
		throw std::runtime_error("Didn't manage to open the file.");

	std::ofstream writer(path_to_file + ".enc", std::ofstream::out | std::ofstream::binary);

	write_flag(writer);

	uint8_t block[BLOCK_LENGTH];
	bool end_file = false;
	short count;

	while (!end_file) {
		reader.read((char*)block, BLOCK_LENGTH);
		count = static_cast<short>(reader.gcount());

		if (count < BLOCK_LENGTH) {
			for (size_t i = count; i < BLOCK_LENGTH; i++)
				block[i] = 0;
			end_file = true;
		}

		crypting_algorithm->encrypt(block);

		writer.write((char*)block, BLOCK_LENGTH);
		if (end_file)
			writer.write((char*)&count, 1);
	}

	reader.close();
	writer.close();

	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}


void FileCryptor::decrypt_file(const std::string& path_to_file) {
	if (path_to_file.find(".enc", path_to_file.size() - 4) == (size_t)-1)
		throw std::runtime_error(("File " + path_to_file + " hasn't been crypted.").c_str());

	std::ifstream reader(path_to_file, std::ifstream::binary | std::ifstream::in);

	if (!reader.is_open())
		throw std::runtime_error("Didn't manage to open the file.");

	try {
		read_flag(reader);
	}
	catch (const std::exception& ex) {
		reader.close();
		throw ex;
	}

	std::ofstream writer(path_to_file.substr(0, path_to_file.size() - 4), std::ofstream::binary | std::ofstream::out);

	uint8_t block[BLOCK_LENGTH], check[2];

	while (true) {
		reader.read((char*)block, BLOCK_LENGTH);
		crypting_algorithm->decrypt(block);

		reader.read(reinterpret_cast<char*>(check), 2);
		if (reader.gcount() == 1) {
			writer.write(reinterpret_cast<char*>(block), check[0]);
			break;
		}
		else
			writer.write((char*)block, BLOCK_LENGTH);
		reader.seekg(reader.tellg().operator-(2));
	}

	reader.close();
	writer.close();


	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}

