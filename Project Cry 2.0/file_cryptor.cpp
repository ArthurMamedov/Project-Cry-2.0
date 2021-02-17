#include <stdexcept>
#include <fstream>
#include "file_cryptor.hpp"

FileCryptor::FileCryptor() {
	this->crypting_algorithm = nullptr;
}

FileCryptor::FileCryptor(std::unique_ptr<ICryptor>&& cryptor) noexcept {
	this->crypting_algorithm = std::move(cryptor);
}

FileCryptor::FileCryptor(FileCryptor&& fileCryptor) noexcept {
	this->crypting_algorithm = std::move(fileCryptor.crypting_algorithm);
	fileCryptor.crypting_algorithm = nullptr;
}

void FileCryptor::set_crypting_algorithm(std::unique_ptr<ICryptor>&& cryptor) noexcept {
	this->crypting_algorithm = std::move(cryptor);
}

void FileCryptor::read_flag(std::ifstream& r) {
	uint8_t flag[33];
	uint8_t check[33] = "testmessagetestmessagetestmessag";
	auto block_size = crypting_algorithm->get_block_length();
	check[block_size - 1] = '\0';
	r.read((char*)flag, block_size);
	crypting_algorithm->decrypt(flag);
	if (strcmp(reinterpret_cast<char*>(flag), reinterpret_cast<char*>(check))) {
		throw std::runtime_error("Didn't manage to decrypt file. Wrong key or algorithm.");
	}
}

void FileCryptor::write_flag(std::ofstream& w) {
	uint8_t flag[33] = "testmessagetestmessagetestmessag";
	auto block_size = crypting_algorithm->get_block_length();
	flag[block_size - 1] = '\0';
	crypting_algorithm->encrypt(flag);
	w.write((char*)flag, block_size);
}

void FileCryptor::encrypt_file(const std::string& path_to_file) {
	std::ifstream reader(path_to_file, std::ifstream::in | std::ifstream::binary);

	if (!reader.is_open()) {
		throw std::runtime_error("Didn't manage to open the file.");
	}
	std::ofstream writer(path_to_file + ".enc", std::ofstream::out | std::ofstream::binary);
	auto block_length = crypting_algorithm->get_block_length();
	write_flag(writer);

	uint8_t block[32];
	bool end_file = false;
	short count;

	while (!end_file) {
		reader.read((char*)block, block_length);
		count = static_cast<short>(reader.gcount());

		if (count < block_length) {
			for (size_t i = count; i < block_length; i++)
				block[i] = 0;
			end_file = true;
		}

		crypting_algorithm->encrypt(block);

		writer.write((char*)block, block_length);
		if (end_file) {
			writer.write((char*)&count, 1);
		}
	}

	crypting_algorithm->reset();

	reader.close();
	writer.close();

	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}

void FileCryptor::decrypt_file(const std::string& path_to_file) {
	if (path_to_file.find(".enc", path_to_file.size() - 4) == (size_t)-1) {
		throw std::runtime_error(("File " + path_to_file + " hasn't been crypted.").c_str());
	}
	std::ifstream reader(path_to_file, std::ifstream::binary | std::ifstream::in);

	if (!reader.is_open()) {
		throw std::runtime_error("Didn't manage to open the file.");
	}
	try {
		read_flag(reader);
	} catch (const std::exception& ex) {
		reader.close();
		throw ex;
	}

	std::ofstream writer(path_to_file.substr(0, path_to_file.size() - 4), std::ofstream::binary | std::ofstream::out);
	auto block_length = crypting_algorithm->get_block_length();
	uint8_t check[2];
	uint8_t block[32];

	while (true) {
		reader.read((char*)block, block_length);
		crypting_algorithm->decrypt(block);

		reader.read(reinterpret_cast<char*>(check), 2);
		if (reader.gcount() == 1) {
			writer.write(reinterpret_cast<char*>(block), check[0]);
			break;
		} else {
			writer.write((char*)block, block_length);
		}
		reader.seekg(reader.tellg().operator-(2));
	}

	crypting_algorithm->reset();

	reader.close();
	writer.close();

	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}

