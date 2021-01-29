#include <stdexcept>
#include <fstream>
#include "file_cryptor.hpp"

#define PRL_POW 3

FileCryptor::FileCryptor() {
	_crypting_algorithm = nullptr;
}

FileCryptor::FileCryptor(std::unique_ptr<ICryptor>&& cryptor) noexcept {
	_crypting_algorithm = std::move(cryptor);
	_crypting_algorithm->set_parallelization_power(PRL_POW);  //TODO: Add an opportunity to choose the parallelization power.
	_block.reset(new uint8_t[_crypting_algorithm->get_block_length() * _crypting_algorithm->get_parallelization_power()]);
}

FileCryptor::FileCryptor(FileCryptor&& fileCryptor) noexcept {
	_crypting_algorithm = std::move(fileCryptor._crypting_algorithm);
	_crypting_algorithm->set_parallelization_power(PRL_POW);
	_block = std::move(fileCryptor._block);
	fileCryptor._crypting_algorithm = nullptr;
}

void FileCryptor::set_crypting_algorithm(std::unique_ptr<ICryptor>&& cryptor) noexcept {
	_crypting_algorithm = std::move(cryptor);
	_crypting_algorithm->set_parallelization_power(PRL_POW);
	_block.reset(new uint8_t[_crypting_algorithm->get_block_length() * _crypting_algorithm->get_parallelization_power()]);
}

void FileCryptor::_read_flag(std::ifstream& r) {
	uint8_t flag[33];
	uint8_t check[33] = "testmessagetestmessagetestmessag";
	auto block_size = _crypting_algorithm->get_block_length();
	check[block_size - 1] = '\0';
	r.read((char*)flag, block_size);
	auto save = _crypting_algorithm->get_parallelization_power();
	_crypting_algorithm->set_parallelization_power(1);
	_crypting_algorithm->decrypt(flag);
	_crypting_algorithm->set_parallelization_power(save);
	if (strcmp(reinterpret_cast<char*>(flag), reinterpret_cast<char*>(check))) {
		throw std::runtime_error("Didn't manage to decrypt file. Wrong key or algorithm.");
	}
}

void FileCryptor::_write_flag(std::ofstream& w) {
	uint8_t flag[33] = "testmessagetestmessagetestmessag";
	auto block_size = _crypting_algorithm->get_block_length();
	flag[block_size - 1] = '\0';
	auto save = _crypting_algorithm->get_parallelization_power();
	_crypting_algorithm->set_parallelization_power(1);
	_crypting_algorithm->encrypt(flag);
	_crypting_algorithm->set_parallelization_power(save);
	w.write((char*)flag, block_size);
}

void FileCryptor::encrypt_file(const std::string& path_to_file) {
	std::ifstream reader(path_to_file, std::ifstream::in | std::ifstream::binary);
	if (!reader.is_open()) {
		throw std::runtime_error("Didn't manage to open the file.");
	}
	std::ofstream writer(path_to_file + ".enc", std::ofstream::out | std::ofstream::binary);
	const auto block_length = _crypting_algorithm->get_block_length() * _crypting_algorithm->get_parallelization_power();
	bool end_file = false;
	short count;
	_write_flag(writer);
	while (!end_file) {
		reader.read(reinterpret_cast<char*>(_block.get()), block_length);
		count = static_cast<short>(reader.gcount());
		if (count < block_length) {
			for (size_t i = count; i < block_length; i++) {
				_block[i] = 0;
			}
			end_file = true;
		}
		_crypting_algorithm->encrypt(_block.get());
		writer.write(reinterpret_cast<char*>(_block.get()), block_length);
		if (end_file) {
			writer.write(reinterpret_cast<char*>(&count), 1);
		}
	}
	_crypting_algorithm->reset();
	reader.close();
	writer.close();
	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}

void FileCryptor::decrypt_file(const std::string& path_to_file) {
	if (path_to_file.find(".enc", path_to_file.size() - 4) == (size_t)-1) {  //An exception thrown when filename doesn't end with '.enc'.
		throw std::runtime_error(("File " + path_to_file + " hasn't been crypted.").c_str());
	}
	std::ifstream reader(path_to_file, std::ifstream::binary | std::ifstream::in);  //Else - opening encrypted file in reading mode.
	if (!reader.is_open()) {  //Throw an exception if file isn't opened.
		throw std::runtime_error("Didn't manage to open the file.");
	}
	try {  //Reading flag, written while encryption. If we manage to decrypt it, then we decrypt the rest of the file WITHOUT this flag.
		_read_flag(reader);
	} catch (const std::exception& ex) {  //Closing file if we didn't manage to decrypt the flag.
		reader.close();
		throw ex;
	}
	std::ofstream writer(path_to_file.substr(0, path_to_file.size() - 4), std::ofstream::binary | std::ofstream::out);
	const auto block_length = _crypting_algorithm->get_block_length() * _crypting_algorithm->get_parallelization_power();
	uint8_t check[2];
	while (true) {
		reader.read(reinterpret_cast<char*>(_block.get()), block_length);
		_crypting_algorithm->decrypt(_block.get());
		reader.read(reinterpret_cast<char*>(check), 2);
		if (reader.gcount() == 1) {
			writer.write(reinterpret_cast<char*>(_block.get()), check[0]);
			break;
		} else {
			writer.write(reinterpret_cast<char*>(_block.get()), block_length);
		}
		reader.seekg(reader.tellg().operator-(2));
	}
	_crypting_algorithm->reset();
	reader.close();
	writer.close();
	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}
