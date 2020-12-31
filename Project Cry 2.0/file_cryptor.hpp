#pragma once
#include <memory>
#include <string>
#include "ICryptor.hpp"

class FileCryptor final {
private:
	std::shared_ptr<ICryptor> crypting_algorithm;
	void read_flag(std::ifstream& r);
	void write_flag(std::ofstream& w);
public:
	bool in_place;

	FileCryptor();
	FileCryptor(const std::shared_ptr<ICryptor>& cryptor);
	FileCryptor(const FileCryptor& fileCryptor);
	FileCryptor(FileCryptor&& fileCryptor) noexcept;
	~FileCryptor() = default;

	void set_crypting_algorithm(const std::shared_ptr<ICryptor>& cryptor);
	void encrypt_file(const std::string& path_to_file);
	void decrypt_file(const std::string& path_to_file);
};

