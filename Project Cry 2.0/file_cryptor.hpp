#pragma once
#include <memory>
#include <string>
#include "ICryptor.hpp"

class FileCryptor final {
private:
	std::unique_ptr<ICryptor> crypting_algorithm;
	void read_flag(std::ifstream& r);
	void write_flag(std::ofstream& w);
public:
	bool in_place;

	FileCryptor();
	FileCryptor(std::unique_ptr<ICryptor>&& cryptor) noexcept;
	FileCryptor(FileCryptor&& fileCryptor) noexcept;
	~FileCryptor() = default;

	void set_crypting_algorithm(std::unique_ptr<ICryptor>&& cryptor) noexcept;
	void encrypt_file(const std::string& path_to_file);
	void decrypt_file(const std::string& path_to_file);
};

