#pragma once
#include <memory>
#include <string>
#include "i_cryptor.hpp"

class FileCryptor final {
private:
	std::unique_ptr<ICryptor> _crypting_algorithm;
	std::unique_ptr<uint8_t[]> _block;
	auto _read_flag(std::ifstream& r)											-> void;
	auto _write_flag(std::ofstream& w)											-> void;
public:
	bool in_place;

	FileCryptor();
	FileCryptor(std::unique_ptr<ICryptor>&& cryptor) noexcept;
	FileCryptor(FileCryptor&& fileCryptor) noexcept;
	~FileCryptor() = default;

	auto set_crypting_algorithm(std::unique_ptr<ICryptor>&& cryptor) noexcept	-> void;
	auto encrypt_file(const std::string& path_to_file)							-> void;
	auto decrypt_file(const std::string& path_to_file)							-> void;
};

