#pragma once
#include <cstdint>
#include <functional>
#include "i_cryptor.hpp"
#include "Counter.hpp"

//Groundwork for the future.
/*enum class EncryptionMode : uint8_t {
	ECB,
	CBC,
	CFB,
	OFB,
	CTR
};

class Cryptor final {
private:
	unsigned int _paral_power;
	EncryptionMode _encryption_mode;
	std::unique_ptr<uint8_t> _init_vec;
	std::unique_ptr<uint8_t> _save_init_vec;
	std::unique_ptr<ICore> _cryptor;
	std::function<void(uint8_t*)> _encrypt;
	std::function<void(uint8_t*)> _decrypt;

	auto _encrypt_ecb(uint8_t* block)										-> void;
	auto _encrypt_cbc(uint8_t* block)										-> void;
	auto _encrypt_cfb(uint8_t* block)										-> void;
	auto _encrypt_ofb(uint8_t* block)										-> void;
	auto _encrypt_ctr(uint8_t* block)										-> void;
	auto _decrypt_ecb(uint8_t* block)										-> void;
	auto _decrypt_cbc(uint8_t* block)										-> void;
	auto _decrypt_cfb(uint8_t* block)										-> void;
	auto _decrypt_ofb(uint8_t* block)										-> void;
	auto _decrypt_ctr(uint8_t* block)										-> void;
	auto _xor_blocks(uint8_t* block1, const uint8_t* block2)	-> void;

public:
	Cryptor();
	Cryptor(std::unique_ptr<ICore> cryptor, const unsigned int paral_power = 1, const char* init_vec = nullptr);
	Cryptor(Cryptor&& cryptor);
	Cryptor(const Cryptor& cryptor);
	~Cryptor();

	auto encrypt(uint8_t* block) -> void;
	auto decrypt(uint8_t* block) -> void;
	auto get_parallelization_power() const -> unsigned int;
	auto set_parallelization_power(const unsigned int paral_power) -> void;
	auto get_block_length() const -> unsigned int;
	auto set_initialization_vector(const uint8_t* init_vec) -> void;
	auto get_initializatoin_vector() -> const uint8_t*;
	auto set_encryption_mode(EncryptionMode encryption_mode) -> void;
	auto get_encryption_mode() -> EncryptionMode;
};*/

class EcbCryptor final : public ICryptor {
public:
	EcbCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power = 1);
	EcbCryptor(EcbCryptor&& aesEcbCryptor) noexcept;

	auto encrypt(uint8_t* block)								-> void override;
	auto decrypt(uint8_t* block)								-> void override;
	auto reset()												-> void override;
	auto set_parallelization_power(unsigned int parallelization_power)	-> void override;
	~EcbCryptor() = default;
};

class CbcCryptor final : public ICryptor {
private:
	std::unique_ptr<uint8_t[]> _init_vec;
	std::unique_ptr<uint8_t[]> _save_init_vec;
public:
	CbcCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power = 1);
	CbcCryptor(CbcCryptor&& CbcCryptor) noexcept;

	auto set_parallelization_power(unsigned int parallelization_power)		-> void override;
	auto encrypt(uint8_t* block)																-> void override;
	auto decrypt(uint8_t* block)																-> void override;
	auto reset()																							-> void override;
	auto set_init_vec(const uint8_t* init_vec)											-> void;
	
	~CbcCryptor() = default;
};

class CfbCryptor final : public ICryptor {
private:
	std::unique_ptr<uint8_t[]> _init_vec;
	std::unique_ptr<uint8_t[]> _save_init_vec;
public:
	CfbCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power = 1);
	CfbCryptor(CfbCryptor&& CfbCryptor) noexcept;
	
	auto set_parallelization_power(unsigned int parallelization_power)		-> void override;
	auto encrypt(uint8_t* block)																-> void override;
	auto decrypt(uint8_t* block)																-> void override;
	auto reset()																							-> void override;
	auto set_init_vec(const uint8_t* init_vec)											-> void;

	~CfbCryptor() = default;
};

class OfbCryptor final : public ICryptor {
private:
	std::unique_ptr<uint8_t[]> _init_vec;
	std::unique_ptr<uint8_t[]> _save_init_vec;
public:
	OfbCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power = 1);
	OfbCryptor(OfbCryptor&& ofbCryptor) noexcept;

	auto set_parallelization_power(unsigned int parallelization_power)		-> void override;
	auto encrypt(uint8_t* block)																-> void override;
	auto decrypt(uint8_t* block)																-> void override;
	auto reset()																							-> void override;
	auto set_init_vec(const uint8_t* init_vec)											-> void;
};

class CtrCryptor final : public ICryptor {
private:
	Counter _counter;

public:
	CtrCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power = 1);
	CtrCryptor(CtrCryptor&& ctrCryptor) noexcept;
	auto set_parallelization_power(unsigned int parallelization_power)		-> void override;
	auto encrypt(uint8_t* block)																-> void override;
	auto decrypt(uint8_t* block)																-> void override;
	auto reset()																							-> void override;

	~CtrCryptor() = default;
};
