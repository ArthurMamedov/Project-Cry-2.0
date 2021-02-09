#include <future>
#include <iostream>
#include <array>
#include <stdexcept>
#include <cstring>
#include "cryptors.hpp"

#pragma region EcbCryptor
EcbCryptor::EcbCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power) {
	_algo = std::move(algo);
	_parallelization_power = parallelization_power;
}

EcbCryptor::EcbCryptor(EcbCryptor&& ecbCryptor) noexcept {
	_algo = std::move(ecbCryptor._algo);
	_parallelization_power = ecbCryptor._parallelization_power;
}

auto EcbCryptor::encrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	const auto number = _parallelization_power > 10 ? 10 : _parallelization_power;
	for (size_t c = 0; c < number; c++) {
		f[c] = std::async(std::launch::async, [this, &block, c]() {_algo->cry_round(&block[c * get_block_length()]); });
	}
}

auto EcbCryptor::decrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	const auto number = _parallelization_power > 10 ? 10 : _parallelization_power;
	for (size_t c = 0; c < number; c++) {
		f[c] = std::async(std::launch::async, [this, &block, c]() {_algo->inv_cry_round(&block[c * get_block_length()]); });
	}
}

auto EcbCryptor::reset() -> void {
	return;
}

auto EcbCryptor::set_parallelization_power(unsigned int parallelization_power) -> void {
	_parallelization_power = parallelization_power;
}
#pragma endregion //EcbCryptor

#pragma region CbcCryptor
CbcCryptor::CbcCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power) {
	_algo = std::move(algo);  //Moving encryption algorithm (ICore).
	_parallelization_power = parallelization_power;
	const auto NUMBER = _parallelization_power * get_block_length();
	_save_init_vec.reset(new uint8_t[get_block_length()]);  //Memory allocation for initialization vector and its starting point.
	_init_vec.reset(new uint8_t[NUMBER]);
	for (size_t c = 0; c < get_block_length(); c++) {
		_save_init_vec[c] = 0;
		_init_vec[c] = 0;
	}
}

CbcCryptor::CbcCryptor(CbcCryptor&& cbcCryptor) noexcept {
	_algo = std::move(cbcCryptor._algo);
	_parallelization_power = cbcCryptor._parallelization_power;
	_init_vec = std::move(cbcCryptor._init_vec);
	_save_init_vec = std::move(cbcCryptor._save_init_vec);
}

auto CbcCryptor::set_parallelization_power(unsigned int parallelization_power) -> void {
	_parallelization_power = parallelization_power;
	const auto NUMBER = _parallelization_power * get_block_length();
	std::unique_ptr<uint8_t[]> init_vec(new uint8_t[NUMBER]);
	std::memcpy(reinterpret_cast<void*>(init_vec.get()), reinterpret_cast<const void*>(_init_vec.get()), get_block_length());
	_init_vec = std::move(init_vec);
	/*for (size_t c = 0; c < get_block_length(); c++) {
		init_vec[c] = _init_vec[c];
	}*/
}

auto CbcCryptor::encrypt(uint8_t* block) -> void {
	const auto PP = get_parallelization_power();
	const auto LEN = get_block_length();
	for (size_t c = 0; c < PP; c++) {
		_xor_blocks(&block[c * LEN], _init_vec.get());
		_algo->cry_round(&block[c * LEN]);
		std::memcpy(reinterpret_cast<void*>(_init_vec.get()), reinterpret_cast<const void*>(&block[c * LEN]), 16);
	}
}

auto CbcCryptor::decrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	const auto PP = get_parallelization_power();
	const auto LEN = get_block_length();
	uint8_t buf[16];  //TODO: replace this later. The length of the block may not be 16, but for now it will not be greater than 16.
	std::memcpy(buf, &block[(PP - 1) * LEN], LEN);
	auto init_vec = _init_vec.get();
	std::memcpy(&init_vec[LEN], block, LEN * (PP-1));
	for (size_t c = 0; c < PP; c++) {
		f[c] = std::async(std::launch::async, [&block, this, &init_vec, c, LEN]() {
			_algo->inv_cry_round(&block[c * LEN]);
			_xor_blocks(&block[c * LEN], &init_vec[c * LEN]);
		});
	}
	for (size_t c = 0; c < PP; c++) {
		f[c].get();
	}
	std::memcpy(init_vec, buf, LEN);
}

auto CbcCryptor::reset() -> void {
	for (size_t c = 0; c < get_block_length(); c++) {
		_init_vec[c] = _save_init_vec[c];
	}
	for (size_t c = get_block_length(); c < get_block_length() * get_parallelization_power(); c++) {
		_init_vec[c] = 0;
	}
}

auto CbcCryptor::set_init_vec(const uint8_t* init_vec) -> void {  //TODO: replace "const uint8_t*" with "const char*".
	std::memcpy(reinterpret_cast<void*>(_save_init_vec.get()), reinterpret_cast<const void*>(init_vec), get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()), reinterpret_cast<const void*>(_save_init_vec.get()), get_block_length());
}
#pragma endregion //CbcCryptor

#pragma region CfbCryptor
CfbCryptor::CfbCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power) {
	_algo = std::move(algo);
	_parallelization_power = parallelization_power;
	_init_vec.reset(new uint8_t[_parallelization_power * get_block_length()]);
	_save_init_vec.reset(new uint8_t[get_block_length()]);
	for (size_t c = 0; c < get_block_length(); c++) {
		_init_vec[c] = 0;
		_save_init_vec[c] = 0;
	}
}

CfbCryptor::CfbCryptor(CfbCryptor&& cfbCryptor) noexcept {
	_algo = std::move(cfbCryptor._algo);
	_parallelization_power = cfbCryptor._parallelization_power;
	_init_vec = std::move(cfbCryptor._init_vec);
	_save_init_vec = std::move(cfbCryptor._save_init_vec);
}

auto CfbCryptor::set_parallelization_power(unsigned int parallelization_power) -> void {
	_parallelization_power = parallelization_power;
	const auto BLOCK_LENGTH = get_block_length();
	std::unique_ptr<uint8_t[]> init_vec(new uint8_t[BLOCK_LENGTH * _parallelization_power]);
	std::memcpy(reinterpret_cast<void*>(init_vec.get()), reinterpret_cast<const void*>(_init_vec.get()), BLOCK_LENGTH);
	_init_vec = std::move(init_vec);
}

auto CfbCryptor::encrypt(uint8_t* block) -> void {
	uint8_t* init_vec = _init_vec.get();
	const auto PARAL_POWER = get_parallelization_power();
	const auto BLOCK_LENGTH = get_block_length();
	for (size_t c = 0; c < PARAL_POWER; c++) {
		_algo->cry_round(init_vec);
		_xor_blocks(&block[c * BLOCK_LENGTH], init_vec);
		std::memcpy(reinterpret_cast<void*>(init_vec), reinterpret_cast<const void*>(&block[c * BLOCK_LENGTH]), BLOCK_LENGTH);
	}
}

auto CfbCryptor::decrypt(uint8_t* block) -> void {
	uint8_t buf[16];  //TODO: problem code: STATIC16
	std::future<void> f[10];
	const auto PARAL_POWER = get_parallelization_power();
	const auto BLOCK_LENGTH = get_block_length();
	uint8_t* init_vec = _init_vec.get();
	std::memcpy(reinterpret_cast<void*>(buf), reinterpret_cast<const void*>(&block[(PARAL_POWER-1) * BLOCK_LENGTH]), BLOCK_LENGTH);
	std::memcpy(reinterpret_cast<void*>(&init_vec[BLOCK_LENGTH]), reinterpret_cast<const void*>(block), (PARAL_POWER - 1) * BLOCK_LENGTH);
	for (size_t c = 0; c < PARAL_POWER; c++) {
		f[c] = std::async(std::launch::async, [this, &init_vec, &block, c, BLOCK_LENGTH]() {
			_algo->cry_round(&init_vec[c*BLOCK_LENGTH]);
			_xor_blocks(&block[c*BLOCK_LENGTH], &init_vec[c * BLOCK_LENGTH]);
		});
	}
	for (size_t c = 0; c < PARAL_POWER; c++) {
	f[c].get();
	}
	std::memcpy(init_vec, buf, BLOCK_LENGTH);
}

auto CfbCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()),
				reinterpret_cast<const void*>(_save_init_vec.get()),
				get_block_length());
}

auto CfbCryptor::set_init_vec(const uint8_t* init_vec) -> void {
	const auto LENGTH = get_block_length();
	std::memcpy(reinterpret_cast<void*>(_save_init_vec.get()),
				reinterpret_cast<const void*>(init_vec),
				LENGTH);
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()),
				reinterpret_cast<const void*>(_save_init_vec.get()),
				LENGTH);
}
#pragma endregion //CfbCryptor

#pragma region OfbCryptor
OfbCryptor::OfbCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power) {
	_algo = std::move(algo);
	_parallelization_power = parallelization_power;
	_init_vec.reset(new uint8_t[_parallelization_power * get_block_length()]);
	_save_init_vec.reset(new uint8_t[get_block_length()]);
	for (size_t c = 0; c < get_block_length(); c++) {
		_init_vec[c] = _save_init_vec[c] = 0;
	}
}

OfbCryptor::OfbCryptor(OfbCryptor&& ofbCryptor) noexcept {
	_algo = std::move(ofbCryptor._algo);
	_parallelization_power = ofbCryptor._parallelization_power;
	_init_vec = std::move(ofbCryptor._init_vec);
	_save_init_vec = std::move(ofbCryptor._save_init_vec);
}

auto OfbCryptor::set_parallelization_power(unsigned int parallelization_power) -> void {
	_parallelization_power = parallelization_power;
	const auto BLOCK_LENGTH = get_block_length();
	std::unique_ptr<uint8_t[]> init_vec(new uint8_t[BLOCK_LENGTH * _parallelization_power]);
	std::memcpy(reinterpret_cast<void*>(init_vec.get()), reinterpret_cast<const void*>(_init_vec.get()), BLOCK_LENGTH);
	_init_vec = std::move(init_vec);
}

auto OfbCryptor::encrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	auto init_vec = _init_vec.get();
	const auto BLOCK_LENGTH = get_block_length();
	for (size_t c = 0; c < _parallelization_power; c++) {
		if (c != 0) {
			std::memcpy(&init_vec[(c - 1) * BLOCK_LENGTH], &init_vec[c * BLOCK_LENGTH], BLOCK_LENGTH);
		}
		_algo->cry_round(&init_vec[c * BLOCK_LENGTH]);
	}
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c] = std::async(std::launch::async, [this, &block, &init_vec, c, BLOCK_LENGTH]() {
			_xor_blocks(&block[c * BLOCK_LENGTH], &init_vec[c * BLOCK_LENGTH]);
		});
	}
}

auto OfbCryptor::decrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	auto init_vec = _init_vec.get();
	const auto BLOCK_LENGTH = get_block_length();
	for (size_t c = 0; c < _parallelization_power; c++) {
		if (c != 0) {
			std::memcpy(&init_vec[(c - 1) * BLOCK_LENGTH], &init_vec[c * BLOCK_LENGTH], BLOCK_LENGTH);
		}
		_algo->cry_round(&init_vec[c * BLOCK_LENGTH]);
	}
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c] = std::async(std::launch::async, [this, &block, &init_vec, c, BLOCK_LENGTH]() {
			_xor_blocks(&block[c * BLOCK_LENGTH], &init_vec[c * BLOCK_LENGTH]);
		});
	}
}

auto OfbCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()), reinterpret_cast<const void*>(_save_init_vec.get()), get_block_length());
}

auto OfbCryptor::set_init_vec(const uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec.get()), reinterpret_cast<const void*>(init_vec), get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()), reinterpret_cast<const void*>(_save_init_vec.get()), get_block_length());
}
#pragma endregion //OfbCryptor

#pragma region CtrCryptor
CtrCryptor::CtrCryptor(std::unique_ptr<ICore>&& algo, unsigned int parallelization_power) {
	_algo = std::move(algo);
	_parallelization_power = parallelization_power;
}

CtrCryptor::CtrCryptor(CtrCryptor&& ctrCryptor) noexcept {
	_algo = std::move(ctrCryptor._algo);
	_parallelization_power = ctrCryptor._parallelization_power;
	std::memcpy(reinterpret_cast<void*>(static_cast<uint8_t*>(_counter)),
				reinterpret_cast<const void*>(static_cast<uint8_t*>(ctrCryptor._counter)),
				16);
}

auto CtrCryptor::set_parallelization_power(unsigned int parallelization_power) -> void {
	_parallelization_power = parallelization_power;
}

auto CtrCryptor::encrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	const auto BLOCK_LENGTH = get_block_length();
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c] = std::async(std::launch::async, [this, &block, c, BLOCK_LENGTH]() {
			uint8_t tmp[16];
			Counter counter = _counter + c;
			std::memcpy(tmp, reinterpret_cast<const void*>(static_cast<uint8_t*>(counter)), BLOCK_LENGTH);
			_algo->cry_round(tmp);
			_xor_blocks(&block[c * BLOCK_LENGTH], tmp);
		});
	}
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c].get();
	}
	_counter += _parallelization_power;
}

auto CtrCryptor::decrypt(uint8_t* block) -> void {
	std::future<void> f[10];
	const auto BLOCK_LENGTH = get_block_length();
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c] = std::async(std::launch::async, [this, &block, c, BLOCK_LENGTH]() {
			uint8_t tmp[16];
			Counter counter = _counter + c;
			std::memcpy(tmp, reinterpret_cast<const void*>(static_cast<uint8_t*>(counter)), BLOCK_LENGTH);
			_algo->cry_round(tmp);
			_xor_blocks(&block[c * BLOCK_LENGTH], tmp);
		});
	}
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c].get();
	}
	_counter += _parallelization_power;
	/*std::future<void> f[10];
	const auto BLOCK_LENGTH = get_block_length();
	for (size_t c = 0; c < _parallelization_power; c++) {
		f[c] = std::async(std::launch::async, [this, &block, c, BLOCK_LENGTH]() {
			uint8_t tmp[16];
			std::memcpy(tmp, reinterpret_cast<const void*>(static_cast<uint8_t*>(_counter + c)), get_block_length());
			for (size_t i = 0; i < 16; i++) {
				std::cout << (int)tmp[c];
			} std::cout << std::endl;
			_algo->cry_round(tmp);
			_xor_blocks(&block[c * BLOCK_LENGTH], tmp);
		});
	}
	_counter += _parallelization_power;*/
}

auto CtrCryptor::reset() -> void {
	_counter.null();
}
#pragma endregion //CtrCryptor

#pragma region Cryptor
auto Cryptor::_encrypt_ecb(uint8_t* block) -> void {
}

auto Cryptor::_encrypt_cbc(uint8_t* block) -> void {
}

auto Cryptor::_encrypt_cfb(uint8_t* block) -> void {
}

auto Cryptor::_encrypt_ofb(uint8_t* block) -> void {
}

auto Cryptor::_encrypt_ctr(uint8_t* block) -> void {
}

auto Cryptor::_decrypt_ecb(uint8_t* block) -> void {
}

auto Cryptor::_decrypt_cbc(uint8_t* block) -> void {
}

auto Cryptor::_decrypt_cfb(uint8_t* block) -> void {
}

auto Cryptor::_decrypt_ofb(uint8_t* block) -> void {
}

auto Cryptor::_decrypt_ctr(uint8_t* block) -> void {
}

auto Cryptor::_xor_blocks(uint8_t* block1, const uint8_t* block2) -> void {
}

auto Cryptor::_inc_init_vec(const uint64_t component) -> void {
}

Cryptor::Cryptor() {
}

Cryptor::Cryptor(std::unique_ptr<ICore> cryptor, const unsigned int paral_power, const char* init_vec) {
}

Cryptor::Cryptor(Cryptor&& cryptor) {
}

Cryptor::Cryptor(const Cryptor& cryptor) {
}

Cryptor::~Cryptor() {
}

auto Cryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()),
				reinterpret_cast<const void*>(_save_init_vec.get()),
				get_block_length());
}

auto Cryptor::encrypt(uint8_t* block) -> void {
	_encrypt(block);
}

auto Cryptor::decrypt(uint8_t* block) -> void {
	_decrypt(block);
}

auto Cryptor::get_parallelization_power() const -> unsigned int {
	return _paral_power;
}

auto Cryptor::set_parallelization_power(const unsigned int paral_power) -> void {
	if (_encryption_mode != EncryptionMode::CTR) {
		_paral_power = paral_power;
		const auto BLOCK_LENGTH = get_block_length();
		std::unique_ptr<uint8_t[]> init_vec(new uint8_t[BLOCK_LENGTH * _paral_power]);
		std::memcpy(reinterpret_cast<void*>(init_vec.get()),
					reinterpret_cast<const void*>(_init_vec.get()),
					BLOCK_LENGTH);
		_init_vec = std::move(init_vec);
	}
}

auto Cryptor::get_block_length() const -> unsigned int {
	return _cryptor->get_block_length();
}

auto Cryptor::set_initialization_vector(const uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec.get()), reinterpret_cast<const void*>(init_vec), get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec.get()), reinterpret_cast<const void*>(init_vec), get_block_length());
}

auto Cryptor::get_initializatoin_vector() -> const uint8_t* {
	return _save_init_vec.get();
}

auto Cryptor::set_encryption_mode(EncryptionMode encryption_mode) -> void {
	_encryption_mode = encryption_mode;
	size_t init_vec_length = _paral_power * get_block_length();
	switch (_encryption_mode) {
		case EncryptionMode::ECB:
			_encrypt = [this](uint8_t* block) {	_encrypt_ecb(block); };
			_decrypt = [this](uint8_t* block) { _decrypt_ecb(block); };
			break;
		case EncryptionMode::CBC:
			_encrypt = [this](uint8_t* block) {	_encrypt_cbc(block); };
			_decrypt = [this](uint8_t* block) { _decrypt_cbc(block); };
			break;
		case EncryptionMode::CFB:
			_encrypt = [this](uint8_t* block) {	_encrypt_cfb(block); };
			_decrypt = [this](uint8_t* block) { _decrypt_cfb(block); };
			break;
		case EncryptionMode::OFB:
			_encrypt = [this](uint8_t* block) {	_encrypt_ofb(block); };
			_decrypt = [this](uint8_t* block) { _decrypt_ofb(block); };
			break;
		case EncryptionMode::CTR:
			_encrypt = [this](uint8_t* block) {	_encrypt_ctr(block); };
			_decrypt = [this](uint8_t* block) { _decrypt_ctr(block); };
			std::unique_ptr<uint8_t[]> init_vec(new uint8_t[get_block_length()]);
			init_vec_length = get_block_length();
			break;
	}
	reset();
}

auto Cryptor::get_encryption_mode() -> EncryptionMode {
	return _encryption_mode;
}
#pragma endregion
