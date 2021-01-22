#include <future>
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
}

OfbCryptor::OfbCryptor(OfbCryptor&& ofbCryptor) noexcept {
	_algo = std::move(ofbCryptor._algo);
	_parallelization_power = ofbCryptor._parallelization_power;
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(ofbCryptor._init_vec),
				16);
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(ofbCryptor._save_init_vec),
				16);
}

auto OfbCryptor::encrypt(uint8_t* block) -> void {
	_algo->cry_round(_init_vec);
	_xor_blocks(block, _init_vec);
}

auto OfbCryptor::decrypt(uint8_t* block) -> void {
	_algo->cry_round(_init_vec);
	_xor_blocks(block, _init_vec);
}

auto OfbCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				16);
}

auto OfbCryptor::set_init_vec(const uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(init_vec),
				16);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				16);
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

auto CtrCryptor::encrypt(uint8_t* block) -> void {
	uint8_t round_c[16];
	std::memcpy(reinterpret_cast<void*>(round_c),
				reinterpret_cast<const void*>(static_cast<uint8_t*>(_counter)),
				16);
	_algo->cry_round(round_c);
	_xor_blocks(block, round_c);
	++_counter;
}

auto CtrCryptor::decrypt(uint8_t* block) -> void {
	uint8_t round_c[16];
	std::memcpy(reinterpret_cast<void*>(round_c),
				reinterpret_cast<const void*>(static_cast<uint8_t*>(_counter)),
				16);
	_algo->cry_round(round_c);
	_xor_blocks(block, round_c);
	++_counter;
}

auto CtrCryptor::reset() -> void {
	_counter.null();
}

auto CtrCryptor::set_init_vec(uint8_t* init_vec) -> void {
	return;
}
#pragma endregion //CtrCryptor
