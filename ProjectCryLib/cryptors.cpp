#include <stdexcept>
#include <cstring>
#include "cryptors.hpp"
#include "Auxilary.hpp"

using namespace ProjectCry;

#pragma region EcbCryptor
EcbCryptor::EcbCryptor(std::unique_ptr<ICore>&& algo) {
	_algo = std::move(algo);
}

EcbCryptor::EcbCryptor(EcbCryptor&& aesEcbCryptor) noexcept {
	_algo = std::move(aesEcbCryptor._algo);
}

auto EcbCryptor::encrypt(uint8_t* block) -> void {
	_algo->cry_round(block);
}

auto EcbCryptor::decrypt(uint8_t* block) -> void {
	_algo->inv_cry_round(block);
}

auto EcbCryptor::reset() -> void {
	return;
}
#pragma endregion //EcbCryptor

#pragma region CbcCryptor
CbcCryptor::CbcCryptor(std::unique_ptr<ICore>&& algo) {
	_algo = std::move(algo);
}

CbcCryptor::CbcCryptor(CbcCryptor&& CbcCryptor) noexcept {
	_algo = std::move(CbcCryptor._algo);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(CbcCryptor._init_vec),
				get_block_length());
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(CbcCryptor._save_init_vec),
				get_block_length());
}

auto CbcCryptor::encrypt(uint8_t* block) -> void {
	ProjectCryAuxilary::xor_blocks(block, _init_vec, get_block_length());
	_algo->cry_round(block);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(block),
				get_block_length());
}

auto CbcCryptor::decrypt(uint8_t* block) -> void {
	uint8_t buf[16];
	std::memcpy(reinterpret_cast<void*>(buf),
				reinterpret_cast<const void*>(block),
				get_block_length());
	_algo->inv_cry_round(block);
	ProjectCryAuxilary::xor_blocks(block, _init_vec, get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(buf),
				get_block_length());
}

auto CbcCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				get_block_length());
}

auto CbcCryptor::set_init_vec(uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(init_vec),
				get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				get_block_length());
}
#pragma endregion //CbcCryptor

#pragma region CfbCryptor
CfbCryptor::CfbCryptor(std::unique_ptr<ICore>&& algo) {
	_algo = std::move(algo);
}

CfbCryptor::CfbCryptor(CfbCryptor&& CfbCryptor) noexcept {
	_algo = std::move(CfbCryptor._algo);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(CfbCryptor._init_vec),
				get_block_length());
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(CfbCryptor._save_init_vec),
				get_block_length());
}

auto CfbCryptor::encrypt(uint8_t* block) -> void {
	_algo->cry_round(_init_vec);
	ProjectCryAuxilary::xor_blocks(block, _init_vec, get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(block),
				get_block_length());
}

auto CfbCryptor::decrypt(uint8_t* block) -> void {
	uint8_t buf[16];
	memcpy(buf, block, get_block_length());
	_algo->cry_round(_init_vec);
	ProjectCryAuxilary::xor_blocks(block, _init_vec, get_block_length());
	memcpy(_init_vec, buf, get_block_length());
}

auto CfbCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				get_block_length());
}

auto CfbCryptor::set_init_vec(uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(init_vec),
				get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				get_block_length());
}
#pragma endregion //CfbCryptor

#pragma region OfbCryptor
OfbCryptor::OfbCryptor(std::unique_ptr<ICore>&& algo) {
	_algo = std::move(algo);
}

OfbCryptor::OfbCryptor(OfbCryptor&& ofbCryptor) noexcept {
	_algo = std::move(ofbCryptor._algo);
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(ofbCryptor._init_vec),
				get_block_length());
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(ofbCryptor._save_init_vec),
				get_block_length());
}

auto OfbCryptor::encrypt(uint8_t* block) -> void {
	_algo->cry_round(_init_vec);
	ProjectCryAuxilary::xor_blocks(block, _init_vec, get_block_length());
}

auto OfbCryptor::decrypt(uint8_t* block) -> void {
	_algo->cry_round(_init_vec);
	ProjectCryAuxilary::xor_blocks(block, _init_vec, get_block_length());
}

auto OfbCryptor::reset() -> void {
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				get_block_length());
}

auto OfbCryptor::set_init_vec(uint8_t* init_vec) -> void {
	std::memcpy(reinterpret_cast<void*>(_save_init_vec),
				reinterpret_cast<const void*>(init_vec),
				get_block_length());
	std::memcpy(reinterpret_cast<void*>(_init_vec),
				reinterpret_cast<const void*>(_save_init_vec),
				get_block_length());
}
#pragma endregion //OfbCryptor

#pragma region CtrCryptor
CtrCryptor::CtrCryptor(std::unique_ptr<ICore>&& algo) {
	_algo = std::move(algo);
}

CtrCryptor::CtrCryptor(CtrCryptor&& ctrCryptor) noexcept {
	_algo = std::move(ctrCryptor._algo);
	std::memcpy(reinterpret_cast<void*>(static_cast<uint8_t*>(_counter)),
				reinterpret_cast<const void*>(static_cast<uint8_t*>(ctrCryptor._counter)),
				get_block_length());
}

auto CtrCryptor::encrypt(uint8_t* block) -> void {
	uint8_t round_c[16];
	std::memcpy(reinterpret_cast<void*>(round_c),
				reinterpret_cast<const void*>(static_cast<uint8_t*>(_counter)),
				get_block_length());
	_algo->cry_round(round_c);
	ProjectCryAuxilary::xor_blocks(block, round_c, get_block_length());
	++_counter;
}

auto CtrCryptor::decrypt(uint8_t* block) -> void {
	uint8_t round_c[16];
	std::memcpy(reinterpret_cast<void*>(round_c),
				reinterpret_cast<const void*>(static_cast<uint8_t*>(_counter)),
				get_block_length());
	_algo->cry_round(round_c);
	ProjectCryAuxilary::xor_blocks(block, round_c, get_block_length());
	++_counter;
}

auto CtrCryptor::reset() -> void {
	_counter.null();
}

auto CtrCryptor::set_init_vec(uint8_t* init_vec) -> void {
	UNREFERENCED_PARAMETER(init_vec);
	return;
}
#pragma endregion //CtrCryptor