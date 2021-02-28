#pragma once
#include <cstdint>
#include <cstring>
#include <climits>
#include "ICryptor.hpp"

class EcbCryptor final : public ICryptor {
public:
	EcbCryptor(std::unique_ptr<ICore>&& algo);
	EcbCryptor(EcbCryptor&& aesEcbCryptor) noexcept;

	virtual auto encrypt(uint8_t* block)							-> void override;
	virtual auto decrypt(uint8_t* block)							-> void override;
	virtual auto reset()											-> void override;
	
	~EcbCryptor() = default;
};

class CbcCryptor final : public ICryptor {
private:
	uint8_t _save_init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t _init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
public:
	CbcCryptor(std::unique_ptr<ICore>&& algo);
	CbcCryptor(CbcCryptor&& CbcCryptor) noexcept;

	virtual auto encrypt(uint8_t* block)							-> void override;
	virtual auto decrypt(uint8_t* block)							-> void override;
	virtual auto reset()											-> void override;
			auto set_init_vec(uint8_t* init_vec)					-> void;
	
	~CbcCryptor() = default;
};

class CfbCryptor final : public ICryptor {
private:
	uint8_t _save_init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t _init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
public:
	CfbCryptor(std::unique_ptr<ICore>&& algo);
	CfbCryptor(CfbCryptor&& CfbCryptor) noexcept;
	
	virtual auto encrypt(uint8_t* block)							-> void override;
	virtual auto decrypt(uint8_t* block)							-> void override;
	virtual auto reset()											-> void override;
			auto set_init_vec(uint8_t* init_vec)					-> void;

	~CfbCryptor() = default;
};

class OfbCryptor final : public ICryptor {
private:
	uint8_t _save_init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t _init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
public:
	OfbCryptor(std::unique_ptr<ICore>&& algo);
	OfbCryptor(OfbCryptor&& ofbCryptor) noexcept;

	virtual auto encrypt(uint8_t* block)							-> void override;
	virtual auto decrypt(uint8_t* block)							-> void override;
	virtual auto reset()											-> void override;
			auto set_init_vec(uint8_t* init_vec)					-> void;
};

class CtrCryptor final : public ICryptor {
private:
	class uint128_t final {
	private:
		uint64_t _data[2];
	public:
		uint128_t() {
			_data[1] = 0;
			_data[0] = 0;
		}
		uint128_t operator++() {
			if (_data[1] == ULLONG_MAX) {
				_data[0] += 1;
			}
			_data[1] += 1;
			return *this;
		}
		uint128_t(const uint128_t& uint128) {
			std::memcpy(reinterpret_cast<void*>(_data),
						reinterpret_cast<const void*>(uint128._data),
						16);
		}
		uint128_t& operator =(const uint128_t& uint128) {
			std::memcpy(reinterpret_cast<void*>(_data),
						reinterpret_cast<const void*>(uint128._data),
						16);
			return *this;
		}
		operator uint8_t* () {
			return reinterpret_cast<uint8_t*>(_data);
		}
		void null() {
			_data[0] = 0;
			_data[1] = 0;
		}
	};
	uint128_t _counter;
public:
	CtrCryptor(std::unique_ptr<ICore>&& algo);
	CtrCryptor(CtrCryptor&& ctrCryptor) noexcept;
	
	virtual auto encrypt(uint8_t* block)							-> void override;
	virtual auto decrypt(uint8_t* block)							-> void override;
	virtual auto reset()											-> void override;
			auto set_init_vec(uint8_t* init_vec)					-> void;

	~CtrCryptor() = default;
};
