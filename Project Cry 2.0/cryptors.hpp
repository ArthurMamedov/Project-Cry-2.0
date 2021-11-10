#pragma once
#include <cstdint>
#include <cstring>
#include <climits>
#include "ICryptor.hpp"
#include "Counter.hpp"

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

	virtual void encrypt(uint8_t* block) override;
	virtual void decrypt(uint8_t* block) override;
	virtual void reset() override;
	        void set_init_vec(uint8_t* init_vec);
	
	~CbcCryptor() = default;
};

class CfbCryptor final : public ICryptor {
private:
	uint8_t _save_init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t _init_vec[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
public:
	CfbCryptor(std::unique_ptr<ICore>&& algo);
	CfbCryptor(CfbCryptor&& CfbCryptor) noexcept;
	
	virtual void encrypt(uint8_t* block) override;
	virtual void decrypt(uint8_t* block) override;
	virtual void reset() override;
			void set_init_vec(uint8_t* init_vec);

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
	Counter _counter;

public:
	CtrCryptor(std::unique_ptr<ICore>&& algo);
	CtrCryptor(CtrCryptor&& ctrCryptor) noexcept;
	
	virtual auto encrypt(uint8_t* block)							-> void override;
	virtual auto decrypt(uint8_t* block)							-> void override;
	virtual auto reset()											-> void override;
			auto set_init_vec(uint8_t* init_vec)					-> void;

	~CtrCryptor() = default;
};
