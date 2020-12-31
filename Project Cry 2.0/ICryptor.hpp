#pragma once
#include <cstdint>

class ICryptor {
public:
	/// <summary>
	/// Sets the key for encryption algorithm.
	/// </summary>
	/// <param name="key"> - encryption/decryption key.</param>
	virtual auto set_key(const char* key) -> void = 0;

	/// <summary>
	/// Encrypts the block of data.
	/// </summary>
	/// <param name="block">- the block of raw data.</param>
	virtual auto encrypt(uint8_t* block) -> void = 0;

	/// <summary>
	/// Decrypts the block of encrypted data.
	/// </summary>
	/// <param name="block">- block of ecnrypted data.</param>
	virtual auto decrypt(uint8_t* block) -> void = 0;

	virtual auto reset() -> void = 0;

	virtual ~ICryptor() = default;
};