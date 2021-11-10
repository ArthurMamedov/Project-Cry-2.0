#include <stdexcept>
#include <algorithm>
#include "PasswordEqualizer.hpp"

char bit_shift_char(char to_shift) {
	return (to_shift >> 1) | (to_shift << 7);
}

std::string PasswordEqualizer::_logic(const char* key, const int desired_size) {
	if (key == nullptr) {
		throw std::runtime_error("key is nullptr");
	}

	const int current_size = std::strlen(key);
	
	if (desired_size <= 0) {
		throw std::runtime_error("Desired size is less or equal to 0");
	}
	
	if (current_size == 0) {
		throw std::runtime_error("Current key length is 0");
	}

	if (current_size == desired_size) {
		return std::string(key);
	}

	std::string result(desired_size + 1, '\0');
	if (current_size < desired_size) {
		for (int i = 0; i < result.size()-1; i++) {
			result[i] = i >= current_size? bit_shift_char(key[i % current_size]) : key[i];
		}
	}
	else {
		std::copy(key, key + desired_size, result.begin());
		for (int i = 0; i < current_size / desired_size; i++) {
			for (int j = 0; j < result.size()-1; j++) {
				if (j > current_size) {
					break;
				}
				result[j] += key[desired_size * i + j];
				if (result[j] == 0) {
					result[j] = 1;
				}
			}
		}
	}
	return result;
}

std::string PasswordEqualizer::normalize_key_to_appropriate_length(const char* key, int desired_size) {
	return _logic(key, desired_size);
}
