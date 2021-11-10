#pragma once
#include <string>

class PasswordEqualizer final {
private:
	std::string _logic(const char* key, const int desired_size);
public:
	std::string normalize_key_to_appropriate_length(const char* key, int desired_size);
};

