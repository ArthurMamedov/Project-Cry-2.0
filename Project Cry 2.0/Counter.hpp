#pragma once
#include <stdint.h>
#include <limits.h>

class Counter final {
private:
	unsigned long long _data[2];
public:
	Counter();
	Counter(const Counter& counter);
	Counter(Counter&& counter) noexcept;

	explicit operator uint8_t* ();
	
	Counter& operator ++();
	Counter operator+(unsigned long long num);
	Counter& operator+=(unsigned long long num);
	
	auto null() -> void;
};

