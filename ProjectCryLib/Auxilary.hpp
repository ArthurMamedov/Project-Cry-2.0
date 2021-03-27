#pragma once
#include <stdint.h>
#include <limits.h>

namespace ProjectCryAuxilary {
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

	extern int index(int row, int col, int N);

	extern void xor_blocks(uint8_t* block1, const uint8_t* block2, const int size);
}