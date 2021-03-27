#include "Auxilary.hpp"

using namespace ProjectCryAuxilary;

Counter::Counter() {
	_data[0] = 0;
	_data[1] = 0;
}

Counter::Counter(const Counter& counter) {
	_data[0] = counter._data[0];
	_data[1] = counter._data[1];
}

Counter::Counter(Counter&& counter) noexcept {
	_data[0] = counter._data[0];
	_data[1] = counter._data[1];
}

Counter::operator uint8_t* () {
	return reinterpret_cast<uint8_t*>(_data);
}

Counter& Counter::operator++() {
	if (_data[0] == ULLONG_MAX) {
		++_data[1];
	}
	++_data[0];
	return *this;
}

Counter Counter::operator+(unsigned long long num) {
	Counter counter;
	counter._data[0] = _data[0];
	counter._data[1] = _data[1];
	if (ULLONG_MAX - counter._data[0] < num) {
		++(counter._data[1]);
	}
	counter._data[0] += num;
	return counter;
}

Counter& Counter::operator+=(unsigned long long num) {
	if (ULLONG_MAX - _data[0] < num) {
		_data[1]++;
	}
	_data[0] += num;
	return *this;
}

auto Counter::null() -> void {
	_data[0] = _data[1] = 0;
}

int ProjectCryAuxilary::index(int row, int col, int N) {
	return col + row * N;
}

void ProjectCryAuxilary::xor_blocks(uint8_t* block1, const uint8_t* block2, const int size) {
	for (size_t c = 0; c < size; c++) {
		block1[c] ^= block2[c];
	}
}
