#include "ICryptor.hpp"

using namespace ProjectCry;

auto ICryptor::get_block_length() -> size_t {
	return _algo->get_block_length();
}
