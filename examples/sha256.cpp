#include <botan/hash.h>
#include <botan/hex.h>

#include <memory>
#include <cstdint>
#include <iostream>

int main()
{
	// hash a message with SHA-256
	std::unique_ptr<Botan::HashFunction> sha256(Botan::HashFunction::create("SHA-256"));
	sha256->update("123");
	sha256->update("456");
	Botan::secure_vector<uint8_t> digest = sha256->final();

	std::cout << Botan::hex_encode(digest) << std::endl;

	return 0;
}