#include <botan/rsa.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>

#include <iostream>

int main()
{
	// sign and verify using openssl provider
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey key(rng, 2048);

	Botan::secure_vector<Botan::byte> in { 0x01, 0x02, 0x03 };
	Botan::PK_Signer signer(key, "EMSA4(SHA-256)", Botan::IEEE_1363, "openssl");
	std::vector<Botan::byte> sig = signer.sign_message(in, rng);

	Botan::PK_Verifier verifier(key, "EMSA4(SHA-256)", Botan::IEEE_1363, "openssl");
	bool ok = verifier.verify_message(in, sig);

	std::cout << ok << std::endl;
}
