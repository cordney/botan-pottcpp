#include <botan/ecdsa.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>

#include <cstdint>

int main()
{
	// sign and verify with ECDSA
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("brainpool512r1"));

	Botan::secure_vector<uint8_t> in { 0x01, 0x02, 0x03 };
	Botan::PK_Signer signer(key, "EMSA1(SHA-256)", Botan::IEEE_1363);
	std::vector<uint8_t> sig = signer.sign_message(in, rng);

	Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)", Botan::IEEE_1363);
	bool ok = verifier.verify_message(in, sig);

	return ok;
}
