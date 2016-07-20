#include <botan/aead.h>
#include <botan/auto_rng.h>

int main()
{
	// encrypt one block with AES in GCM mode
   std::unique_ptr<Botan::AEAD_Mode> enc(Botan::get_aead("AES-256/GCM", Botan::ENCRYPTION));
   std::unique_ptr<Botan::AEAD_Mode> dec(Botan::get_aead("AES-256/GCM", Botan::DECRYPTION));

	Botan::AutoSeeded_RNG rng;
	Botan::secure_vector<uint8_t> key = rng.random_vec(32);
	Botan::secure_vector<uint8_t> nonce = rng.random_vec(32);

	enc->set_key(key);
	//enc->set_associated_data_vec(ad);
	enc->start(nonce);

	Botan::secure_vector<uint8_t> buf(32, 0xFE);
	Botan::secure_vector<uint8_t> expected(buf.begin(), buf.end());

	enc->finish(buf); // encrypts in-place

	dec->set_key(key);
	dec->start(nonce);

	dec->finish(buf); // decrypts in-place

	return (buf == expected);
}