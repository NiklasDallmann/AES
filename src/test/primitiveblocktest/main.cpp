#include <chrono>
#include <iostream>
#include <stdint.h>
#include <stdlib.h>

#include "block.h"
#include "ctr.h"
#include "utilities.h"

#define SUCCESS(text) \
	std::cout << "[\x1B[32mSUCCESS\x1B[0m]	" << text << std::endl;

#define FAIL(text) \
	std::cout << "[\x1B[31mFAIL\x1B[0m]		" << text << std::endl;

#define BENCHMARK(text) \
	std::cout << "[\x1B[34mBENCHMARK\x1B[0m]	" << text << std::endl;

template <typename Function>
void benchmark(Function f, const std::string &tag, size_t numberOfCycles, size_t dataSize = AES_BLOCK_SIZE)
{
	auto startTimePoint = std::chrono::high_resolution_clock::now();
	
	for (size_t cycle = 0; cycle < numberOfCycles; cycle++)
	{
		f();
	}
	
	auto endTimePoint = std::chrono::high_resolution_clock::now();
	auto duration = (endTimePoint - startTimePoint);
	double millisecondsTaken = double(std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
	double millisecondsPerCycle = (millisecondsTaken / double(numberOfCycles));
	double secondsPerCycle = millisecondsPerCycle / double(1000);
	double bandwidth = 0;
	
	bandwidth = (double(dataSize * sizeof (uint32_t)) / double(1000000) / secondsPerCycle);
	
	BENCHMARK(tag << "	" << millisecondsPerCycle << " ms/cycle	" << bandwidth << " MB/s")
}

int main()
{
	auto aes128Test = []()
	{
		uint8_t plaintext[] = {
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
		};
		
		uint8_t key[] {
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
		};
		
		uint8_t expectedCiphertext[] {
			0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
		};
		
		uint8_t ciphertext[sizeof (plaintext)];
		uint8_t decryptedPlaintext[sizeof (plaintext)];
		
		Aes::Key128 keyObj(key);
		Aes::Block128 block(keyObj);
		block.encrypt(plaintext, ciphertext);
		
		if (memcmp(expectedCiphertext, ciphertext, sizeof (expectedCiphertext)) == 0)
		{
			SUCCESS("AES-128 Encryption")
		}
		else
		{
			FAIL("AES-128 Encryption")
			INFO("RESULT")
			printBuffer(ciphertext, AES_BLOCK_SIZE * 4);
			INFO("EXPECTED")
			printBuffer(expectedCiphertext, AES_BLOCK_SIZE * 4);
		}
		
		block.decrypt(ciphertext, decryptedPlaintext);
		
		if (memcmp(plaintext, decryptedPlaintext, sizeof (plaintext)) == 0)
		{
			SUCCESS("AES-128 Decryption")
		}
		else
		{
			FAIL("AES-128 Decryption")
			INFO("RESULT")
			printBuffer(decryptedPlaintext, AES_BLOCK_SIZE * 4);
			INFO("EXPECTED")
			printBuffer(plaintext, AES_BLOCK_SIZE * 4);
		}
		
		benchmark([&block, &plaintext, &ciphertext](){block.encrypt(plaintext, ciphertext);}, "AES-128 Encryption", 10000000);
	};
	
	auto aes128CtrTest = []()
	{
		uint8_t plaintext[] = {
			0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
			0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
			0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
			0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
		};
		
		uint8_t key[] {
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
		};
		
		uint8_t initializationVector[] {
			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff			
		};
		
		uint8_t expectedCiphertext[] {
			0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
			0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
			0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
			0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
		};
		
		uint8_t ciphertext[sizeof (plaintext)];
		uint8_t decryptedPlaintext[sizeof (plaintext)];
		
		Aes::Key128 keyObj(key);
		Aes::Mode::Ctr128::encrypt(keyObj, initializationVector, plaintext, sizeof (plaintext), ciphertext);
		Aes::Mode::Ctr128::decrypt(keyObj, initializationVector, ciphertext, sizeof (ciphertext), decryptedPlaintext);
		
		if (memcmp(expectedCiphertext, ciphertext, sizeof (expectedCiphertext)) == 0)
		{
			SUCCESS("AES-128-CTR Encryption")
		}
		else
		{
			FAIL("AES-128-CTR Encryption")
			INFO("RESULT")
			printBuffer(ciphertext, sizeof (ciphertext));
			INFO("EXPECTED")
			printBuffer(expectedCiphertext, sizeof (expectedCiphertext));
		}
		
		if (memcmp(plaintext, decryptedPlaintext, sizeof (plaintext)) == 0)
		{
			SUCCESS("AES-128 Decryption")
		}
		else
		{
			FAIL("AES-128-CTR Decryption")
			INFO("RESULT")
			printBuffer(decryptedPlaintext, sizeof (decryptedPlaintext));
			INFO("EXPECTED")
			printBuffer(plaintext, sizeof (plaintext));
		}
		
		benchmark([&keyObj, &initializationVector, &plaintext, &ciphertext](){Aes::Mode::Ctr128::encrypt(keyObj, initializationVector, plaintext, sizeof (plaintext), ciphertext);}, "AES-128-CTR Encryption", 100000, sizeof (plaintext) / sizeof (uint32_t));
	};
	
	auto aes128CtrBenchmark = []()
	{
		uint8_t plaintext[8192];
		
		// Generate plaintext
		for (uint32_t byte = 0; byte < sizeof (plaintext); byte++)
		{
			plaintext[byte] = uint8_t(byte);
		}
		
		uint8_t key[] {
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
		};
		
		uint8_t initializationVector[] {
			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff			
		};
		
		uint8_t ciphertext[sizeof (plaintext)];
		uint8_t decryptedPlaintext[sizeof (plaintext)];
		
		Aes::Key128 keyObj(key);
		Aes::Mode::Ctr128::encrypt(keyObj, initializationVector, plaintext, sizeof (plaintext), ciphertext);
		Aes::Mode::Ctr128::decrypt(keyObj, initializationVector, ciphertext, sizeof (ciphertext), decryptedPlaintext);
		
		if (memcmp(plaintext, decryptedPlaintext, sizeof (plaintext)) == 0)
		{
			SUCCESS("AES-128-CTR")
		}
		else
		{
			FAIL("AES-128-CTR")
		}
		
		benchmark([&keyObj, &initializationVector, &plaintext, &ciphertext](){Aes::Mode::Ctr128::encrypt(keyObj, initializationVector, plaintext, sizeof (plaintext), ciphertext);}, "AES-128-CTR Encryption", 10000, sizeof (plaintext) / sizeof (uint32_t));
	};
	
	auto aes192Test = []()
	{
		uint8_t plaintext[] = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
		};
		
		uint8_t key[] {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17		
		};
		
		uint8_t expectedCiphertext[] {
			0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
		};
		
		uint8_t ciphertext[sizeof (plaintext)];
		uint8_t decryptedPlaintext[sizeof (plaintext)];
		
		Aes::Key192 keyObj(key);
		Aes::Block192 block(keyObj);
		block.encrypt(plaintext, ciphertext);
		
		if (memcmp(expectedCiphertext, ciphertext, sizeof (expectedCiphertext)) == 0)
		{
			SUCCESS("AES-192 Encryption")
		}
		else
		{
			FAIL("AES-192 Encryption")
			INFO("RESULT")
			printBuffer(ciphertext, AES_BLOCK_SIZE * 4);
			INFO("EXPECTED")
			printBuffer(expectedCiphertext, AES_BLOCK_SIZE * 4);
		}
		
		block.decrypt(ciphertext, decryptedPlaintext);
		
		if (memcmp(plaintext, decryptedPlaintext, sizeof (plaintext)) == 0)
		{
			SUCCESS("AES-192 Decryption")
		}
		else
		{
			FAIL("AES-192 Decryption")
			INFO("RESULT")
			printBuffer(decryptedPlaintext, AES_BLOCK_SIZE * 4);
			INFO("EXPECTED")
			printBuffer(plaintext, AES_BLOCK_SIZE * 4);
		}
		
		benchmark([&block, &plaintext, &ciphertext](){block.encrypt(plaintext, ciphertext);}, "AES-192 Encryption", 10000000);
	};
	
	auto aes256Test = []()
	{
		uint8_t plaintext[] = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
		};
		
		uint8_t key[] {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
		};
		
		uint8_t expectedCiphertext[] {
			0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
		};
		
		uint8_t ciphertext[sizeof (plaintext)];
		uint8_t decryptedPlaintext[sizeof (plaintext)];
		
		Aes::Key256 keyObj(key);
		Aes::Block256 block(keyObj);
		block.encrypt(plaintext, ciphertext);
		
		if (memcmp(expectedCiphertext, ciphertext, sizeof (expectedCiphertext)) == 0)
		{
			SUCCESS("AES-256 Encryption")
		}
		else
		{
			FAIL("AES-256 Encryption")
			INFO("RESULT")
			printBuffer(ciphertext, AES_BLOCK_SIZE * 4);
			INFO("EXPECTED")
			printBuffer(expectedCiphertext, AES_BLOCK_SIZE * 4);
		}
		
		block.decrypt(ciphertext, decryptedPlaintext);
		
		if (memcmp(plaintext, decryptedPlaintext, sizeof (plaintext)) == 0)
		{
			SUCCESS("AES-256 Decryption")
		}
		else
		{
			FAIL("AES-256 Decryption")
			INFO("RESULT")
			printBuffer(decryptedPlaintext, AES_BLOCK_SIZE * 4);
			INFO("EXPECTED")
			printBuffer(plaintext, AES_BLOCK_SIZE * 4);
		}
		
		benchmark([&block, &plaintext, &ciphertext](){block.encrypt(plaintext, ciphertext);}, "AES-256 Encryption", 10000000);
	};
	
	// Run tests
	aes128Test();
	aes128CtrTest();
	aes128CtrBenchmark();
	aes192Test();
	aes256Test();
	
	return 0;
}
