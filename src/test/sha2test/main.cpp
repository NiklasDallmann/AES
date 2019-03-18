#include <chrono>
#include <iostream>
#include <stdint.h>
#include <stdlib.h>

#include "sha2digest.h"
#include "cryptoutilities.h"

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
	
	bandwidth = (double(dataSize) / double(1000000) / secondsPerCycle);
	
	BENCHMARK(tag << "	" << millisecondsPerCycle << " ms/cycle	" << bandwidth << " MB/s")
}

int main()
{
	auto sha256Test = []()
	{
		uint8_t key[] = {
			0xfa
		};
		
		uint8_t expectedHash[] = {
			0xc4, 0xef, 0x36, 0x92, 0x3c, 0x64, 0xe5, 0x1e, 0x87, 0x57, 0x20, 0xe5, 0x50, 0x29, 0x8a, 0x5a,
			0xb8, 0xa3, 0xf2, 0xf8, 0x75, 0xb1, 0xe1, 0xa4, 0xc9, 0xb9, 0x5b, 0xab, 0xf7, 0x34, 0x4f, 0xef
		};
		
		uint8_t hash[sizeof (expectedHash)];
		
		Crypto::Hash::Sha2::Digest256 digest;
		digest.hash(key, sizeof (key));
		
		if (memcmp(expectedHash, hash, sizeof (expectedHash)) == 0)
		{
			SUCCESS("SHA-256")
		}
		else
		{
			FAIL("SHA-256")
			INFO("RESULT")
			printBuffer(hash, sizeof (expectedHash));
			INFO("EXPECTED")
			printBuffer(expectedHash, sizeof (expectedHash));
		}
		
//		benchmark([&block, &plaintext, &ciphertext](){block.encrypt(plaintext, ciphertext);}, "AES-128 Encryption", 10000000);
	};
	
	// Run tests
	sha256Test();
	
	return 0;
}
