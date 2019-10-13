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
	auto sha256TestEmptyMsg = []()
	{
		uint8_t expectedHash[] = {
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
		};
		
		uint8_t hash[sizeof (expectedHash)];
		
		Crypto::Hash::Sha2::Digest256 digest;
		digest.hash(nullptr, 0);
		digest.extract(hash);
		
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
			abort();
		}
	};
	
	auto sha256TestShortMsg = []()
	{
		uint8_t key[] = {
			0xd3
		};
		
		uint8_t expectedHash[] = {
			0x28, 0x96, 0x9c, 0xdf, 0xa7, 0x4a, 0x12, 0xc8, 0x2f, 0x3b, 0xad, 0x96, 0x0b, 0x0b, 0x00, 0x0a,
			0xca, 0x2a, 0xc3, 0x29, 0xde, 0xea, 0x5c, 0x23, 0x28, 0xeb, 0xc6, 0xf2, 0xba, 0x98, 0x02, 0xc1
		};
		
		uint8_t hash[sizeof (expectedHash)];
		
		Crypto::Hash::Sha2::Digest256 digest;
		digest.hash(key, sizeof (key));
		digest.extract(hash);
		
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
			abort();
		}
	};
	
	auto sha256TestMediumMsg = []()
	{
		uint8_t key[] = {
			0x1b, 0x77, 0xc8, 0xdc, 0xfd, 0x2f, 0xc4, 0xb5, 0x46, 0x17, 0x05, 0x4f, 0xa6, 0xb1, 0x4d, 0x6e,
			0x9d, 0x09, 0xce, 0x91, 0x85, 0xa3, 0x4a, 0x7f, 0xd2, 0xb2, 0x79, 0x23, 0x99, 0x8a, 0xab, 0x99
		};
		
		uint8_t expectedHash[] = {
			0x68, 0x3b, 0x48, 0x68, 0x61, 0xe5, 0x98, 0xda, 0xbb, 0xa7, 0x40, 0xac, 0x91, 0x95, 0x22, 0xcf,
			0x3b, 0x60, 0x9c, 0x18, 0x20, 0x5b, 0x6b, 0xec, 0xa4, 0xcc, 0xbe, 0x6b, 0x0f, 0x6d, 0xc6, 0xdb
		};
		
		uint8_t hash[sizeof (expectedHash)];
		
		Crypto::Hash::Sha2::Digest256 digest;
		digest.hash(key, sizeof (key));
		digest.extract(hash);
		
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
			abort();
		}
	};
	
	// Run tests
	sha256TestEmptyMsg();
	sha256TestShortMsg();
//	sha256TestMediumMsg();
	
	return 0;
}
