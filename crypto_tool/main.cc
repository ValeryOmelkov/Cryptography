/*
 * main.cc
 *
 *  Created on: 20 янв. 2022 г.
 *      Author: Omelk
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <random>
#include <ctime>
#include <stdint.h>

#include <ec-container.h>
#include <ec-utils.h>
#include <ec-crypt.h>

const char * TEST_KEY_FILE = "test-key.ecc";
const char * TEST_FILE_NAME = "test.txt";
const char * TEST_CONTAINER_NAME = "test-container.ecc";
const uint32_t TEST_BLOCK_SIZE = 32; // в битах
const char * TEST_CRYPTOCONTAINER = "test-cryptocontainer.ecc";
const char * TEST_CBC_CRYPTOCONTAINER = "test-CBC.ecc";
const char * TEST_CTR_CRYPTOCONTAINER = "test-CTR.ecc";
const uint32_t T_SWAP[16] = {3, 5, 4, 8, 9, 1, 11, 13, 12, 0, 15, 2, 7, 6, 10, 14};
const char * IV = "mvpd";

/*
 * тестовый шифр
 * блок - 32 бита (4 байта)
 * раундов - 18
 * длина ключа - 288 (36 байт)
 */
const uint32_t MY_CRYPT_ROUNDS = 18;
const uint16_t MY_CRYPT_KEY[18] {
	0x1234, 0x5678, 0x9abc, 0xdef0,
	0x1122, 0x3344, 0x5566, 0x7788,
	0x9900, 0xaabb, 0xccdd, 0xeeff,
	0xa1b2, 0xc3d4, 0xe5f6, 0xaa00,
	0xabcd, 0xef99
};

const uint8_t MY_CRYPT_S_BLOCKS[4][16] {
	{ 12,  4,  6,  2, 10,  5, 11,  9, 14,  8, 13,  7,  0,  3, 15,  1 },
	{  6,  8,  2,  3,  9, 10,  5, 12,  1, 14,  4,  7, 11, 13,  0, 15 },
	{ 11,  3,  5,  8,  2, 15, 10, 13, 14,  1,  7,  4, 12,  9,  6,  0 },
	{ 12,  8,  2,  1, 13,  4, 15,  6,  7,  0, 10,  5,  3, 14,  9, 11 }
};

void my_crypt(const uint8_t *src, const uint8_t *key, uint8_t *dst) {
	const uint16_t *src_val = reinterpret_cast<const uint16_t*>(src);
	const uint16_t *key_val = reinterpret_cast<const uint16_t*>(key);
	uint16_t *dst_val = reinterpret_cast<uint16_t*>(dst);

	uint16_t v = *src_val;
	*dst_val = 0;

	for (int i=0; i<4; ++i) {
		for (unsigned j=0; j<4; ++j) {
				*dst_val <<= j;
				*dst_val |= MY_CRYPT_S_BLOCKS[j][v & 0x0f];
			}
		v >>= i;
	}

	*dst_val += *key_val;
}

void increment_block(uint8_t * block, size_t sz)
{
	unsigned current_byte = 0;
	while (current_byte < sz)
	{
		uint8_t old_value = block[current_byte];
		uint8_t new_value = old_value + 1;
		block[current_byte] = new_value;
		if (new_value > old_value) return;
		current_byte++;
	}
}

void test_create_container() {

	std::ifstream src_file;
	std::ofstream dst_file;

	src_file.open("test.txt", std::ios::binary | std::ios::ate);
	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	dst_file.open("test-container.ecc", std::ios::binary);

	using namespace ec::container;
	header hdr {};
	hdr.magic = MAGIC;
	hdr.version = 1;
	hdr.header_size = HEADER_SIZE_V1;
	hdr.v1.payload = RAW;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE_V1);

	metadata_v1 md {};
	uint32_t name_length = strlen(TEST_FILE_NAME);
	md.length = FILE_METADATA_SIZE_V1_BASE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = TEST_BLOCK_SIZE;
	md.file.block_count = filesize / (TEST_BLOCK_SIZE / 8);
	if (filesize % (TEST_BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	auto file_header_pos = dst_file.tellp();
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	uint32_t crc32 = 0;
	uint32_t crc32_table[256];
	ec::utils::generate_crc32_lut(crc32_table); // @suppress("Invalid arguments")
	for (uint64_t block = 0; block < md.file.block_count; ++block) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
		for (unsigned k=0; k<TEST_BLOCK_SIZE/8; ++k)
			crc32 = ec::utils::update_crc32(crc32_table, buffer[k], crc32); // @suppress("Invalid arguments")

		ec::crypt::feistel(
				reinterpret_cast<const uint8_t*>(&buffer[0]),
				TEST_BLOCK_SIZE / 8,
				reinterpret_cast<const uint8_t*>(MY_CRYPT_KEY),
				sizeof(MY_CRYPT_KEY),
				MY_CRYPT_ROUNDS,
				false,
				[](	const uint8_t *s,
					const uint8_t *k,
					uint8_t *d) { my_crypt(s, k, d); },
				reinterpret_cast<uint8_t*>(&buffer[0]));

		dst_file.write(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
	}

	md.file.crc32 = crc32;
	std::cout << "generated CRC: " << std::hex << std::setfill('0') << std::setw(8) << crc32 << std::endl;
	dst_file.seekp(file_header_pos);
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);

	src_file.close();
	dst_file.close();
}

void test_extract_container() {

	std::ifstream src_file;
	std::ofstream dst_file;

	using namespace ec::container;

	src_file.open(TEST_CONTAINER_NAME, std::ios::binary);
	header hdr { };
	src_file.readsome(reinterpret_cast<char*>(&hdr), sizeof(header));
	if (hdr.magic != MAGIC) {
		std::cerr << "файл контейнера кривой" << std::endl;
		return;
	}
	if (hdr.v1.payload != RAW) {
		std::cerr << "в контейнере лежит что-то не то" << std::endl;
		return;
	}
	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata_v1 md { };
	src_file.readsome(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	std::string orig_file_name = "extracted-";
	char c;
	while ((c = src_file.get())) {
		orig_file_name += c;
	}

	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);

	uint32_t crc32 = 0;
	uint32_t crc32_table[256];
	ec::utils::generate_crc32_lut(crc32_table); // @suppress("Invalid arguments")

	while (md.file.orig_length > 0) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);

		ec::crypt::feistel(reinterpret_cast<const uint8_t*>(&buffer[0]),
				TEST_BLOCK_SIZE / 8,
				reinterpret_cast<const uint8_t*>(MY_CRYPT_KEY),
				sizeof(MY_CRYPT_KEY), MY_CRYPT_ROUNDS, true,
				[](const uint8_t *s, const uint8_t *k, uint8_t *d) {
					my_crypt(s, k, d);
				},
				reinterpret_cast<uint8_t*>(&buffer[0]));

		for (unsigned k = 0; k < TEST_BLOCK_SIZE / 8; ++k)
			crc32 = ec::utils::update_crc32(crc32_table, buffer[k], crc32); // @suppress("Invalid arguments")

//		uint64_t bytes_to_write = std::min(4UL, md.file.orig_length);
		uint64_t bytes_to_write;
		if (4UL < md.file.orig_length)
			bytes_to_write = 4UL;
		else
			bytes_to_write = md.file.orig_length;

		dst_file.write(reinterpret_cast<char*>(&buffer[0]), bytes_to_write);
		md.file.orig_length -= bytes_to_write;

	}

	dst_file.close();
	src_file.close();

	std::cout << "calculated CRC: " << std::hex << std::setfill('0')
			<< std::setw(8) << crc32 << std::endl;
	std::cout << "read CRC: " << std::hex << std::setfill('0') << std::setw(8)
			<< md.file.crc32 << std::endl;

	if (crc32 != md.file.crc32)
		std::cout << "WARNING!!! CRC mismatch!" << std::endl;

}

void key_container(uint64_t key_length) {
	std::ofstream src_file;
	using namespace ec::container;

	src_file.open(TEST_KEY_FILE, std::ios::binary);
	if (!src_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}

	header hdr { };
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE_V1;
	hdr.v1.payload = KEY_DATA;
	src_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE_V1);

	metadata_v1 md { };
	md.length = FILE_METADATA_SIZE_V1_BASE;
	md.key.length = key_length;
	md.key.block_size = TEST_BLOCK_SIZE;
	md.key.block_count = key_length / (TEST_BLOCK_SIZE / 8);
	if (key_length % (TEST_BLOCK_SIZE / 8) > 0)
		md.key.block_count++;
	src_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	std::random_device rd;
	std::mt19937 random_mt(rd());
	for (uint64_t block = 0; block < md.key.block_count; block++) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };

		srand(static_cast<unsigned int>(time(0)));
		for (uint8_t i = 0; i < TEST_BLOCK_SIZE / 8; i++) {
			buffer[i] = random_mt() % 32;
		}
		src_file.write(reinterpret_cast<char*>(&buffer[0]),TEST_BLOCK_SIZE / 8);
	}

	src_file.close();
	std::cout << "Create key container" << std::endl;
}

void encryption() {
	std::ifstream src_file;
	std::ofstream dst_file;
	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);

	if (!src_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}

	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	dst_file.open(TEST_CRYPTOCONTAINER, std::ios::binary);

	using namespace ec::container;

	header hdr { };
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE_V1;
	hdr.v1.payload = ENCRYPTED_DATA;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE_V1);

	metadata_v1 md { };
	uint32_t name_length = strlen(TEST_FILE_NAME);
	md.length = FILE_METADATA_SIZE_V1_BASE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = TEST_BLOCK_SIZE;
	md.file.block_count = filesize / (TEST_BLOCK_SIZE / 8);
	if (filesize % (TEST_BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	std::ifstream src2_file;
	src2_file.open(TEST_KEY_FILE, std::ios::binary);
	if (!src2_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}
	using namespace ec::container;
	header hdr2 { };
	src2_file.read(reinterpret_cast<char*>(&hdr2), sizeof(header));
	if (hdr2.magic != MAGIC) {
		std::cerr << "File dont open (MAGIC ERROR)!" << std::endl;
		return;
	}
	if (hdr2.v1.payload != KEY_DATA) {
		std::cerr << "File no KEY_DATA data!" << std::endl;
		return;
	}
	src2_file.seekg(hdr2.header_size);

	uint64_t pos_after_header_2 = src2_file.tellg();

	metadata_v1 md2 { };
	src2_file.readsome(reinterpret_cast<char*>(&md2),
			FILE_METADATA_SIZE_V1_BASE);
	src2_file.seekg(pos_after_header_2 + md2.length);
	uint8_t key[16] { };

	src2_file.read(reinterpret_cast<char*>(&key[0]), 16);
//	std::cout << reinterpret_cast<char*>(&key[0]) << std::endl;

	src2_file.close();
//	std::cout << "Key read OK!" << std::endl;

	for (uint64_t block = 0; block < md.file.block_count; block++) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
		uint8_t *forMerge = new uint8_t[2];
		forMerge[0] = buffer[3];
		forMerge[1] = buffer[2];
		uint16_t Li = *((uint16_t*) forMerge);
		forMerge[0] = buffer[1];
		forMerge[1] = buffer[0];
		uint16_t Ri = *((uint16_t*) forMerge);
//		std::cout << " " << std::endl;
//		std::cout << Li << " " << Ri << std::endl;

		for (uint16_t ttt = 0; ttt < 8; ttt++) {
			uint16_t a[4] { };
			uint32_t y = 0;
			for (uint32_t i = 0; i < 16; i = i + 4) {
				a[y] = (((Li >> (i + 3)) & 1) << 0)
						| (((Li >> (i + 2)) & 1) << 1)
						| (((Li >> (i + 1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8)
					| (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[ttt * 2];
			forMerge2[1] = key[ttt * 2 + 1];
			uint16_t key_buff = *((uint16_t*) forMerge2);

			Sx ^= key_buff;

			Sx = (Sx << 3) | (Sx >> (16 - 3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
//			std::cout << Li << " " << Ri << std::endl;
		}
		//std::cout << reinterpret_cast<char*>(&Ri) << std::endl;
		//std::cout << reinterpret_cast<char*>(&Li) << std::endl;
		dst_file.write(reinterpret_cast<char*>(&Ri), TEST_BLOCK_SIZE / 16);
		dst_file.write(reinterpret_cast<char*>(&Li), TEST_BLOCK_SIZE / 16);
	}

	src_file.close();
	dst_file.close();
//	std::cout << "Crypto container:" << std::endl;
}

void decryption() {
	std::ifstream src_file;
	src_file.open(TEST_CRYPTOCONTAINER, std::ios::binary | std::ios::ate);
	if (!src_file.is_open()) {
		std::cerr << "File dont open 1!" << std::endl;
		return;
	}

	using namespace ec::container;

	header hdr { };
	src_file.read(reinterpret_cast<char*>(&hdr), sizeof(header));
	if (hdr.magic != MAGIC) {
//		std::cerr << "File dont open 2!" << std::endl;
		return;
	}

	if (hdr.v1.payload != ENCRYPTED_DATA) {
		std::cerr << "File no ENCRYPTED_DATA data!" << std::endl;
		return;
	}

	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata_v1 md { };
	src_file.readsome(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	std::string orig_file_name = "EXTRACTED_";
	char c;
	while ((c = src_file.get())) {
		orig_file_name += c;
	}
	std::cout << "Start extract encryption container" << std::endl;
	std::ofstream dst_file;
	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);

	while (md.file.orig_length > 0) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL,
				md.file.orig_length);

		std::ifstream src2_file;
		src2_file.open(TEST_KEY_FILE, std::ios::binary);
		if (!src2_file.is_open()) {
			std::cerr << "File dont open 3!" << std::endl;
			return;
		}
		using namespace ec::container;
		header hdr2 { };
		src2_file.read(reinterpret_cast<char*>(&hdr2), sizeof(header));
		if (hdr2.magic != MAGIC) {
			std::cerr << "File dont open (MAGIC ERROR)!" << std::endl;
			return;
		}
		if (hdr2.v1.payload != KEY_DATA) {
			std::cerr << "File no KEY_DATA data!" << std::endl;
			return;
		}
		src2_file.seekg(hdr2.header_size);

		uint64_t pos_after_header2 = src2_file.tellg();

		metadata_v1 md2 { };
		src2_file.readsome(reinterpret_cast<char*>(&md2),
				FILE_METADATA_SIZE_V1_BASE);
		src2_file.seekg(pos_after_header2 + md2.length);

		uint8_t key[16] { };
		src2_file.read(reinterpret_cast<char*>(&key[0]), 16);

		src2_file.close();
		//std::cout << "Key read OK!" << std::endl;

		uint16_t Li = (buffer[3] << 8) + buffer[2];
		uint16_t Ri = (buffer[1] << 8) + buffer[0];
		//std::cout << Li << " " << Ri << std::endl;
		//std::cout << " " << std::endl;
		for (uint16_t ttt = 0; ttt < 8; ttt++) {
			uint16_t a[4] { };
			uint32_t y = 0;
			for (uint32_t i = 0; i < 16; i = i + 4) {
				a[y] = (((Li >> (i + 3)) & 1) << 0)
						| (((Li >> (i + 2)) & 1) << 1)
						| (((Li >> (i + 1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8)
					| (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[15 - (ttt * 2 + 1)];
			forMerge2[1] = key[15 - (ttt * 2)];
			uint16_t key_buff = *((uint16_t*) forMerge2);

			Sx ^= key_buff;

			Sx = (Sx << 3) | (Sx >> (16 - 3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
//			std::cout << Li << " " << Ri << std::endl;
		}
		//std::cout << reinterpret_cast<char*>(&Ri) << std::endl;
		//std::cout << reinterpret_cast<char*>(&Li) << std::endl;
		uint32_t cryptParts = (Li << 16) + Ri;
		dst_file.write(reinterpret_cast<char*>(&cryptParts), bytes_to_write);
		md.file.orig_length -= bytes_to_write;
	}

	dst_file.close();
	src_file.close();

	std::cout << "Extract container" << std::endl;
}

void CBC_container() {
	std::ifstream src_file;
	std::ofstream dst_file;
	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);

	if (!src_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}

	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	dst_file.open(TEST_CBC_CRYPTOCONTAINER, std::ios::binary);

	using namespace ec::container;

	header hdr { };
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE_V1;
	hdr.v1.payload = ENCRYPTED_DATA;
	hdr.v1.crypt = CBC_CRYPT;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE_V1);

	metadata_v1 md { };
	uint32_t name_length = strlen(TEST_FILE_NAME);
	md.length = FILE_METADATA_SIZE_V1_BASE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = TEST_BLOCK_SIZE;
	md.file.block_count = filesize / (TEST_BLOCK_SIZE / 8);
	if (filesize % (TEST_BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	std::ifstream src2_file;
	src2_file.open(TEST_KEY_FILE, std::ios::binary);
	if (!src2_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}
	using namespace ec::container;
	header hdr2 { };
	src2_file.read(reinterpret_cast<char*>(&hdr2), sizeof(header));
	if (hdr2.magic != MAGIC) {
		std::cerr << "File dont open (MAGIC ERROR)!" << std::endl;
		return;
	}
	if (hdr2.v1.payload != KEY_DATA) {
		std::cerr << "File no KEY_DATA data!" << std::endl;
		return;
	}
	src2_file.seekg(hdr2.header_size);

	uint64_t pos_after_header_2 = src2_file.tellg();

	metadata_v1 md2 { };
	src2_file.readsome(reinterpret_cast<char*>(&md2),
			FILE_METADATA_SIZE_V1_BASE);
	src2_file.seekg(pos_after_header_2 + md2.length);
	uint8_t key[16] { };
	src2_file.read(reinterpret_cast<char*>(&key[0]), 16);
//	std::cout << reinterpret_cast<char*>(&key[0]) << std::endl;

	src2_file.close();
//	std::cout << "Key read OK!" << std::endl;
	uint32_t word_crypt = *((uint32_t*) IV);

	for (uint64_t block = 0; block < md.file.block_count; block++) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);

		uint32_t word = (buffer[3] << 24) + (buffer[2] << 16) + (buffer[1] << 8)
				+ buffer[0];
		word ^= word_crypt;
		uint16_t Li = word >> 16 & 0xFFFF;
		uint16_t Ri = word & 0xFFFF;
		for (uint16_t ttt = 0; ttt < 8; ttt++) {
			uint16_t a[4] { };
			uint32_t y = 0;
			for (uint32_t i = 0; i < 16; i = i + 4) {
				a[y] = (((Li >> (i + 3)) & 1) << 0)
						| (((Li >> (i + 2)) & 1) << 1)
						| (((Li >> (i + 1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8)
					| (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[0];
			forMerge2[1] = key[1];
			uint16_t key_buff = *((uint16_t*) forMerge2);

			Sx ^= key_buff;
			Sx = (Sx << 3) | (Sx >> (16 - 3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
//			std::cout << Li << " " << Ri << std::endl;
		}
		//std::cout << reinterpret_cast<char*>(&Ri) << std::endl;
		//std::cout << reinterpret_cast<char*>(&Li) << std::endl;
		word_crypt = (Li << 16) + Ri;
		dst_file.write(reinterpret_cast<char*>(&word_crypt),
				TEST_BLOCK_SIZE / 8);
	}

	src_file.close();
	dst_file.close();
//	std::cout << "Crypto container:" << std::endl;
}

void CBC_decryption() {
	std::ifstream src_file;
	src_file.open(TEST_CRYPTOCONTAINER, std::ios::binary | std::ios::ate);
	if (!src_file.is_open()) {
		std::cerr << "File dont open 1!" << std::endl;
		return;
	}

	using namespace ec::container;

	header hdr { };
	src_file.read(reinterpret_cast<char*>(&hdr), sizeof(header));
	if (hdr.magic != MAGIC) {
//		std::cerr << "File dont open 2!" << std::endl;
		return;
	}

	if (hdr.v1.payload != ENCRYPTED_DATA) {
		std::cerr << "File no ENCRYPTED_DATA data!" << std::endl;
		return;
	}

	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata_v1 md { };
	src_file.readsome(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	std::string orig_file_name = "EXTRACTED_";
	char c;
	while ((c = src_file.get())) {
		orig_file_name += c;
	}
	std::cout << "Start extract encryption container" << std::endl;
	std::ofstream dst_file;
	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);
	uint32_t word_crypt = *((uint32_t*) IV);
	while (md.file.orig_length > 0) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL,
				md.file.orig_length);

		std::ifstream src2_file;
		src2_file.open(TEST_KEY_FILE, std::ios::binary);
		if (!src2_file.is_open()) {
			std::cerr << "File dont open 3!" << std::endl;
			return;
		}
		using namespace ec::container;
		header hdr2 { };
		src2_file.read(reinterpret_cast<char*>(&hdr2), sizeof(header));
		if (hdr2.magic != MAGIC) {
			std::cerr << "File dont open (MAGIC ERROR)!" << std::endl;
			return;
		}
		if (hdr2.v1.payload != KEY_DATA) {
			std::cerr << "File no KEY_DATA data!" << std::endl;
			return;
		}
		src2_file.seekg(hdr2.header_size);

		uint64_t pos_after_header2 = src2_file.tellg();

		metadata_v1 md2 { };
		src2_file.readsome(reinterpret_cast<char*>(&md2),
				FILE_METADATA_SIZE_V1_BASE);
		src2_file.seekg(pos_after_header2 + md2.length);

		uint8_t key[16] { };
		src2_file.read(reinterpret_cast<char*>(&key[0]), 16);

		src2_file.close();
		//std::cout << "Key read OK!" << std::endl;

		uint16_t Li = (buffer[3] << 8) + buffer[2];
		uint16_t Ri = (buffer[1] << 8) + buffer[0];
		uint32_t LiRi = (Li << 16) + Ri;
		//std::cout << Li << " " << Ri << std::endl;
		//std::cout << " " << std::endl;
		for (uint16_t ttt = 0; ttt < 8; ttt++) {
			uint16_t a[4] { };
			uint32_t y = 0;
			for (uint32_t i = 0; i < 16; i = i + 4) {
				a[y] = (((Li >> (i + 3)) & 1) << 0)
						| (((Li >> (i + 2)) & 1) << 1)
						| (((Li >> (i + 1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8)
					| (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[15 - (ttt * 2 + 1)];
			forMerge2[1] = key[15 - (ttt * 2)];
			uint16_t key_buff = *((uint16_t*) forMerge2);

			Sx ^= key_buff;

			Sx = (Sx << 3) | (Sx >> (16 - 3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
//			std::cout << Li << " " << Ri << std::endl;
		}
		//std::cout << reinterpret_cast<char*>(&Ri) << std::endl;
		//std::cout << reinterpret_cast<char*>(&Li) << std::endl;
		uint32_t word = (Li << 16) + Ri;
		word ^= word_crypt;
		word_crypt = LiRi;
		dst_file.write(reinterpret_cast<char*>(&word), bytes_to_write);
		md.file.orig_length -= bytes_to_write;
	}

	dst_file.close();
	src_file.close();

	std::cout << "Extract container" << std::endl;
}

void CTR_container() {
	std::ifstream src_file;
	std::ofstream dst_file;
	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);

	if (!src_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}

	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	dst_file.open(TEST_CTR_CRYPTOCONTAINER, std::ios::binary);

	using namespace ec::container;

	header hdr { };
	hdr.magic = MAGIC;
	hdr.header_size = HEADER_SIZE_V1;
	hdr.v1.payload = ENCRYPTED_DATA;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE_V1);

	metadata_v1 md { };
	uint32_t name_length = strlen(TEST_FILE_NAME);
	md.length = FILE_METADATA_SIZE_V1_BASE + name_length + 1;
	md.file.orig_length = filesize;
	md.file.block_size = TEST_BLOCK_SIZE;
	md.file.block_count = filesize / (TEST_BLOCK_SIZE / 8);
	if (filesize % (TEST_BLOCK_SIZE / 8) > 0)
		md.file.block_count++;
	dst_file.write(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	std::ifstream src2_file;
	src2_file.open(TEST_KEY_FILE, std::ios::binary);
	if (!src2_file.is_open()) {
		std::cerr << "File dont open!" << std::endl;
		return;
	}
	using namespace ec::container;
	header hdr2 { };
	src2_file.read(reinterpret_cast<char*>(&hdr2), sizeof(header));
	if (hdr2.magic != MAGIC) {
		std::cerr << "File dont open (MAGIC ERROR)!" << std::endl;
		return;
	}
	if (hdr2.v1.payload != KEY_DATA) {
		std::cerr << "File no KEY_DATA data!" << std::endl;
		return;
	}
	src2_file.seekg(hdr2.header_size);

	uint64_t pos_after_header_2 = src2_file.tellg();

	metadata_v1 md2 { };
	src2_file.readsome(reinterpret_cast<char*>(&md2),
			FILE_METADATA_SIZE_V1_BASE);
	src2_file.seekg(pos_after_header_2 + md2.length);
	uint8_t key[16] { };

	src2_file.read(reinterpret_cast<char*>(&key[0]), 16);
//	std::cout << reinterpret_cast<char*>(&key[0]) << std::endl;

	src2_file.close();
//	std::cout << "Key read OK!" << std::endl;
	uint32_t word_crypt = *((uint32_t*) IV);
	for (uint64_t block = 0; block < md.file.block_count; block++) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
		uint16_t Li = word_crypt >> 16 & 0xFFFF;
		uint16_t Ri = word_crypt & 0xFFFF;

		for (uint16_t ttt = 0; ttt < 8; ttt++) {
			uint16_t a[4] { };
			uint32_t y = 0;
			for (uint32_t i = 0; i < 16; i = i + 4) {
				a[y] = (((Li >> (i + 3)) & 1) << 0)
						| (((Li >> (i + 2)) & 1) << 1)
						| (((Li >> (i + 1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8)
					| (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[ttt * 2];
			forMerge2[1] = key[ttt * 2 + 1];
			uint16_t key_buff = *((uint16_t*) forMerge2);

			Sx ^= key_buff;

			Sx = (Sx << 3) | (Sx >> (16 - 3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
//			std::cout << Li << " " << Ri << std::endl;
		}
		uint32_t word = (buffer[3] << 24) + (buffer[2] << 16) + (buffer[1] << 8)
				+ buffer[0];
		word ^= ((Li << 16) + Ri);

		dst_file.write(reinterpret_cast<char*>(&word), TEST_BLOCK_SIZE / 8);

		uint8_t word_crypt_to_blocks[4] { };
		word_crypt_to_blocks[3] = word_crypt & 0xFF;
		word_crypt_to_blocks[2] = word_crypt >> 8 & 0xFF;
		word_crypt_to_blocks[1] = word_crypt >> 16 & 0xFF;
		word_crypt_to_blocks[0] = word_crypt >> 24 & 0xFF;
		increment_block(&word_crypt_to_blocks[0], TEST_BLOCK_SIZE);
		word_crypt = (word_crypt_to_blocks[3] << 24)
				+ (word_crypt_to_blocks[2] << 16)
				+ (word_crypt_to_blocks[1] << 8) + word_crypt_to_blocks[0];
	}

	src_file.close();
	dst_file.close();
//	std::cout << "Crypto container:" << std::endl;
}

void CTR_decryption() {
	std::ifstream src_file;
	src_file.open(TEST_CRYPTOCONTAINER, std::ios::binary | std::ios::ate);
	if (!src_file.is_open()) {
		std::cerr << "File dont open 1!" << std::endl;
		return;
	}

	using namespace ec::container;

	header hdr { };
	src_file.read(reinterpret_cast<char*>(&hdr), sizeof(header));
	if (hdr.magic != MAGIC) {
//		std::cerr << "File dont open 2!" << std::endl;
		return;
	}

	if (hdr.v1.payload != ENCRYPTED_DATA) {
		std::cerr << "File no ENCRYPTED_DATA data!" << std::endl;
		return;
	}

	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata_v1 md { };
	src_file.readsome(reinterpret_cast<char*>(&md), FILE_METADATA_SIZE_V1_BASE);
	std::string orig_file_name = "EXTRACTED_";
	char c;
	while ((c = src_file.get())) {
		orig_file_name += c;
	}
	std::cout << "Start extract encryption container" << std::endl;
	std::ofstream dst_file;
	dst_file.open(orig_file_name.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + md.length);
	uint32_t word_crypt = *((uint32_t*) IV);
	while (md.file.orig_length > 0) {
		uint8_t buffer[TEST_BLOCK_SIZE / 8] { };
		src_file.read(reinterpret_cast<char*>(&buffer[0]), TEST_BLOCK_SIZE / 8);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL,
				md.file.orig_length);

		std::ifstream src2_file;
		src2_file.open(TEST_KEY_FILE, std::ios::binary);
		if (!src2_file.is_open()) {
			std::cerr << "File dont open 3!" << std::endl;
			return;
		}
		using namespace ec::container;
		header hdr2 { };
		src2_file.read(reinterpret_cast<char*>(&hdr2), sizeof(header));
		if (hdr2.magic != MAGIC) {
			std::cerr << "File dont open (MAGIC ERROR)!" << std::endl;
			return;
		}
		if (hdr2.v1.payload != KEY_DATA) {
			std::cerr << "File no KEY_DATA data!" << std::endl;
			return;
		}
		src2_file.seekg(hdr2.header_size);

		uint64_t pos_after_header2 = src2_file.tellg();

		metadata_v1 md2 { };
		src2_file.readsome(reinterpret_cast<char*>(&md2),
				FILE_METADATA_SIZE_V1_BASE);
		src2_file.seekg(pos_after_header2 + md2.length);

		uint8_t key[16] { };
		src2_file.read(reinterpret_cast<char*>(&key[0]), 16);

		src2_file.close();

		uint16_t Li = word_crypt >> 16 & 0xFFFF;
		uint16_t Ri = word_crypt & 0xFFFF;

		for (uint16_t ttt = 0; ttt < 8; ttt++) {
			uint16_t a[4] { };
			uint32_t y = 0;
			for (uint32_t i = 0; i < 16; i = i + 4) {
				a[y] = (((Li >> (i + 3)) & 1) << 0)
						| (((Li >> (i + 2)) & 1) << 1)
						| (((Li >> (i + 1)) & 1) << 2) | (((Li >> i) & 1) << 3);
				y += 1;
			}

			uint16_t Sx = (T_SWAP[a[3]] << 12) | (T_SWAP[a[2]] << 8)
					| (T_SWAP[a[1]] << 4) | (T_SWAP[a[0]] << 0);

			uint8_t *forMerge2 = new uint8_t[2];
			forMerge2[0] = key[15 - (ttt * 2 + 1)];
			forMerge2[1] = key[15 - (ttt * 2)];
			uint16_t key_buff = *((uint16_t*) forMerge2);

			Sx ^= key_buff;

			Sx = (Sx << 3) | (Sx >> (16 - 3));

			uint16_t oldLi = Li;
			Li = Ri ^ Sx;
			Ri = oldLi;
//			std::cout << Li << " " << Ri << std::endl;
		}

		uint32_t word = (buffer[3] << 24) + (buffer[2] << 16) + (buffer[1] << 8)
				+ buffer[0];
		word ^= ((Li << 16) + Ri);

		dst_file.write(reinterpret_cast<char*>(&word), TEST_BLOCK_SIZE / 8);

		uint8_t word_crypt_to_blocks[4] { };
		word_crypt_to_blocks[3] = word_crypt & 0xFF;
		word_crypt_to_blocks[2] = word_crypt >> 8 & 0xFF;
		word_crypt_to_blocks[1] = word_crypt >> 16 & 0xFF;
		word_crypt_to_blocks[0] = word_crypt >> 24 & 0xFF;
		increment_block(&word_crypt_to_blocks[0], TEST_BLOCK_SIZE);
		word_crypt = (word_crypt_to_blocks[3] << 24)
				+ (word_crypt_to_blocks[2] << 16)
				+ (word_crypt_to_blocks[1] << 8) + word_crypt_to_blocks[0];

		md.file.orig_length -= bytes_to_write;
	}

	dst_file.close();
	src_file.close();

	std::cout << "Extract container" << std::endl;
}


void test_magma () {

	uint8_t src_key[] {
			0xff, 0xfe, 0xfd, 0xfc,
			0xfb, 0xfa, 0xf9, 0xf8,
			0xf7, 0xf6, 0xf5, 0xf4,
			0xf3, 0xf2, 0xf1, 0xf0,
			0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff
	};

	const uint8_t src_m[] {
		0x4e, 0xe9, 0x01, 0xe5,
		0xc2, 0xd8, 0xca, 0x3d
	};

	uint8_t dst_m[8];

	ec::crypt::crypt_gost_34_12_64(src_m, src_key, true, dst_m);

	for (unsigned i=0; i<8; ++i){
		std::cout <<
		std::hex <<
		std::setfill('0') <<
		std::setw(2) <<
		uint32_t(dst_m[i]) << std::endl;
	}
}

int main(int argc, char ** argv) {

//	test_create_container();
//	test_extract_container();
//	std::cout << "\n" << "test magma" << std::endl;
//	test_magma();

	uint64_t key_length = 32;
	key_container(key_length);
	encryption();
	decryption();

	CBC_container();
	CBC_decryption();
	CTR_container();
	CTR_decryption();

	return 0;
}

