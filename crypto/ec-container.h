/*
 * ec-container.h
 *
 *  Created on: 20 янв. 2022 г.
 *      Author: Omelk
 */

#ifndef EC_CONTAINER_H_
#define EC_CONTAINER_H_

#include <cstdint>

namespace ec {
namespace container {

	// Container MAGIC number = "EC!C"
	constexpr uint32_t MAGIC =
		0x00000001 * 'E' +
		0x00000100 * 'C' +
		0x00010000 * '!' +
		0x01000000 * 'C';

	enum payload_type {
		RAW = 0,		// "сырые" данные
		KEY_DATA,		//  ключ для симметричного шифра
		PRIVATE_KEY,	//	закрытый ключ для асимметричного шифра
		PUBLIC_KEY,		//	открытый ключ для асимметричного шифра
		ENCRYPTED_DATA,	//	шифротекст
		DH_PARAMS,		//
	};

	constexpr uint32_t HEADER_SIZE_V1 = 16;
	constexpr uint32_t FILE_METADATA_SIZE_V1_BASE = 28;
	constexpr uint32_t CRC32_POLY = 0xEDB88320; //1110 1101 1011 1000 1000 0011 0010 0000

	#pragma pack(push, 1)

	struct header {
		uint32_t magic;
		uint32_t version;
		uint32_t header_size;

		union {
			struct {
				uint8_t payload;
				uint8_t padding[3];
			} v1;
		};
	};

	struct metadata_v1 {
		uint32_t length;

		union {
			struct {
				uint64_t orig_length;
				uint64_t block_count;
				uint32_t block_size;
				uint32_t crc32;
			} file;

			struct {
				uint32_t length;
				uint64_t block_count;
				uint32_t block_size;
			} key;

			struct {
				//?????
			} dh_params;
		};
	};

	#pragma pack(pop)

	/* структура криптоконтейнера v1
	 * --------------------------------
	 * 		header_v1
	 * 		metadata_v1, в зависимости от типа
	 * 			для файла - следом идет имя в ASCIIZ
	 * 		данные
	 */

} /* namespace container */
} /* namespace ec */

#endif /* EC_CONTAINER_H_ */
