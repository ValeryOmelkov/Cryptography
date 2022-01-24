/*
 * ec-utils.cc
 *
 *  Created on: 20 џэт. 2022 у.
 *      Author: Omelk
 */
#include "ec-container.h"
#include "ec-utils.h"

namespace ec {
namespace utils {

	void generate_crc32_lut(uint32_t * table) {

		using ec::container::CRC32_POLY;
		for (unsigned i=0; i<256; ++i) {
			uint32_t b = i;
			for (unsigned j=0; j<8; ++j) {
				if (b & 1) b = (b >> 1) ^ CRC32_POLY;
				else b = (b >> 1);
			}
			table[i] = b;
		}
	}

	uint32_t update_crc32(uint32_t * table, uint8_t b, uint32_t crc){
		uint32_t result = crc;
		result = table[(crc ^ b) & 0xff];
		return result;
	}

} /* namespace utils */
} /* namespace ec */



