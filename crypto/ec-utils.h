/*
 * ec-utils.h
 *
 *  Created on: 20 џэт. 2022 у.
 *      Author: Omelk
 */

#ifndef EC_UTILS_H_
#define EC_UTILS_H_

#include <cstdint>

namespace ec {
namespace utils {

	void generate_crc32_lut(uint32_t * table);
	uint32_t update_crc32(uint32_t *table, uint8_t b, uint32_t crc);

} /* namespace utils */
} /* namespace ec */

#endif /* EC_UTILS_H_ */
