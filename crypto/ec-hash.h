/*
 * ec-hash.h
 *
 *  Created on: 21 џэт. 2022 у.
 *      Author: Omelk
 */

#ifndef EC_HASH_H_
#define EC_HASH_H_

#include <cstdint>

namespace ec {
namespace crypt {

	void gost_34_11_hash_256();
	void gost_34_11_hash_512();

} /* namespace hash */
} /* namespace ec */

#endif /* EC_HASH_H_ */
