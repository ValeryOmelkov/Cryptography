/*
 * ec-crypt.h
 *
 *  Created on: 20 янв. 2022 г.
 *      Author: Omelk
 */

#ifndef EC_CRYPT_H_
#define EC_CRYPT_H_

#include <cstdint>
#include <functional>

namespace ec {
namespace crypt {

	/*
	 * 1 параметр - исходный массив
	 * 2 параметр - ключ
	 * 3 параметр - конечный массив
	 */
	using crypto_function = std::function<void(const uint8_t *, const uint8_t *, uint8_t *)>;

	/*
	 * src_block 	- исходный массив байтов
	 * block_size 	- длина исходного/конечного массива в байтах
	 * key 			- массив байтов ключевой информации
	 * key_length 	- длина ключа в байтах
	 * rounds_count	- количество раундов
	 * reverse_key 	- следует ли развернуть ключ (для расшифрования)
	 * cf 			- функция шифрования
	 * dst_block 	- конечный массив байтов
	 */
	void feistel(const uint8_t 		*src_block,
	 			 uint32_t 			block_size,
	 			 const uint8_t 		*key,
				 uint32_t 			key_length,
				 uint32_t 			rounds_count,
				 bool 				reverse_key,
				 crypto_function		cf,
				 uint8_t 			*dst_block);

	/*
	 * шифрование или расшифрование одного блока
	 * ГОСТ 34.12 ч.5 "Магма"
	 */
	void crypt_gost_34_12_64(
			const uint8_t	*src_block,
			const uint8_t 	*key,
			bool 			reverse_key,
			uint8_t 		*dst_block);

	/*
	 * шифрование или расшифрование одного блока
	 * ГОСТ 34.12 ч.5 "Кузнечик"
	 */
	void crypt_gost_34_12_128(const uint8_t	*src_block,
						      const uint8_t 	*key,
							  bool 			reverse_key,
							  uint8_t 		*dst_block);

} /* namespace crypt */
} /* namespace ec */

#endif /* EC_CRYPT_H_ */
