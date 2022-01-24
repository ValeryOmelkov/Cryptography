/*
 * ec-crypt.h
 *
 *  Created on: 20 ���. 2022 �.
 *      Author: Omelk
 */

#ifndef EC_CRYPT_H_
#define EC_CRYPT_H_

#include <cstdint>
#include <functional>

namespace ec {
namespace crypt {

	/*
	 * 1 �������� - �������� ������
	 * 2 �������� - ����
	 * 3 �������� - �������� ������
	 */
	using crypto_function = std::function<void(const uint8_t *, const uint8_t *, uint8_t *)>;

	/*
	 * src_block 	- �������� ������ ������
	 * block_size 	- ����� ���������/��������� ������� � ������
	 * key 			- ������ ������ �������� ����������
	 * key_length 	- ����� ����� � ������
	 * rounds_count	- ���������� �������
	 * reverse_key 	- ������� �� ���������� ���� (��� �������������)
	 * cf 			- ������� ����������
	 * dst_block 	- �������� ������ ������
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
	 * ���������� ��� ������������� ������ �����
	 * ���� 34.12 �.5 "�����"
	 */
	void crypt_gost_34_12_64(
			const uint8_t	*src_block,
			const uint8_t 	*key,
			bool 			reverse_key,
			uint8_t 		*dst_block);

	/*
	 * ���������� ��� ������������� ������ �����
	 * ���� 34.12 �.5 "��������"
	 */
	void crypt_gost_34_12_128(const uint8_t	*src_block,
						      const uint8_t 	*key,
							  bool 			reverse_key,
							  uint8_t 		*dst_block);

} /* namespace crypt */
} /* namespace ec */

#endif /* EC_CRYPT_H_ */
