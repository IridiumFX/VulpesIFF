/**
 * @brief CRC-64/ECMA-182 checksum algorithm.
 * @details Uses polynomial 0x42F0E1EBA9EA3693. 64-bit output, big-endian.
 *          Identifier: "CRC64-ECMA"
 */

const struct IFF_ChecksumAlgorithm* IFF_Checksum_CRC64ECMA_Get(void);
