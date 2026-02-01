/**
 * @brief CRC-32C (Castagnoli) checksum algorithm.
 * @details Uses polynomial 0x1EDC6F41. 32-bit output, big-endian.
 *          Identifier: "CRC-32C"
 */

const struct IFF_ChecksumAlgorithm* IFF_Checksum_CRC32C_Get(void);
