/**
 * @brief LRC-ISO-1155 checksum algorithm (Longitudinal Redundancy Check).
 * @details XOR of all bytes. 8-bit output.
 *          Identifier: "LRC-ISO-1155"
 */

const struct IFF_ChecksumAlgorithm* IFF_Checksum_LRC_Get(void);
