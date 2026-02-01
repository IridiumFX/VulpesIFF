/**
 * @brief A trivial XOR-of-all-bytes checksum algorithm for testing.
 *
 * identifier:  "TEST-XOR"
 * output_size: 1
 * Computes: XOR of every byte that passes through the span.
 */

struct IFF_ChecksumAlgorithm;

/**
 * @brief Returns a pointer to a static TEST-XOR algorithm instance.
 * @details The returned pointer is valid for the lifetime of the program.
 *          Do NOT release or free it.
 */
const struct IFF_ChecksumAlgorithm *IFF_TestChecksumAlgorithm_GetXOR(void);
