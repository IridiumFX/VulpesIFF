/**
 * @brief Represents a single, active checksum span initiated by a 'CHK' directive.
 * @details This struct acts as a container for all the concurrent checksum
 *          calculations happening within one level of nesting.
 */
struct IFF_ChecksumSpan
{
	/**
	 * @brief A list of IFF_ChecksumCalculator instances.
	 * @details Each calculator in this list corresponds to one algorithm
	 *          (e.g., "CRC-32C", "RFC-1071") active for this span.
	 */
	struct VPS_List* calculators;
};

char IFF_ChecksumSpan_Allocate
(
	struct IFF_ChecksumSpan** item
);

char IFF_ChecksumSpan_Construct
(
	struct IFF_ChecksumSpan* item
);

char IFF_ChecksumSpan_Deconstruct
(
	struct IFF_ChecksumSpan* item
);

char IFF_ChecksumSpan_Release
(
	struct IFF_ChecksumSpan* item
);
