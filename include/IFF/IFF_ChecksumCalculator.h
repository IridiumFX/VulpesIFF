/**
 * @brief A concrete instance of a checksum calculator for a single span.
 * @details This struct pairs a specific algorithm's function table with its
 *          live state (context) for a given 'CHK'...'SUM' span. It is the
 *          object that performs the actual calculation.
 */
struct IFF_ChecksumCalculator
{
	/** @brief A pointer to the algorithm's function table. */
	const struct IFF_ChecksumAlgorithm* algorithm;

	/**
	 * @brief The live state for this calculator instance (e.g., holds the
	 *        current CRC value). This is created and managed by the
	 *        functions in the `algorithm` interface.
	 */
	void* context;
};

char IFF_ChecksumCalculator_Allocate
(
	struct IFF_ChecksumCalculator **item
);

char IFF_ChecksumCalculator_Construct
(
	struct IFF_ChecksumCalculator *item,
	const struct IFF_ChecksumAlgorithm* algorithm
);

char IFF_ChecksumCalculator_Deconstruct
(
	struct IFF_ChecksumCalculator *item
);

char IFF_ChecksumCalculator_Release
(
	struct IFF_ChecksumCalculator *item
);
