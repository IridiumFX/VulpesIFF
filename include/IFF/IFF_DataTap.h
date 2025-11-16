/**
 * @brief A decorator reader that transparently calculates checksums.
 * @details This reader acts as a "tap" on the I/O stream. It wraps a lower-level
 *          reader (like IFF_DataPump) and, when a checksum span is active, it
 *          feeds all raw bytes that pass through it into the appropriate
 *          checksum algorithm(s).
 */
struct IFF_DataTap
{
	struct IFF_DataPump *pump;

	/**
	 * @brief A dictionary mapping algorithm identifiers (e.g., "CRC-32C")
	 *        to their IFF_ChecksumAlgorithm implementations.
	 */
	struct VPS_Dictionary *registered_algorithms;

	/**
	 * @brief A LIFO of active checksum spans.
	 * @details Each node in this list contains an IFF_ChecksumSpan object,
	 * which in turn holds all the concurrent calculators for that
	 * level of nesting, supporting multiple algorithms per ' CHK' directive
	 */
	struct VPS_List *active_spans;
};

char IFF_DataTap_Allocate
(
	struct IFF_DataTap **item
);

char IFF_DataTap_Construct
(
	struct IFF_DataTap *item
	, int fh
);

char IFF_DataTap_Deconstruct
(
	struct IFF_DataTap *item
);

char IFF_DataTap_Release
(
	struct IFF_DataTap *tap
);

char IFF_DataTap_RegisterAlgorithm
(
	struct IFF_DataTap* tap,
	const struct IFF_ChecksumAlgorithm* algorithm
);

/**
 * @brief Reads raw bytes, transparently updating any active checksums.
 * @details This is the core "tap" function. It calls the underlying reader
 *          to get the bytes, then passes those bytes to all active calculators
 *          before returning the bytes to the caller.
 */
char IFF_DataTap_ReadRaw
(
	struct IFF_DataTap *tap
	, VPS_TYPE_SIZE bytes_to_read
	, struct VPS_Data **out_data
);

char IFF_DataTap_StartSpan
(
	struct IFF_DataTap *tap
	, const struct VPS_Set *algorithm_identifiers
);

char IFF_DataTap_EndSpan
(
	struct IFF_DataTap *tap
	, struct VPS_Dictionary *expected_checksums
);

char IFF_DataTap_Skip
(
	struct IFF_DataTap *tap
	, VPS_TYPE_SIZE bytes_to_skip
);
