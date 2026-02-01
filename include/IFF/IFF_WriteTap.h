struct IFF_ChecksumAlgorithm;
struct VPS_Set;
struct VPS_Dictionary;

/**
 * @brief A decorator writer that transparently calculates checksums.
 * @details This writer acts as a "tap" on the output stream. It wraps a
 *          lower-level writer (IFF_WritePump) and, when a checksum span is
 *          active, feeds all raw bytes that pass through it into the
 *          appropriate checksum algorithm(s). Write-side mirror of IFF_DataTap.
 */
struct IFF_WriteTap
{
	struct IFF_WritePump *pump;

	/**
	 * @brief A dictionary mapping algorithm identifiers (e.g., "CRC-32C")
	 *        to their IFF_ChecksumAlgorithm implementations.
	 */
	struct VPS_Dictionary *registered_algorithms;

	/**
	 * @brief A LIFO of active checksum spans.
	 * @details Each node contains an IFF_ChecksumSpan object with concurrent
	 *          calculators for that level of nesting.
	 */
	struct VPS_List *active_spans;
};

char IFF_WriteTap_Allocate
(
	struct IFF_WriteTap **item
);

char IFF_WriteTap_Construct
(
	struct IFF_WriteTap *item
	, int file_handle
);

char IFF_WriteTap_ConstructToData
(
	struct IFF_WriteTap *item
);

char IFF_WriteTap_GetOutputData
(
	struct IFF_WriteTap *tap
	, struct VPS_Data **out_data
);

char IFF_WriteTap_Deconstruct
(
	struct IFF_WriteTap *item
);

char IFF_WriteTap_Release
(
	struct IFF_WriteTap *item
);

char IFF_WriteTap_RegisterAlgorithm
(
	struct IFF_WriteTap *tap
	, const struct IFF_ChecksumAlgorithm *algorithm
);

/**
 * @brief Writes raw bytes, transparently updating any active checksums.
 */
char IFF_WriteTap_WriteRaw
(
	struct IFF_WriteTap *tap
	, const unsigned char *data
	, VPS_TYPE_SIZE size
);

/**
 * @brief Writes a VPS_Data buffer, transparently updating any active checksums.
 */
char IFF_WriteTap_WriteData
(
	struct IFF_WriteTap *tap
	, const struct VPS_Data *data
);

/**
 * @brief Starts a new checksum span for the given algorithm identifiers.
 */
char IFF_WriteTap_StartSpan
(
	struct IFF_WriteTap *tap
	, const struct VPS_Set *algorithm_identifiers
);

/**
 * @brief Ends the current checksum span and returns computed checksums.
 * @param tap The write tap.
 * @param out_checksums A dictionary to receive computed {id -> checksum_bytes} pairs.
 *                      The caller is responsible for releasing this dictionary.
 * @return 1 on success, 0 on failure.
 */
char IFF_WriteTap_EndSpan
(
	struct IFF_WriteTap *tap
	, struct VPS_Dictionary **out_checksums
);

char IFF_WriteTap_Flush
(
	struct IFF_WriteTap *tap
);
