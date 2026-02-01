/**
 * @brief A stateful decorator that interprets a raw IFF byte stream.
 * @details This reader wraps a lower-level reader (like IFF_CheckedReader)
 *          and uses its internal configuration state to transform raw bytes
 *          into meaningful IFF primitives like canonical tags and integers.
 */
struct IFF_Reader
{
	/** @brief The next reader in the decorator chain (the "tap"). */
	struct IFF_DataTap* tap;

	/**
	 * @brief A dictionary for content decoders (e.g., Base64), if the encoding field gets specc'ed
	 */
	struct VPS_Dictionary* content_decoders;
};

char IFF_Reader_Allocate
(
	struct IFF_Reader** item
);

char IFF_Reader_Construct
(
	struct IFF_Reader* item
	, int fh
);

char IFF_Reader_ConstructFromData
(
	struct IFF_Reader* item
	, const struct VPS_Data *source
);

char IFF_Reader_Deconstruct
(
	struct IFF_Reader* item
);

char IFF_Reader_Release
(
	struct IFF_Reader* item
);

/**
 * @brief Reads and canonicalizes a tag based on the current configuration.
 */
char IFF_Reader_ReadTag
(
	struct IFF_Reader* reader
	, enum IFF_Header_TagSizing tag_sizing
	, struct IFF_Tag* tag
);

/**
 * @brief Reads and interprets a size field based on the current configuration.
 */
char IFF_Reader_ReadSize
(
	struct IFF_Reader* reader
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_SIZE* size
);

/**
 * @brief Reads a block of data, applying content decoding if necessary.
 */
char IFF_Reader_ReadData
(
	struct IFF_Reader* reader
	, enum IFF_Header_Encoding encoding
	, VPS_TYPE_SIZE size
	, struct VPS_Data** out_data
);

/**
 * @brief Skips a block of data, applying content decoding if necessary.
 */
char IFF_Reader_Skip
(
	struct IFF_Reader* reader
	, VPS_TYPE_SIZE bytes_to_skip
);

/**
 * @brief Reads a chunk data (Size, and Data) for a specified Tag.
 * @details This is the primary high-level primitive for the parser. It internally
 *          calls the granular ReadSize, and ReadData functions, ensuring
 *          the entire decorator stack (e.g., checksumming) is processed correctly.
 */
char IFF_Reader_ReadChunk
(
	struct IFF_Reader* reader,
	const struct IFF_Header_Flags_Fields* config,
	struct IFF_Tag *tag,
	struct IFF_Chunk** out_chunk
);

char IFF_Reader_IsActive
(
	struct IFF_Reader* reader
);

/**
 * @brief Parses a ' CHK' directive payload and starts a checksum span.
 * @details Decodes the binary payload format (version, algorithm identifiers),
 *          builds a VPS_Set of identifiers, and delegates to IFF_DataTap_StartSpan.
 * @param reader The reader whose DataTap owns the checksum state.
 * @param config Current scope flags (for interpreting size fields in the payload).
 * @param chk_payload The raw data from the ' CHK' directive chunk.
 * @return 1 on success, 0 on failure.
 */
/**
 * @brief Reads a size field from a VPS_DataReader using the provided config.
 */
char IFF_Reader_ReadPayloadSize
(
	struct VPS_DataReader* dr,
	const struct IFF_Header_Flags_Fields* config,
	VPS_TYPE_SIZE* out_size
);

char IFF_Reader_StartChecksumSpan
(
	struct IFF_Reader* reader
	, const struct IFF_Header_Flags_Fields* config
	, const struct VPS_Data* chk_payload
);

/**
 * @brief Parses a ' SUM' directive payload and ends the current checksum span.
 * @details Decodes the binary payload format (version, algorithm identifiers +
 *          expected checksums), builds a VPS_Dictionary of expected values, and
 *          delegates to IFF_DataTap_EndSpan for verification.
 * @param reader The reader whose DataTap owns the checksum state.
 * @param config Current scope flags (for interpreting size fields in the payload).
 * @param sum_payload The raw data from the ' SUM' directive chunk.
 * @return 1 if all checksums match, 0 on mismatch or failure.
 */
char IFF_Reader_EndChecksumSpan
(
	struct IFF_Reader* reader
	, const struct IFF_Header_Flags_Fields* config
	, const struct VPS_Data* sum_payload
);
