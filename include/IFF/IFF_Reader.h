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

char IFF_Reader_Skip
(
	struct IFF_Reader* reader
	, VPS_TYPE_SIZE bytes_to_skip
);
