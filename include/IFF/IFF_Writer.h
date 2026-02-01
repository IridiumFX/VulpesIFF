/**
 * @brief A stateful decorator that writes IFF primitives to a byte stream.
 * @details Inverse of IFF_Reader. Serializes tags, sizes, and data payloads
 *          using the current configuration flags and delegates to the
 *          underlying IFF_WriteTap for checksum-aware output.
 */
struct IFF_Writer
{
	struct IFF_WriteTap *tap;

	/**
	 * @brief Reserved for future content encoders (e.g., Base64).
	 */
	struct VPS_Dictionary *content_encoders;
};

char IFF_Writer_Allocate
(
	struct IFF_Writer **item
);

char IFF_Writer_Construct
(
	struct IFF_Writer *item
	, int file_handle
);

char IFF_Writer_ConstructToData
(
	struct IFF_Writer *item
);

char IFF_Writer_GetOutputData
(
	struct IFF_Writer *writer
	, struct VPS_Data **out_data
);

char IFF_Writer_Deconstruct
(
	struct IFF_Writer *item
);

char IFF_Writer_Release
(
	struct IFF_Writer *item
);

/**
 * @brief Serializes and writes a tag to the output stream.
 */
char IFF_Writer_WriteTag
(
	struct IFF_Writer *writer
	, enum IFF_Header_TagSizing tag_sizing
	, const struct IFF_Tag *tag
);

/**
 * @brief Serializes and writes a size field to the output stream.
 */
char IFF_Writer_WriteSize
(
	struct IFF_Writer *writer
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_SIZE size
);

/**
 * @brief Writes raw chunk payload data to the output stream.
 */
char IFF_Writer_WriteData
(
	struct IFF_Writer *writer
	, enum IFF_Header_Encoding encoding
	, const struct VPS_Data *data
);

/**
 * @brief Convenience: writes tag + size + data as a complete chunk.
 */
char IFF_Writer_WriteChunk
(
	struct IFF_Writer *writer
	, const struct IFF_Header_Flags_Fields *config
	, const struct IFF_Tag *tag
	, const struct VPS_Data *data
);

/**
 * @brief Emits 1 zero byte if data_size is odd and NO_PADDING is not set.
 */
char IFF_Writer_WritePadding
(
	struct IFF_Writer *writer
	, const struct IFF_Header_Flags_Fields *config
	, VPS_TYPE_SIZE data_size
);

char IFF_Writer_Flush
(
	struct IFF_Writer *writer
);
