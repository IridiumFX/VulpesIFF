/**
 * @brief A simple binary serializer that constructs IFF byte images in memory.
 * @details Independent of both IFF_Parser and IFF_Generator to avoid circular
 *          trust. Builds valid IFF binary data that can be fed into the parser
 *          via the memory-backed constructor path.
 *
 *          Supports blobbed mode (size-patching) only. For progressive mode,
 *          the caller writes ' END' directives manually via AddDirective.
 */

#include <vulpes/VPS_Types.h>

struct VPS_Data;
struct VPS_DataWriter;
struct IFF_Header;

#define IFF_TEST_BUILDER_MAX_DEPTH 32

struct IFF_TestBuilder
{
	struct VPS_Data *buffer;
	struct VPS_DataWriter *writer;

	VPS_TYPE_8U tag_length;
	VPS_TYPE_8U size_length;
	char is_le;
	char is_progressive;
	char no_padding;

	VPS_TYPE_SIZE patch_offsets[IFF_TEST_BUILDER_MAX_DEPTH];
	int depth;
};

char IFF_TestBuilder_Allocate
(
	struct IFF_TestBuilder **builder
);

char IFF_TestBuilder_Construct
(
	struct IFF_TestBuilder *b
);

char IFF_TestBuilder_Deconstruct
(
	struct IFF_TestBuilder *b
);

char IFF_TestBuilder_Release
(
	struct IFF_TestBuilder *b
);

/**
 * @brief Write an ' IFF' header directive into the output.
 * @details Serializes version, revision, and flags as the spec requires.
 *          Also updates the builder's internal tag_length/size_length/endianness
 *          to match the header flags, so subsequent writes use the right widths.
 */
char IFF_TestBuilder_AddHeader
(
	struct IFF_TestBuilder *b
	, const struct IFF_Header *header
);

/**
 * @brief Begin a container (FORM, LIST, CAT, PROP).
 * @details In blobbed mode: writes variant tag, placeholder size, type tag.
 *          In progressive mode: writes variant tag, type tag (no size).
 * @param variant 4-char string: "FORM", "LIST", "CAT " or "PROP"
 * @param type 4-char string: e.g. "ILBM", "    " (wildcard), etc.
 */
char IFF_TestBuilder_BeginContainer
(
	struct IFF_TestBuilder *b
	, const char *variant
	, const char *type
);

/**
 * @brief End the current container.
 * @details In blobbed mode: patches the size field written by BeginContainer.
 *          In progressive mode: writes ' END' + size 0.
 */
char IFF_TestBuilder_EndContainer
(
	struct IFF_TestBuilder *b
);

/**
 * @brief Write a complete chunk: tag + size + data + padding.
 */
char IFF_TestBuilder_AddChunk
(
	struct IFF_TestBuilder *b
	, const char *tag
	, const unsigned char *data
	, VPS_TYPE_SIZE size
);

/**
 * @brief Write a raw directive: left-padded tag + size + data.
 * @details Useful for custom directives or ' END' in progressive mode.
 */
char IFF_TestBuilder_AddDirective
(
	struct IFF_TestBuilder *b
	, const char *tag
	, const unsigned char *data
	, VPS_TYPE_SIZE size
);

/**
 * @brief Get the built binary image.
 * @details Returns a pointer to the builder's internal buffer. The caller
 *          must NOT release it — it's owned by the builder.
 */
char IFF_TestBuilder_GetResult
(
	struct IFF_TestBuilder *b
	, struct VPS_Data **out_data
);
