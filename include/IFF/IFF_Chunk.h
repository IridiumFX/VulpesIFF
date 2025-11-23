/**
 * @brief Represents a single, complete IFF chunk read from the stream.
 * @details This is a simple data container that holds the tag, the interpreted
 *          size, and the raw data payload of a chunk. It is the primary
 *          "product" of the IFF_Reader.
 */
struct IFF_Chunk
{
	struct IFF_Tag tag;
	VPS_TYPE_SIZE size;
	struct VPS_Data* data;
};

char IFF_Chunk_Allocate
(
	struct IFF_Chunk** item
);

char IFF_Chunk_Construct
(
	struct IFF_Chunk* item,
	const struct IFF_Tag* tag,
	VPS_TYPE_SIZE size,
	struct VPS_Data* data
);

char IFF_Chunk_Deconstruct
(
	struct IFF_Chunk* item
);

char IFF_Chunk_Release
(
	struct IFF_Chunk* item
);
