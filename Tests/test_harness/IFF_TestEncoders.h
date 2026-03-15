struct IFF_FormEncoder;
struct IFF_ChunkEncoder;

struct TestSourceChunk
{
	const char *tag;
	unsigned char *data;
	VPS_TYPE_SIZE size;
};

struct TestSourceEntity
{
	int chunk_count;
	struct TestSourceChunk chunks[8];
};

char IFF_TestEncoders_CreateFormEncoder
(
	struct IFF_FormEncoder **out
);

char IFF_TestEncoders_CreateDoublerChunkEncoder
(
	struct IFF_ChunkEncoder **out
);

/**
 * @brief Creates a FormEncoder whose produce_chunk immediately sets done=1.
 * @details Produces empty FORM (no chunks). Used for W67.
 */
char IFF_TestEncoders_CreateEmptyFormEncoder
(
	struct IFF_FormEncoder **out
);

/**
 * @brief Creates a FormEncoder whose begin_encode returns 0.
 * @details Used for W68 error propagation test.
 */
char IFF_TestEncoders_CreateFailBeginFormEncoder
(
	struct IFF_FormEncoder **out
);

/**
 * @brief Creates a FormEncoder whose produce_chunk fails on 2nd call.
 * @details First chunk succeeds, second returns 0. Uses TestSourceEntity.
 *          Used for W69.
 */
char IFF_TestEncoders_CreateFailSecondChunkFormEncoder
(
	struct IFF_FormEncoder **out
);
