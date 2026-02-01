/**
 * @brief Test decoder implementations for verifying parser decoder dispatch.
 *
 * TestChunkDecoder: passthrough that wraps raw chunk data as ContextualData.
 * TestFormDecoder: collects chunks, produces TestFormState as final entity.
 * PropAwareFormDecoder: like TestFormDecoder but calls FindProp in begin_decode.
 */

struct IFF_FormDecoder;
struct IFF_ChunkDecoder;

/**
 * @brief Final entity produced by TestFormDecoder / PropAwareFormDecoder.
 */
struct TestFormState
{
	int chunk_count;
	char has_bmhd;
	char prop_found;
};

/**
 * @brief Creates a TestChunkDecoder (passthrough).
 * @details Wraps raw chunk data as IFF_ContextualData with default flags.
 *          Caller must release the returned decoder.
 */
char IFF_TestDecoders_CreateChunkDecoder
(
	struct IFF_ChunkDecoder **out_decoder
);

/**
 * @brief Creates a TestFormDecoder (chunk collector).
 * @details Counts chunks, detects BMHD via non-null contextual_data.
 *          Produces TestFormState as final_entity.
 *          Caller must release the returned decoder.
 */
char IFF_TestDecoders_CreateFormDecoder
(
	struct IFF_FormDecoder **out_decoder
);

/**
 * @brief Creates a PropAwareFormDecoder.
 * @details Like TestFormDecoder, but begin_decode calls FindProp for BMHD
 *          and sets prop_found=1 if found.
 *          Caller must release the returned decoder.
 */
char IFF_TestDecoders_CreatePropAwareFormDecoder
(
	struct IFF_FormDecoder **out_decoder
);
