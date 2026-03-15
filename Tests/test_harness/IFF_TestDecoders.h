/**
 * @brief Test decoder implementations for verifying parser decoder dispatch.
 *
 * TestChunkDecoder: passthrough that wraps raw chunk data as ContextualData.
 * TestFormDecoder: collects chunks, produces TestFormState as final entity.
 * PropAwareFormDecoder: like TestFormDecoder but calls FindProp in begin_decode.
 * FailingFormDecoder: begin_decode returns 0 to test error propagation.
 * NestingAwareFormDecoder: tracks nested forms received via process_nested_form.
 * ShardCountingChunkDecoder: like TestChunkDecoder but increments global counter.
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
	int nested_form_count;
};

/**
 * @brief Global counter incremented by ShardCountingChunkDecoder's process_shard.
 *        Reset to 0 before each test that uses it.
 */
extern int IFF_TestDecoders_ShardCallCount;

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
 * @brief Creates a ShardCountingChunkDecoder.
 * @details Like TestChunkDecoder, but increments IFF_TestDecoders_ShardCallCount
 *          on each process_shard call. Reset the counter before each test.
 */
char IFF_TestDecoders_CreateShardCountingChunkDecoder
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

/**
 * @brief Creates a FailingFormDecoder.
 * @details begin_decode returns 0. Used to test error propagation (R78).
 */
char IFF_TestDecoders_CreateFailingFormDecoder
(
	struct IFF_FormDecoder **out_decoder
);

/**
 * @brief Creates a NestingAwareFormDecoder.
 * @details Like TestFormDecoder, but process_nested_form increments
 *          nested_form_count in TestFormState.
 */
char IFF_TestDecoders_CreateNestingAwareFormDecoder
(
	struct IFF_FormDecoder **out_decoder
);
