#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_ChecksumAlgorithm.h>

static char TestXOR_CreateContext(void **context)
{
	unsigned char *ctx = calloc(1, sizeof(unsigned char));
	if (!ctx) return 0;

	*ctx = 0;
	*context = ctx;
	return 1;
}

static void TestXOR_Update(void *context, const struct VPS_Data *raw_data)
{
	unsigned char *ctx = context;
	VPS_TYPE_SIZE i;

	if (!ctx || !raw_data || !raw_data->bytes) return;

	for (i = 0; i < raw_data->limit; i++)
	{
		*ctx ^= raw_data->bytes[i];
	}
}

static char TestXOR_Finalize(void *context, struct VPS_Data *out_checksum)
{
	unsigned char *ctx = context;

	if (!ctx || !out_checksum) return 0;

	// VPS_Data_Allocate(, 0, 0) leaves own_bytes=0, so Resize rejects it.
	// Manually allocate the buffer.
	out_checksum->bytes = calloc(1, 1);
	if (!out_checksum->bytes) return 0;
	out_checksum->bytes[0] = *ctx;
	out_checksum->size = 1;
	out_checksum->limit = 1;
	out_checksum->own_bytes = 1;

	return 1;
}

static void TestXOR_ReleaseContext(void *context)
{
	free(context);
}

static struct IFF_ChecksumAlgorithm s_test_xor_algorithm =
{
	.identifier = "TEST-XOR",
	.output_size = 1,
	.create_context = TestXOR_CreateContext,
	.update = TestXOR_Update,
	.finalize = TestXOR_Finalize,
	.release_context = TestXOR_ReleaseContext
};

const struct IFF_ChecksumAlgorithm *IFF_TestChecksumAlgorithm_GetXOR(void)
{
	return &s_test_xor_algorithm;
}
