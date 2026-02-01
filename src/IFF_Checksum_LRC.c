#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_Checksum_LRC.h>

/**
 * LRC-ISO-1155: XOR of all bytes. 8-bit output.
 *
 * The context is a single heap-allocated byte holding the running XOR.
 */

static char LRC_CreateContext
(
	void** context
)
{
	VPS_TYPE_8U* state;

	if (!context)
	{
		return 0;
	}

	state = calloc(1, sizeof(VPS_TYPE_8U));
	if (!state)
	{
		return 0;
	}

	*state = 0;
	*context = state;

	return 1;
}

static void LRC_Update
(
	void* context
	, const struct VPS_Data* raw_data
)
{
	VPS_TYPE_8U* state = context;
	VPS_TYPE_SIZE i;

	if (!state || !raw_data || !raw_data->bytes)
	{
		return;
	}

	for (i = 0; i < raw_data->size; ++i)
	{
		*state ^= raw_data->bytes[i];
	}
}

static char LRC_Finalize
(
	void* context
	, struct VPS_Data* out_checksum
)
{
	VPS_TYPE_8U* state = context;

	if (!state || !out_checksum)
	{
		return 0;
	}

	if (!VPS_Data_Resize(out_checksum, 1))
	{
		return 0;
	}

	out_checksum->bytes[0] = *state;

	return 1;
}

static void LRC_ReleaseContext
(
	void* context
)
{
	free(context);
}

static struct IFF_ChecksumAlgorithm LRC_ALGORITHM =
{
	"LRC-ISO-1155",
	1,
	LRC_CreateContext,
	LRC_Update,
	LRC_Finalize,
	LRC_ReleaseContext
};

const struct IFF_ChecksumAlgorithm* IFF_Checksum_LRC_Get(void)
{
	return &LRC_ALGORITHM;
}
