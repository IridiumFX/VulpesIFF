#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_Checksum_RFC1071.h>

/**
 * RFC-1071 Internet Checksum: one's complement sum of 16-bit words.
 * 16-bit output, stored big-endian.
 *
 * Algorithm:
 *   1. Accumulate running 32-bit sum of 16-bit big-endian words.
 *   2. If odd byte count, pad the last byte with 0x00 to form a word.
 *   3. Fold carry into the low 16 bits.
 *   4. Output is the one's complement (~sum).
 */

struct RFC1071_State
{
	VPS_TYPE_32U sum;
};

static char RFC1071_CreateContext
(
	void** context
)
{
	struct RFC1071_State* state;

	if (!context)
	{
		return 0;
	}

	state = calloc(1, sizeof(struct RFC1071_State));
	if (!state)
	{
		return 0;
	}

	state->sum = 0;
	*context = state;

	return 1;
}

static void RFC1071_Update
(
	void* context
	, const struct VPS_Data* raw_data
)
{
	struct RFC1071_State* state = context;
	VPS_TYPE_SIZE i;

	if (!state || !raw_data || !raw_data->bytes)
	{
		return;
	}

	for (i = 0; i < raw_data->size; ++i)
	{
		if (i & 1)
		{
			// Odd byte: low byte of a 16-bit word.
			state->sum += raw_data->bytes[i];
		}
		else
		{
			// Even byte: high byte of a 16-bit word.
			state->sum += (VPS_TYPE_32U)raw_data->bytes[i] << 8;
		}
	}
}

static char RFC1071_Finalize
(
	void* context
	, struct VPS_Data* out_checksum
)
{
	struct RFC1071_State* state = context;
	VPS_TYPE_32U sum;
	VPS_TYPE_16U result;

	if (!state || !out_checksum)
	{
		return 0;
	}

	// Fold 32-bit sum to 16 bits.
	sum = state->sum;
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	result = (VPS_TYPE_16U)~sum;

	out_checksum->bytes = calloc(1, 2);
	if (!out_checksum->bytes) return 0;
	out_checksum->size = 2;
	out_checksum->limit = 2;
	out_checksum->own_bytes = 1;

	// Store big-endian.
	out_checksum->bytes[0] = (unsigned char)(result >> 8);
	out_checksum->bytes[1] = (unsigned char)(result & 0xFF);

	return 1;
}

static void RFC1071_ReleaseContext
(
	void* context
)
{
	free(context);
}

static struct IFF_ChecksumAlgorithm RFC1071_ALGORITHM =
{
	"RFC-1071",
	2,
	RFC1071_CreateContext,
	RFC1071_Update,
	RFC1071_Finalize,
	RFC1071_ReleaseContext
};

const struct IFF_ChecksumAlgorithm* IFF_Checksum_RFC1071_Get(void)
{
	return &RFC1071_ALGORITHM;
}
