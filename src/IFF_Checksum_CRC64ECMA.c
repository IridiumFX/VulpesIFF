#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_Checksum_CRC64ECMA.h>

/**
 * CRC-64/ECMA-182: polynomial 0x42F0E1EBA9EA3693.
 * 64-bit output, stored big-endian.
 *
 * Uses a 256-entry lookup table generated from the polynomial directly
 * (non-reflected, MSB-first).
 */

static VPS_TYPE_64U CRC64_TABLE[256];
static char CRC64_TABLE_INITIALIZED = 0;

static void CRC64_InitTable(void)
{
	VPS_TYPE_64U i;
	VPS_TYPE_64U j;

	if (CRC64_TABLE_INITIALIZED)
	{
		return;
	}

	for (i = 0; i < 256; ++i)
	{
		VPS_TYPE_64U crc = i << 56;

		for (j = 0; j < 8; ++j)
		{
			if (crc & ((VPS_TYPE_64U)1 << 63))
			{
				crc = (crc << 1) ^ (VPS_TYPE_64U)0x42F0E1EBA9EA3693ULL;
			}
			else
			{
				crc <<= 1;
			}
		}

		CRC64_TABLE[i] = crc;
	}

	CRC64_TABLE_INITIALIZED = 1;
}

struct CRC64_State
{
	VPS_TYPE_64U crc;
};

static char CRC64_CreateContext
(
	void** context
)
{
	struct CRC64_State* state;

	if (!context)
	{
		return 0;
	}

	CRC64_InitTable();

	state = calloc(1, sizeof(struct CRC64_State));
	if (!state)
	{
		return 0;
	}

	state->crc = 0;
	*context = state;

	return 1;
}

static void CRC64_Update
(
	void* context
	, const struct VPS_Data* raw_data
)
{
	struct CRC64_State* state = context;
	VPS_TYPE_SIZE i;

	if (!state || !raw_data || !raw_data->bytes)
	{
		return;
	}

	for (i = 0; i < raw_data->size; ++i)
	{
		VPS_TYPE_8U index = (VPS_TYPE_8U)((state->crc >> 56) ^ raw_data->bytes[i]);
		state->crc = CRC64_TABLE[index] ^ (state->crc << 8);
	}
}

static char CRC64_Finalize
(
	void* context
	, struct VPS_Data* out_checksum
)
{
	struct CRC64_State* state = context;
	VPS_TYPE_64U final_crc;

	if (!state || !out_checksum)
	{
		return 0;
	}

	final_crc = state->crc;

	out_checksum->bytes = calloc(1, 8);
	if (!out_checksum->bytes) return 0;
	out_checksum->size = 8;
	out_checksum->limit = 8;
	out_checksum->own_bytes = 1;

	// Store big-endian.
	out_checksum->bytes[0] = (unsigned char)((final_crc >> 56) & 0xFF);
	out_checksum->bytes[1] = (unsigned char)((final_crc >> 48) & 0xFF);
	out_checksum->bytes[2] = (unsigned char)((final_crc >> 40) & 0xFF);
	out_checksum->bytes[3] = (unsigned char)((final_crc >> 32) & 0xFF);
	out_checksum->bytes[4] = (unsigned char)((final_crc >> 24) & 0xFF);
	out_checksum->bytes[5] = (unsigned char)((final_crc >> 16) & 0xFF);
	out_checksum->bytes[6] = (unsigned char)((final_crc >> 8) & 0xFF);
	out_checksum->bytes[7] = (unsigned char)(final_crc & 0xFF);

	return 1;
}

static void CRC64_ReleaseContext
(
	void* context
)
{
	free(context);
}

static struct IFF_ChecksumAlgorithm CRC64_ALGORITHM =
{
	"CRC64-ECMA",
	8,
	CRC64_CreateContext,
	CRC64_Update,
	CRC64_Finalize,
	CRC64_ReleaseContext
};

const struct IFF_ChecksumAlgorithm* IFF_Checksum_CRC64ECMA_Get(void)
{
	return &CRC64_ALGORITHM;
}
