#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_Checksum_CRC32C.h>

/**
 * CRC-32C (Castagnoli): polynomial 0x1EDC6F41.
 * 32-bit output, stored big-endian.
 *
 * Uses a 256-entry lookup table generated from the reflected polynomial
 * 0x82F63B78 (bit-reversed 0x1EDC6F41).
 */

static VPS_TYPE_32U CRC32C_TABLE[256];
static char CRC32C_TABLE_INITIALIZED = 0;

static void CRC32C_InitTable(void)
{
	VPS_TYPE_32U i;
	VPS_TYPE_32U j;

	if (CRC32C_TABLE_INITIALIZED)
	{
		return;
	}

	for (i = 0; i < 256; ++i)
	{
		VPS_TYPE_32U crc = i;

		for (j = 0; j < 8; ++j)
		{
			if (crc & 1)
			{
				crc = (crc >> 1) ^ 0x82F63B78u;
			}
			else
			{
				crc >>= 1;
			}
		}

		CRC32C_TABLE[i] = crc;
	}

	CRC32C_TABLE_INITIALIZED = 1;
}

struct CRC32C_State
{
	VPS_TYPE_32U crc;
};

static char CRC32C_CreateContext
(
	void** context
)
{
	struct CRC32C_State* state;

	if (!context)
	{
		return 0;
	}

	CRC32C_InitTable();

	state = calloc(1, sizeof(struct CRC32C_State));
	if (!state)
	{
		return 0;
	}

	state->crc = 0xFFFFFFFFu;
	*context = state;

	return 1;
}

static void CRC32C_Update
(
	void* context
	, const struct VPS_Data* raw_data
)
{
	struct CRC32C_State* state = context;
	VPS_TYPE_SIZE i;

	if (!state || !raw_data || !raw_data->bytes)
	{
		return;
	}

	for (i = 0; i < raw_data->size; ++i)
	{
		VPS_TYPE_8U index = (VPS_TYPE_8U)((state->crc ^ raw_data->bytes[i]) & 0xFF);
		state->crc = CRC32C_TABLE[index] ^ (state->crc >> 8);
	}
}

static char CRC32C_Finalize
(
	void* context
	, struct VPS_Data* out_checksum
)
{
	struct CRC32C_State* state = context;
	VPS_TYPE_32U final_crc;

	if (!state || !out_checksum)
	{
		return 0;
	}

	final_crc = state->crc ^ 0xFFFFFFFFu;

	out_checksum->bytes = calloc(1, 4);
	if (!out_checksum->bytes) return 0;
	out_checksum->size = 4;
	out_checksum->limit = 4;
	out_checksum->own_bytes = 1;

	// Store big-endian.
	out_checksum->bytes[0] = (unsigned char)((final_crc >> 24) & 0xFF);
	out_checksum->bytes[1] = (unsigned char)((final_crc >> 16) & 0xFF);
	out_checksum->bytes[2] = (unsigned char)((final_crc >> 8) & 0xFF);
	out_checksum->bytes[3] = (unsigned char)(final_crc & 0xFF);

	return 1;
}

static void CRC32C_ReleaseContext
(
	void* context
)
{
	free(context);
}

static struct IFF_ChecksumAlgorithm CRC32C_ALGORITHM =
{
	"CRC-32C",
	4,
	CRC32C_CreateContext,
	CRC32C_Update,
	CRC32C_Finalize,
	CRC32C_ReleaseContext
};

const struct IFF_ChecksumAlgorithm* IFF_Checksum_CRC32C_Get(void)
{
	return &CRC32C_ALGORITHM;
}
