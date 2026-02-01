#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Decoder.h>
#include <vulpes/VPS_Decoder_Base256.h>
#include <vulpes/VPS_StreamReader.h>
#include <vulpes/VPS_DataReader.h>

#include <IFF/IFF_DataPump.h>

char IFF_DataPump_Allocate
(
	struct IFF_DataPump **item
)
{
	struct IFF_DataPump *pump;

	if (!item)
	{
		return 0;
	}

	pump = calloc
	(
		1
		, sizeof(struct IFF_DataPump)
	);
	if (!pump)
	{
		return 0;
	}

	VPS_Decoder_Allocate
	(
		&pump->base256_decoder
	);
	if (!pump->base256_decoder)
	{
		goto cleanup;
	}

	VPS_Data_Allocate
	(
		&pump->data_buffer
		, 128
		, 0
	);
	if (!pump->data_buffer)
	{
		goto cleanup;
	}

	VPS_DataReader_Allocate
	(
		&pump->data_reader
	);
	if (!pump->data_reader)
	{
		goto cleanup;
	}

	VPS_StreamReader_Allocate
	(
		&pump->stream_reader
	);
	if (!pump->stream_reader)
	{
		goto cleanup;
	}

	*item = pump;

	return 1;

cleanup:

	IFF_DataPump_Release
	(
		pump
	);

	return 0;
}

char IFF_DataPump_Construct
(
	struct IFF_DataPump *item
	, int fh
)
{
	if (!item)
	{
		return 0;
	}

	// Construct the I/O pipeline that this reader will manage.
	if
	(
		!VPS_Decoder_Base256_Construct
		(
			item->base256_decoder
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_Data_Construct
		(
			item->data_buffer
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_DataReader_Construct
		(
			item->data_reader
			, item->data_buffer
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_StreamReader_Construct
		(
			item->stream_reader
			, item->data_buffer
			, fh
			, 0 // Let the stream reader create its own raw buffer
			, 0
		)
	)
	{
		return 0;
	}

	return 1;
}

char IFF_DataPump_ConstructFromData
(
	struct IFF_DataPump *item
	, const struct VPS_Data *source
)
{
	if (!item || !source)
	{
		return 0;
	}

	// Release the stream reader — not needed for memory mode.
	VPS_StreamReader_Release(item->stream_reader);
	item->stream_reader = 0;

	// Resize the data buffer to fit the source data.
	if (!VPS_Data_Resize(item->data_buffer, source->limit))
	{
		return 0;
	}

	if (!VPS_Data_Construct(item->data_buffer))
	{
		return 0;
	}

	// Copy source bytes into the data buffer.
	memcpy
	(
		item->data_buffer->bytes
		, source->bytes
		, source->limit
	);
	item->data_buffer->limit = source->limit;

	// Construct the data reader over the filled buffer.
	if
	(
		!VPS_DataReader_Construct
		(
			item->data_reader
			, item->data_buffer
		)
	)
	{
		return 0;
	}

	// Construct the base256 decoder for API consistency.
	if
	(
		!VPS_Decoder_Base256_Construct
		(
			item->base256_decoder
		)
	)
	{
		return 0;
	}

	return 1;
}

char IFF_DataPump_Deconstruct
(
	struct IFF_DataPump *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_StreamReader_Deconstruct
	(
		item->stream_reader
	);

	VPS_DataReader_Deconstruct
	(
		item->data_reader
	);

	VPS_Data_Deconstruct
	(
		item->data_buffer
	);

	VPS_Decoder_Deconstruct
	(
		item->base256_decoder
	);

	return 1;
}

char IFF_DataPump_Release
(
	struct IFF_DataPump *item
)
{
	if (item)
	{
		IFF_DataPump_Deconstruct
		(
			item
		);

		VPS_StreamReader_Release
		(
			item->stream_reader
		);

		VPS_DataReader_Release
		(
			item->data_reader
		);

		VPS_Data_Release
		(
			item->data_buffer
		);

		VPS_Decoder_Release
		(
			item->base256_decoder
		);

		free
		(
			item
		);
	}
	return 1;
}

static char IFF_DataPump_PRIVATE_EnsureDataAvailable
(
	struct IFF_DataPump *pump,
	VPS_TYPE_SIZE bytes_needed
)
{
	VPS_TYPE_SIZE bytes_available = 0;

	VPS_Data_Compact(pump->data_buffer);

	if (pump->data_buffer->limit >= bytes_needed)
	{
		return 1;
	}

	if (!pump->stream_reader)
	{
		return 0; // Memory mode: no more data available
	}

	if
	(
		!VPS_StreamReader_Read
		(
			pump->stream_reader
			, bytes_needed
			, 0
			, 0
			, 0
			, &bytes_available
			, pump->base256_decoder
			, 0
		)
	)
	{
		return 0; // Read error
	}

	return (char)(bytes_available >= bytes_needed);
}

char IFF_DataPump_ReadRaw
(
	struct IFF_DataPump *pump
	, VPS_TYPE_SIZE bytes_to_read
	, struct VPS_Data **out_data
)
{
	if (!pump || !out_data || bytes_to_read == 0)
	{
		return 0;
	}

	if (!IFF_DataPump_PRIVATE_EnsureDataAvailable(pump, bytes_to_read))
	{
		return 0;
	}

	if
	(
		!VPS_Data_Clone
		(
			out_data
			, pump->data_buffer
			, pump->data_buffer->position
			, bytes_to_read
		)
	)
	{
		return 0;
	}

	if
	(
		!VPS_Data_Seek
		(
			pump->data_buffer
			, bytes_to_read
			, SEEK_CUR
		)
	)
	{
		VPS_Data_Release(*out_data);
		*out_data = 0;

		return 0;
	}

	return 1;
}

char IFF_DataPump_Skip
(
	struct IFF_DataPump *pump
	, VPS_TYPE_SIZE bytes_to_skip
)
{
	if (!pump)
	{
		return 0;
	}

	if (bytes_to_skip == 0)
	{
		return 1;
	}

	if (!IFF_DataPump_PRIVATE_EnsureDataAvailable(pump, bytes_to_skip))
	{
		return 0;
	}

	return VPS_Data_Seek
	(
		pump->data_buffer
		, bytes_to_skip
		, SEEK_CUR
	);
}
