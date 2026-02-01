#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataWriter.h>
#include <vulpes/VPS_StreamWriter.h>

#include <IFF/IFF_WritePump.h>

char IFF_WritePump_Allocate
(
	struct IFF_WritePump **item
)
{
	struct IFF_WritePump *pump;

	if (!item)
	{
		return 0;
	}

	pump = calloc(1, sizeof(struct IFF_WritePump));
	if (!pump)
	{
		return 0;
	}

	if (!VPS_StreamWriter_Allocate(&pump->stream_writer))
	{
		goto cleanup;
	}

	if (!VPS_Data_Allocate(&pump->output_buffer, 256, 0))
	{
		goto cleanup;
	}

	if (!VPS_DataWriter_Allocate(&pump->data_writer))
	{
		goto cleanup;
	}

	*item = pump;

	return 1;

cleanup:

	IFF_WritePump_Release(pump);

	return 0;
}

char IFF_WritePump_Construct
(
	struct IFF_WritePump *item
	, int file_handle
)
{
	if (!item)
	{
		return 0;
	}

	if (!VPS_StreamWriter_Construct(item->stream_writer, file_handle))
	{
		return 0;
	}

	return 1;
}

char IFF_WritePump_ConstructToData
(
	struct IFF_WritePump *item
)
{
	if (!item)
	{
		return 0;
	}

	// Release the stream writer — not needed for memory mode.
	VPS_StreamWriter_Release(item->stream_writer);
	item->stream_writer = 0;

	// Construct the output buffer.
	if (!VPS_Data_Construct(item->output_buffer))
	{
		return 0;
	}

	// Construct the data writer targeting the output buffer.
	if (!VPS_DataWriter_Construct(item->data_writer, item->output_buffer))
	{
		return 0;
	}

	return 1;
}

char IFF_WritePump_GetOutputData
(
	struct IFF_WritePump *pump
	, struct VPS_Data **out_data
)
{
	if (!pump || !out_data)
	{
		return 0;
	}

	if (!pump->data_writer)
	{
		return 0; // Not in memory mode
	}

	*out_data = pump->output_buffer;

	return 1;
}

char IFF_WritePump_Deconstruct
(
	struct IFF_WritePump *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_DataWriter_Deconstruct(item->data_writer);
	VPS_Data_Deconstruct(item->output_buffer);
	VPS_StreamWriter_Deconstruct(item->stream_writer);

	return 1;
}

char IFF_WritePump_Release
(
	struct IFF_WritePump *item
)
{
	if (item)
	{
		IFF_WritePump_Deconstruct(item);
		VPS_DataWriter_Release(item->data_writer);
		VPS_Data_Release(item->output_buffer);
		VPS_StreamWriter_Release(item->stream_writer);
		free(item);
	}

	return 1;
}

char IFF_WritePump_WriteRaw
(
	struct IFF_WritePump *pump
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	if (!pump || (!data && size > 0))
	{
		return 0;
	}

	if (pump->data_writer)
	{
		return VPS_DataWriter_WriteBytes(pump->data_writer, data, size);
	}

	return VPS_StreamWriter_Write(pump->stream_writer, data, size);
}

char IFF_WritePump_WriteData
(
	struct IFF_WritePump *pump
	, const struct VPS_Data *data
)
{
	if (!pump || !data)
	{
		return 0;
	}

	if (pump->data_writer)
	{
		return VPS_DataWriter_WriteBytes
		(
			pump->data_writer
			, data->bytes
			, data->limit
		);
	}

	return VPS_StreamWriter_Write
	(
		pump->stream_writer
		, data->bytes
		, data->limit
	);
}

char IFF_WritePump_Flush
(
	struct IFF_WritePump *pump
)
{
	if (!pump)
	{
		return 0;
	}

	if (pump->data_writer)
	{
		return 1; // No-op in memory mode
	}

	return VPS_StreamWriter_Flush(pump->stream_writer);
}
