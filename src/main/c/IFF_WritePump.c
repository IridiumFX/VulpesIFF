#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataWriter.h>
#include <vulpes/VPS_StreamWriter.h>

#include <IFF/IFF_WritePump.h>

IFF_TYPE_RESULT IFF_WritePump_Allocate
(
	struct IFF_WritePump **item
)
{
	struct IFF_WritePump *pump;

	if (!item)
	{
		return IFF_FAIL;
	}

	pump = calloc(1, sizeof(struct IFF_WritePump));
	if (!pump)
	{
		return IFF_FAIL;
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

	return IFF_OK;

cleanup:

	IFF_WritePump_Release(pump);

	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_WritePump_Construct
(
	struct IFF_WritePump *item
	, int file_handle
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	// Release the memory-mode members — a populated data_writer is the
	// discriminator the write paths use to select memory mode.
	VPS_DataWriter_Release(item->data_writer);
	item->data_writer = 0;
	VPS_Data_Release(item->output_buffer);
	item->output_buffer = 0;

	if (!VPS_StreamWriter_Construct(item->stream_writer, file_handle))
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_ConstructToData
(
	struct IFF_WritePump *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	// Release the stream writer — not needed for memory mode.
	VPS_StreamWriter_Release(item->stream_writer);
	item->stream_writer = 0;

	// Construct the output buffer.
	if (!VPS_Data_Construct(item->output_buffer))
	{
		return IFF_FAIL;
	}

	// Construct the data writer targeting the output buffer.
	if (!VPS_DataWriter_Construct(item->data_writer, item->output_buffer))
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_GetOutputData
(
	struct IFF_WritePump *pump
	, struct VPS_Data **out_data
)
{
	if (!pump || !out_data)
	{
		return IFF_FAIL;
	}

	if (!pump->data_writer)
	{
		return IFF_FAIL; // Not in memory mode
	}

	*out_data = pump->output_buffer;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_Deconstruct
(
	struct IFF_WritePump *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	VPS_DataWriter_Deconstruct(item->data_writer);
	VPS_Data_Deconstruct(item->output_buffer);
	VPS_StreamWriter_Deconstruct(item->stream_writer);

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_Release
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

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_WriteRaw
(
	struct IFF_WritePump *pump
	, const unsigned char *data
	, VPS_TYPE_SIZE size
)
{
	if (!pump || (!data && size > 0))
	{
		return IFF_FAIL;
	}

	if (pump->data_writer)
	{
		if (!VPS_DataWriter_WriteBytes(pump->data_writer, data, size))
		{
			return IFF_FAIL;
		}

		return IFF_OK;
	}

	if (!VPS_StreamWriter_Write(pump->stream_writer, data, size))
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_WriteData
(
	struct IFF_WritePump *pump
	, const struct VPS_Data *data
)
{
	if (!pump || !data)
	{
		return IFF_FAIL;
	}

	if (pump->data_writer)
	{
		if
		(
			!VPS_DataWriter_WriteBytes
			(
				pump->data_writer
				, data->bytes
				, data->limit
			)
		)
		{
			return IFF_FAIL;
		}

		return IFF_OK;
	}

	if
	(
		!VPS_StreamWriter_Write
		(
			pump->stream_writer
			, data->bytes
			, data->limit
		)
	)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_WritePump_Flush
(
	struct IFF_WritePump *pump
)
{
	if (!pump)
	{
		return IFF_FAIL;
	}

	if (pump->data_writer)
	{
		return IFF_OK; // No-op in memory mode
	}

	if (!VPS_StreamWriter_Flush(pump->stream_writer))
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}
