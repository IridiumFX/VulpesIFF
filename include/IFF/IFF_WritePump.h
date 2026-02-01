/**
 * @brief The lowest-level write I/O layer, inverse of IFF_DataPump.
 * @details Wraps a VPS_StreamWriter to provide buffered output to a file handle.
 */
struct IFF_WritePump
{
	struct VPS_StreamWriter *stream_writer;
	struct VPS_Data *output_buffer;
	struct VPS_DataWriter *data_writer;
};

char IFF_WritePump_Allocate
(
	struct IFF_WritePump **item
);

char IFF_WritePump_Construct
(
	struct IFF_WritePump *item
	, int file_handle
);

char IFF_WritePump_ConstructToData
(
	struct IFF_WritePump *item
);

char IFF_WritePump_GetOutputData
(
	struct IFF_WritePump *pump
	, struct VPS_Data **out_data
);

char IFF_WritePump_Deconstruct
(
	struct IFF_WritePump *item
);

char IFF_WritePump_Release
(
	struct IFF_WritePump *item
);

char IFF_WritePump_WriteRaw
(
	struct IFF_WritePump *pump
	, const unsigned char *data
	, VPS_TYPE_SIZE size
);

char IFF_WritePump_WriteData
(
	struct IFF_WritePump *pump
	, const struct VPS_Data *data
);

char IFF_WritePump_Flush
(
	struct IFF_WritePump *pump
);
