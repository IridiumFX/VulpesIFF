struct IFF_DataPump
{
	struct VPS_Decoder *base256_decoder;
	struct VPS_StreamReader *stream_reader;
	struct VPS_Data *data_buffer;
	struct VPS_DataReader *data_reader;
};

char IFF_DataPump_Allocate
(
	struct IFF_DataPump **item
);

char IFF_DataPump_Construct
(
	struct IFF_DataPump *item
	, int fh
);

char IFF_DataPump_Deconstruct
(
	struct IFF_DataPump *item
);

char IFF_DataPump_Release
(
	struct IFF_DataPump *item
);

char IFF_DataPump_ReadRaw
(
	struct IFF_DataPump *pump
	, VPS_TYPE_SIZE bytes_to_read
	, struct VPS_Data **out_data
);

char IFF_DataPump_Skip
(
	struct IFF_DataPump *pump
	, VPS_TYPE_SIZE bytes_to_read
);
