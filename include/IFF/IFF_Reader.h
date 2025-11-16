struct IFF_Reader
{
	struct VPS_Decoder *base256_decoder;
	struct VPS_StreamReader *stream_reader;
	struct VPS_Data *data_buffer;
	struct VPS_DataReader *data_reader;
};

char IFF_Reader_Allocate
(
	struct IFF_Reader **item
);

char IFF_Reader_Construct
(
	struct IFF_Reader *item
	, int fh
);

char IFF_Reader_Deconstruct
(
	struct IFF_Reader *item
);

char IFF_Reader_Release
(
	struct IFF_Reader *item
);

char IFF_Reader_ReadTag
(
	struct IFF_Reader *reader
	, enum IFF_Header_TagSizing tag_sizing
	, struct IFF_Tag *tag
);

char IFF_Reader_ReadSize
(
	struct IFF_Reader *reader
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, VPS_TYPE_64U *size
);

char IFF_Reader_ReadData
(
	struct IFF_Reader *reader
	, VPS_TYPE_64U size
	, struct VPS_Data **out_data
);

char IFF_Reader_Seek
(
	struct IFF_Reader *reader
	, VPS_TYPE_64S offset
);
