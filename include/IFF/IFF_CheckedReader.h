struct IFF_CheckedReader
{
	struct VPS_StreamReader *stream_reader;
	struct VPS_Data *data_buffer;
	struct IFF_ControlledReader *reader;
	struct VPS_Decoder *decoder;
};

char IFF_CheckedReader_Allocate
(
	struct IFF_CheckedReader **item
);

char IFF_CheckedReader_Construct
(
	struct IFF_CheckedReader *item
	, struct IFF_ControlledReader *reader
);

char IFF_CheckedReader_Deconstruct
(
	struct IFF_CheckedReader *item
);

char IFF_CheckedReader_Release
(
	struct IFF_CheckedReader *item
);

char IFF_CheckedReader_ReadTag
(
	struct IFF_CheckedReader *reader
	, enum IFF_Header_TagSizing tag_sizing
	, struct IFF_Tag *tag
);

char IFF_CheckedReader_ReadSize
(
	struct IFF_CheckedReader *reader
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, enum IFF_Header_Encoding
	, VPS_TYPE_64U *size
);

char IFF_CheckedReader_ReadData
(
	struct IFF_CheckedReader *reader
	, enum IFF_Header_Encoding encoding
	, VPS_TYPE_64U size
	, struct VPS_Data **out_data
);

char IFF_CheckedReader_Seek
(
	struct IFF_CheckedReader *reader
	, VPS_TYPE_64S offset
);
