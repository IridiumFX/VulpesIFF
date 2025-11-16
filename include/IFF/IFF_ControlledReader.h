struct IFF_ControlledReader
{
	struct VPS_StreamReader *stream_reader;
	struct VPS_Data *data_buffer;
	struct IFF_Reader *reader;
	struct VPS_Decoder *decoder;
};

char IFF_ControlledReader_Allocate
(
	struct IFF_ControlledReader **item
);

char IFF_ControlledReader_Construct
(
	struct IFF_ControlledReader *item
	, struct IFF_Reader *reader
);

char IFF_ControlledReader_Deconstruct
(
	struct IFF_ControlledReader *item
);

char IFF_ControlledReader_Release
(
	struct IFF_ControlledReader *item
);

char IFF_ControlledReader_ReadTag
(
	struct IFF_ControlledReader *reader
	, enum IFF_Header_TagSizing tag_sizing
	, struct IFF_Tag *tag
);

char IFF_ControlledReader_ReadSize
(
	struct IFF_ControlledReader *reader
	, enum IFF_Header_Sizing sizing
	, enum IFF_Header_Flag_Typing typing
	, enum IFF_Header_Encoding
	, VPS_TYPE_64U *size
);

char IFF_ControlledReader_ReadData
(
	struct IFF_ControlledReader *reader
	, enum IFF_Header_Encoding encoding
	, VPS_TYPE_64U size
	, struct VPS_Data **out_data
);

char IFF_ControlledReader_Seek
(
	struct IFF_ControlledReader *reader
	, VPS_TYPE_64S offset
);
