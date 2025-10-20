/**
 * @brief A high-level reader for consuming IFF structural elements from a stream.
 *
 * This component encapsulates the entire I/O pipeline and provides a simple
 * API to read IFF-specific building blocks like tags and correctly-sized chunk
 * length fields, respecting the active header flags of the parsing session.
 */
struct IFF_Reader
{
	struct IFF_Parser_State *parse_state; // Back-link to get header flags
	struct VPS_StreamReader *stream_reader;
	struct VPS_Data *data_buffer;
	struct VPS_DataReader *data_reader;
	struct VPS_Decoder *decoder;
};

char IFF_Reader_Allocate
(
	struct IFF_Reader **item
);

char IFF_Reader_Construct
(
	struct IFF_Reader *item
	, int fh
	, struct IFF_Parser_State *parse_state
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
	, struct IFF_Tag *tag
);

char IFF_Reader_ReadSize
(
	struct IFF_Reader *reader
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
