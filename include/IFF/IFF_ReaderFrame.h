struct IFF_Reader;

struct IFF_ReaderFrame
{
	struct IFF_Reader *reader;
	int file_handle;
	char iff85_locked;
};

char IFF_ReaderFrame_Allocate
(
	struct IFF_ReaderFrame **item
);

char IFF_ReaderFrame_Construct
(
	struct IFF_ReaderFrame *item
	, struct IFF_Reader *reader
	, int file_handle
	, char iff85_locked
);

char IFF_ReaderFrame_Deconstruct
(
	struct IFF_ReaderFrame *item
);

char IFF_ReaderFrame_Release
(
	struct IFF_ReaderFrame *item
);
