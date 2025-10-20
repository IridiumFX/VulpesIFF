enum IFF_Header_Version
{
	IFF_Header_Version_1985 = 0,
	IFF_Header_Version_2025 = 40	// Years after original spec epoch
};

// --- Flag Enumerations ---
// The IFF-2025 header is controlled by a set of bitfields. By using specific
// enums for each field, we gain significant type safety and clarity.
// The default value for all flags is 0, which correctly corresponds to the
// classic IFF-85 standard (32-bit, big-endian, padded, blob-mode, one-shot).

enum IFF_Header_Sizing
{
	// Default
	IFF_Header_Sizing_32 = 0,
	IFF_Header_Sizing_64 = 1,
	// For smaller devices (15 == -1 in a signed nibble)
	IFF_Header_Sizing_16 = 15
};

enum IFF_Header_TagSizing
{
	// Default
	IFF_Header_TagSizing_4 = 0,
	IFF_Header_TagSizing_8 = 1,
	IFF_Header_TagSizing_16 = 2
};

enum IFF_Header_Operating
{
	// Standard mode: all chunks, including containers, have a declared size.
	IFF_Header_Operating_BLOBBED = 0,
	// Progressive mode: Containers (LIST/CAT /FORM) have no size and are terminated by a special " END" directive.
	IFF_Header_Operating_PROGRESSIVE = 1
};

enum IFF_Header_Encoding
{
	IFF_Header_Encoding_BASE_256 = 0
};

enum IFF_Header_Flag_Typing
{
	IFF_Header_Flag_Typing_DEFAULT = 0,        // Big-endian, signed sizes
	IFF_Header_Flag_Typing_UNSIGNED_SIZES = 1, // Bit 0
	IFF_Header_Flag_Typing_LITTLE_ENDIAN = 2   // Bit 1 (Applies to sizes only. Tags are invariants)
};

enum IFF_Header_Flag_Structuring
{
	IFF_Header_Flag_Structuring_DEFAULT = 0,      // Pad odd-length chunks with a byte
	IFF_Header_Flag_Structuring_NO_PADDING = 1,   // Bit 0
	IFF_Header_Flag_Structuring_SHARDING = 2      // Bit 1: "    " Chunks are processed as continuation directives
};

struct IFF_Header_Flags_Fields
{
	// Matches the layout in Appendix A of the IFF-2025 Specification
	enum IFF_Header_Sizing sizing               : 8; // Bits 0-7
	enum IFF_Header_TagSizing tag_sizing        : 8; // Bits 8-15
	enum IFF_Header_Operating operating         : 8; // Bits 16-23
	enum IFF_Header_Encoding encoding			: 8; // Bits 24-31
	enum IFF_Header_Flag_Typing typing          : 8; // Bits 32-39
	enum IFF_Header_Flag_Structuring structuring: 8; // Bits 40-47
	VPS_TYPE_16U reserved						: 16; // Bits 48-63
};

union IFF_Header_Flags
{
    VPS_TYPE_64U as_int;
    struct IFF_Header_Flags_Fields as_fields;
};

/** @brief The structure of the IFF-2025 header directive (" IFF"). */
struct IFF_Header
{
	enum IFF_Header_Version version;
	VPS_TYPE_16U revision;
	union IFF_Header_Flags flags;
};

extern const union IFF_Header_Flags IFF_HEADER_FLAGS_1985;

VPS_TYPE_8U IFF_Header_Flags_GetTagLength
(
	union IFF_Header_Flags flags
);

VPS_TYPE_8U IFF_Header_Flags_GetSizeLength
(
	union IFF_Header_Flags flags
);
