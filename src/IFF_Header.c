#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Header.h>

const union IFF_Header_Flags IFF_HEADER_FLAGS_1985 = { 0 };

VPS_TYPE_8U IFF_Header_Flags_GetTagLength
(
	enum IFF_Header_TagSizing tag_sizing
)
{
	switch (tag_sizing)
	{
		case IFF_Header_TagSizing_8:
			return 8;
		case IFF_Header_TagSizing_16:
			return 16;
		default: // IFF_Header_TagSizing_4
			return 4;
	}
}

VPS_TYPE_8U IFF_Header_Flags_GetSizeLength
(
	enum IFF_Header_Sizing sizing
)
{
	switch (sizing)
	{
		case IFF_Header_Sizing_16:
			return 2;
		case IFF_Header_Sizing_64:
			return 8;
		default: // IFF_Header_Sizing_32
			return 4;
	}
}
