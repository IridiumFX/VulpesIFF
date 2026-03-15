#include <string.h>
#include "ILBM/ILBM_Decompression.h"

char ILBM_DecompressByteRun1
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	VPS_TYPE_SIZE src_size,
	VPS_TYPE_SIZE dest_size
)
{
	if (!dest || !src) return 0;

	VPS_TYPE_SIZE si = 0, di = 0;

	while (si < src_size && di < dest_size)
	{
		signed char c = (signed char)src[si++];

		if (c >= 0)
		{
			/* Literal run: copy next (c + 1) bytes. */
			VPS_TYPE_SIZE n = (VPS_TYPE_SIZE)(c + 1);
			if (si + n > src_size || di + n > dest_size) return 0;
			memcpy(dest + di, src + si, n);
			si += n;
			di += n;
		}
		else if (c > -128)
		{
			/* Replicate run: repeat next byte (-c + 1) times. */
			VPS_TYPE_SIZE n = (VPS_TYPE_SIZE)(-c + 1);
			if (si >= src_size || di + n > dest_size) return 0;
			VPS_TYPE_8U v = src[si++];
			memset(dest + di, v, n);
			di += n;
		}
		/* c == -128: NOP (no operation). */
	}

	return 1;
}
