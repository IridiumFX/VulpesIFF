#include "SVX8/SVX8_Decompression.h"

/*
 * Standard Fibonacci delta table for 8SVX compression.
 * Each 4-bit nibble (0-15) indexes into this table to get a delta value
 * that is added to the running sample accumulator.
 */
static const signed char s_fibonacci_table[16] =
{
	-34, -21, -13, -8, -5, -3, -2, -1,
	  0,   1,   2,  3,  5,  8, 13, 21
};

char SVX8_DecompressFibonacciDelta
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	VPS_TYPE_SIZE src_size,
	VPS_TYPE_SIZE num_samples
)
{
	if (!dest || !src || src_size < 2) return 0;

	/* First two bytes are the initial value (big-endian signed 16-bit),
	   but in practice only the high byte is used as the initial sample. */
	signed char accumulator = (signed char)src[0];
	VPS_TYPE_SIZE si = 2; /* Skip the 2-byte header. */
	VPS_TYPE_SIZE di = 0;

	while (si < src_size && di < num_samples)
	{
		VPS_TYPE_8U byte = src[si++];

		/* High nibble first. */
		signed char delta = s_fibonacci_table[(byte >> 4) & 0x0F];
		accumulator += delta;
		if (di < num_samples) dest[di++] = (VPS_TYPE_8U)accumulator;

		/* Low nibble. */
		delta = s_fibonacci_table[byte & 0x0F];
		accumulator += delta;
		if (di < num_samples) dest[di++] = (VPS_TYPE_8U)accumulator;
	}

	return 1;
}
