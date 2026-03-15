#pragma once

struct IFF_Parser_Factory;

/**
 * @brief Registers 8SVX form and chunk decoders with a parser factory.
 *
 * Registers:
 *   Form decoder for "8SVX"
 *   Chunk decoders for (8SVX, VHDR), (8SVX, BODY)
 *
 * After scanning, the parser's final entity will be an SVX8_Result*.
 *
 * @param factory The parser factory to register with.
 * @return 1 on success, 0 on failure.
 */
char SVX8_RegisterDecoders(struct IFF_Parser_Factory* factory);

/**
 * @brief Result produced by the 8SVX FormDecoder.
 * Contains the voice header and raw 8-bit PCM sample data.
 * Caller must free this struct and the samples VPS_Data.
 */
struct SVX8_Result
{
	struct SVX8_VoiceHeader vhdr;
	struct VPS_Data* samples; /* Signed 8-bit PCM. */
};
