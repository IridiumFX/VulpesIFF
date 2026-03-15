#pragma once

struct IFF_Parser_Factory;

/**
 * @brief Registers ILBM form and chunk decoders with a parser factory.
 *
 * Registers:
 *   Form decoder for "ILBM"
 *   Chunk decoders for (ILBM, BMHD), (ILBM, CMAP), (ILBM, BODY), (ILBM, CAMG)
 *
 * After scanning, the parser's final entity will be a VPS_BitMap* (RGBA8888).
 *
 * @param factory The parser factory to register with.
 * @return 1 on success, 0 on failure.
 */
char ILBM_RegisterDecoders(struct IFF_Parser_Factory* factory);
