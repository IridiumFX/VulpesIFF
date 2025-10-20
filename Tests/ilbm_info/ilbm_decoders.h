#pragma once

struct IFF_Parser;

/**
 * @brief Registers all the decoders required to parse an ILBM file.
 * @param parser The IFF_Parser instance to register the decoders with.
 * @return 1 on success, 0 on failure.
 */
char register_ilbm_decoders(struct IFF_Parser *parser);
