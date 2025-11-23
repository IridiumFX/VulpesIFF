/**
 * @brief Defines the set of actions a directive can request from the parser.
 * @details These represent the "Ok" variants of a directive processing result.
 */
enum IFF_Directive_Action
{
	// Default action: do nothing and continue parsing.
	IFF_ACTION_CONTINUE,
	// Stop parsing the current scope (e.g., for ' END').
	IFF_ACTION_STOP_SCOPE,
	// Update the active parsing flags (for ' IFF').
	IFF_ACTION_UPDATE_FLAGS,
	// Start a new checksum span (for ' CHK').
	IFF_ACTION_START_CHECKSUM,
	// End the current checksum span and verify (for ' SUM').
	IFF_ACTION_END_CHECKSUM,
	// Halt all parsing due to a critical, unrecoverable error.
	IFF_ACTION_HALT
};

/**
 * @brief Defines the set of errors a directive processor can report.
 */
enum IFF_Directive_Error
{
	// The directive's data payload is malformed or invalid.
	IFF_ERROR_MALFORMED_DATA,
	// The directive requests a feature this host cannot support (e.g., 64-bit on a 32-bit build).
	IFF_ERROR_UNSUPPORTED_FEATURE
};

union IFF_Directive_Payload
{
	union IFF_Header_Flags new_flags;
	struct VPS_Set* checksum_identifiers;
	struct VPS_Dictionary* expected_checksums;
	enum IFF_Directive_Error error_code;
};

/**
 * @brief Represents the result of processing a directive chunk.
 * @details This is a "command" object returned by a directive processor.
 *          The main parser loop inspects the `action` field and then accesses
 *          the appropriate member of the `data` union to execute the command.
 */
struct IFF_DirectiveResult
{
	enum IFF_Directive_Action action;
	union IFF_Directive_Payload payload;
};
