#pragma once

struct IFF_Parser_Session;
struct IFF_Tag;
struct IFF_ContextualData;

/**
 * @brief A decoder-facing view into the parser's session state.
 * @details This struct is passed to chunk and form decoders so they can
 *          query properties and access configuration without coupling
 *          directly to the parser's internal session structure.
 */
struct IFF_Parser_State
{
	struct IFF_Parser_Session *session;
};

/**
 * @brief Searches for a property in the current scope hierarchy.
 * @details Delegates to IFF_Parser_Session_FindProp. First searches
 *          for a property specific to the current FORM's type, then
 *          falls back to a wildcard search.
 */
char IFF_Parser_State_FindProp
(
	struct IFF_Parser_State *state
	, struct IFF_Tag *prop_tag
	, struct IFF_ContextualData **out_prop_data
);

/**
 * @brief Retrieves the application context attached to the session.
 * @details The context is set by the application on the session before
 *          scanning (session->user_data); decoders use it to reach their
 *          sink without global state. out_user_data receives NULL when no
 *          context was attached.
 */
char IFF_Parser_State_GetUserData
(
	struct IFF_Parser_State *state
	, void **out_user_data
);
