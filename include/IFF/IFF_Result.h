#pragma once

/**
 * @brief The canonical status type returned by VulpesIFF functions.
 * @details IFF_OK (0) means success. Any non-zero value is a failure and
 *          carries the source line that raised it, so a failing call can be
 *          traced back to its origin without a debugger.
 *
 *          Note that this is the inverse of the VulpesCore convention, where
 *          1 means success and 0 means failure. See "VulpesCore boundary"
 *          below for how the two meet.
 */
typedef unsigned long IFF_TYPE_RESULT;

/**
 * @brief Success.
 */
#define IFF_OK ((IFF_TYPE_RESULT)0)

/**
 * @brief Failure, tagged with the line that raised it.
 * @details Always raise failures through this macro rather than returning a
 *          literal. Doing so keeps the encoding in one place: should the
 *          diagnostic ever need to widen to file+line, only this definition
 *          changes and no call site moves.
 */
#define IFF_FAIL ((IFF_TYPE_RESULT)__LINE__)

/*
 * Propagating failures
 * --------------------
 * When forwarding a failure from a nested IFF call, return the result you
 * received rather than raising a fresh IFF_FAIL. The original line is the
 * useful one; overwriting it discards the root cause.
 *
 *     result = IFF_Reader_ReadTag(reader, tag_sizing, &tag);
 *     if (result)
 *     {
 *         return result;
 *     }
 *
 * Crossing the VulpesCore boundary
 * --------------------------------
 * VulpesCore keeps the boolean convention (1 = success). A VPS_ call is
 * therefore tested for truth, and its failure is re-raised as an IFF failure
 * at the point of the call:
 *
 *     if (!VPS_DataWriter_WriteBytes(dw, buf, size_length))
 *     {
 *         return IFF_FAIL;
 *     }
 *
 *     return IFF_OK;
 *
 * In the other direction, IFF functions registered into VulpesCore callback
 * slots (dictionary hash/compare, list and dictionary release hooks) are
 * wrapped in a PRIVATE_*_VPSAdapter shim that translates the polarity back.
 * VulpesCore checks the boolean result of hash and key_compare, so a raw cast
 * would fail every lookup silently.
 *
 * What does NOT use this type
 * ---------------------------
 * Predicates answer a question rather than report a status, and keep the
 * plain char/boolean form:
 *
 *     IFF_Parser_Session_IsActive
 *     IFF_Parser_Session_IsBoundaryOpen
 *     IFF_Reader_IsActive
 *     IFF_Parser_Session_FindProp    (a lookup miss is a normal outcome)
 *     IFF_Parser_State_FindProp      (likewise)
 *
 * Boolean out-parameters are likewise unrelated to the return channel and
 * stay char: char *out_done, char *out_scope_ended.
 */
