/**
 * Message.cpp — Message is a value-type data holder; no logic lives here.
 *
 * All methods are defined inline in Message.hpp. This file exists so the
 * CMake target compiles cleanly and can be extended with serialisation helpers
 * (e.g. toJson() / fromJson()) when needed.
 */

#include "Message.hpp"

// No additional implementation required at this stage.
// TODO: Add toJson() / fromJson() helpers when wiring up the REST API.
