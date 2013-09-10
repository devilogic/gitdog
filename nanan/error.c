#include "error.h"

const char* error_2_string(int err) {
	if ((err != -1) && (err >= 0))
	    return (const char*) error_to_string(err);
	else if (err == -1)
		return (const char*)"unknow error";

	return (const char*)"x error";
}
