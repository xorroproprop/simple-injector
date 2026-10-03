#pragma once

#include <Windows.h>

//
// Builds a security descriptor whose DACL grants DesiredAccess to every
// enabled group, restricted SID and app container SID of the given token,
// and whose SACL labels objects with the token's integrity level.
//

PSECURITY_DESCRIPTOR
CreateAccessibleSecurityDescriptorFromToken(
	HANDLE Token,
	ACCESS_MASK DesiredAccess
);
