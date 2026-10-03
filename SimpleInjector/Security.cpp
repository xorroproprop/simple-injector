#include "Security.h"
#include "Log.h"

#include <Windows.h>
#include <aclapi.h>

static BOOLEAN
TokenInAppContainer(
	HANDLE Token
)
{
	DWORD InAppContainer = 0;

	// This only fails on platforms that do not support AppContainers,
	// which means we are not in one.
	if (!GetTokenInformation(Token, TokenIsAppContainer, &InAppContainer, sizeof(DWORD), NULL)) {
		return FALSE;
	}

	Log(L"InAppContainer: %d", InAppContainer);

	return InAppContainer > 0;
}

//
// Sizes, allocates and queries any TOKEN_INFORMATION_CLASS in one call.
// The returned buffer is LocalAlloc'd and owned by the caller.
//

static PVOID
QueryTokenInformation(
	HANDLE Token,
	TOKEN_INFORMATION_CLASS InformationClass
)
{
	DWORD Length = 0;
	GetTokenInformation(Token, InformationClass, NULL, 0, &Length);

	if (!Length) {
		ErrorLog(L"Error 0x%08X -- Failed to query token information size.", GetLastError());
	}

	PVOID TokenInformation = LocalAlloc(LPTR, Length);

	if (!TokenInformation) {
		ErrorLog(L"Error 0x%08X -- Failed to allocate token information buffer.", GetLastError());
	}

	if (!GetTokenInformation(Token, InformationClass, TokenInformation, Length, &Length)) {
		ErrorLog(L"Error 0x%08X -- Failed to query token information.", GetLastError());
	}

	return TokenInformation;
}

//
// Appends a DACL entry granting DesiredAccess to the given SID.
//

static VOID
AddSidToDacl(
	PACL* Dacl,
	ACCESS_MASK DesiredAccess,
	PSID Sid
)
{
	EXPLICIT_ACCESSW ExplicitAccess = { 0 };

	ExplicitAccess.grfAccessPermissions = DesiredAccess;
	ExplicitAccess.grfAccessMode = SET_ACCESS;
	ExplicitAccess.grfInheritance = NO_INHERITANCE;
	ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ExplicitAccess.Trustee.ptstrName = (LPWSTR)Sid;

	if (SetEntriesInAclW(1, &ExplicitAccess, *Dacl, Dacl) != ERROR_SUCCESS) {
		ErrorLog(L"Error 0x%08X -- Failed to add entry to DACL.", GetLastError());
	}
}

PSECURITY_DESCRIPTOR
CreateAccessibleSecurityDescriptorFromToken(
	HANDLE Token,
	ACCESS_MASK DesiredAccess
)
{
	PACL Dacl = NULL;

	//
	// DACL: grant DesiredAccess to all enabled groups and restricted sids
	// (and the app container sid, if applicable).
	//

	PTOKEN_GROUPS_AND_PRIVILEGES Groups =
		(PTOKEN_GROUPS_AND_PRIVILEGES)QueryTokenInformation(Token, TokenGroupsAndPrivileges);

	for (ULONG i = 0; i < Groups->SidCount; i++) {

		if (Groups->Sids[i].Attributes & SE_GROUP_ENABLED) {
			AddSidToDacl(&Dacl, DesiredAccess, Groups->Sids[i].Sid);
		}
	}

	for (ULONG i = 0; i < Groups->RestrictedSidCount; i++) {
		AddSidToDacl(&Dacl, DesiredAccess, Groups->RestrictedSids[i].Sid);
	}

	LocalFree(Groups);

	if (TokenInAppContainer(Token)) {

		PTOKEN_APPCONTAINER_INFORMATION AppContainer =
			(PTOKEN_APPCONTAINER_INFORMATION)QueryTokenInformation(Token, TokenAppContainerSid);

		AddSidToDacl(&Dacl, DesiredAccess, AppContainer->TokenAppContainer);
		LocalFree(AppContainer);
	}

	//
	// SACL: mandatory label matching the token integrity level.
	//

	PTOKEN_MANDATORY_LABEL IntegrityLabel =
		(PTOKEN_MANDATORY_LABEL)QueryTokenInformation(Token, TokenIntegrityLevel);

	ULONG SaclLength = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetLengthSid(IntegrityLabel->Label.Sid);

	PACL Sacl = (PACL)LocalAlloc(LPTR, SaclLength);

	if (!Sacl || !InitializeAcl(Sacl, SaclLength, ACL_REVISION) ||
		!AddMandatoryAce(Sacl, ACL_REVISION, 0, 0, IntegrityLabel->Label.Sid)) {
		ErrorLog(L"Error 0x%08X -- Failed to build mandatory label SACL.", GetLastError());
	}

	LocalFree(IntegrityLabel);

	//
	// Finally, create and return the security descriptor to the caller.
	//

	PSECURITY_DESCRIPTOR SecurityDescriptor = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	if (!InitializeSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(SecurityDescriptor, TRUE, Dacl, FALSE) ||
		!SetSecurityDescriptorSacl(SecurityDescriptor, TRUE, Sacl, FALSE)) {
		ErrorLog(L"Error 0x%08X -- Failed to build security descriptor.", GetLastError());
	}

	return SecurityDescriptor;
}
