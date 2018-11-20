
#define ShortProtect(addr, NEW_PROTECTION, OLD_PROTECTION)(VirtualProtect(addr, sizeof(int), NEW_PROTECTION, OLD_PROTECTION))
namespace TrustCheck
{
	inline void BypassTrustCheck() // Function Decleration
	{
		DWORD old_protection; // Creation Here, Later Used In "old protection" in VirtualProtect
		DWORD addr = ASLR(0xC03A00) // Addr
		ShortProtect((LPVOID)addr, PAGE_EXECUTE_READWRITE, &old_protection); // Change Protection So We Modify
		WriteProcessMemory(GetCurrentProcess(), (void*)addr, (LPCVOID)0xEB, sizeof(int), 0); // Modification To JMP
		ShortProtect((LPVOID)addr, old_protection, &old_protection); // Restores To Prevent other Checks
		return; // return
	}

	inline void RestoreTrustCheck() // Creation
	{
		DWORD old_protection; // Creation Here, Later Used In "old protection" in VirtualProtect
		DWORD addr = ASLR(0xC03A00) // Addr
		ShortProtect((LPVOID)addr, PAGE_EXECUTE_READWRITE, &old_protection); // Modify Protection to write
		WriteProcessMemory(GetCurrentProcess(), (void*)addr, (LPCVOID)0x75, sizeof(int), 0); // Restore To Old Value
		ShortProtect((LPVOID)addr, old_protection, &old_protection); // Restores Old Value
		return; // return
	}
};

