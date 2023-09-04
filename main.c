#define _NO_CRT_STDIO_INLINE

#include "stdafx.h"

struct {
	DWORD Length;
	NIC_DRIVER Drivers[0xFF];
} NICs = {0};

PDRIVER_DISPATCH DiskControlOriginal = 0, MountControlOriginal = 0, PartControlOriginal = 0, NsiControlOriginal = 0, GpuControlOriginal = 0;

NTSTATUS SpoofVolumes()
{
	DbgPrintEx(0, 0, "%s\n", "Spoofing volumes");
	UNICODE_STRING driverDisk;
	RtlInitUnicodeString(&driverDisk, L"\\Driver\\mountmgr");

	PDRIVER_OBJECT driverObject;
	NTSTATUS status = ObReferenceObjectByName(&driverDisk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0, *IoDriverObjectType, KernelMode, 0, &driverObject);
	if(!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}

	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];
	ObDereferenceObject(driverObject);
	DbgPrintEx(0, 0, "%s\n", "Spoofing volumes end");
	return STATUS_SUCCESS;
}

NTSTATUS SpoofDisks()
{
	UNICODE_STRING driverDisk;
	RtlInitUnicodeString(&driverDisk, L"\\Driver\\Disk");

	PDRIVER_OBJECT driverObject;
	NTSTATUS status = ObReferenceObjectByName(&driverDisk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0, *IoDriverObjectType, KernelMode, 0, &driverObject);
	if(!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];
	ObDereferenceObject(driverObject);
	return STATUS_SUCCESS;
}

NTSTATUS SpoofNIC()
{
	UNICODE_STRING driverDisk;
	RtlInitUnicodeString(&driverDisk, L"\\Driver\\nsiproxy");

	PDRIVER_OBJECT driverObject;
	NTSTATUS status = ObReferenceObjectByName(&driverDisk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0, *IoDriverObjectType, KernelMode, 0, &driverObject);
	if(!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];
	PVOID base = GetBaseAddress("ndis.sys", 0);
	if(!base)
	{
		DbgPrintEx(0, 0, "%s\n", "Base address of ndis.sys are null");
		return;
	}

	PNDIS_FILTER_BLOCK ndisGlobalFilterList = FindPatternImage(base, "\x40\x8A\xF0\x48\x8B\x05", "xxxxxx");
	if(ndisGlobalFilterList)
	{
		PDWORD ndisFilter_IfBlock = FindPatternImage(base, "\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33", "xx?xx?????x???xxx");
		if(ndisFilter_IfBlock)
		{
			DWORD ndisFilter_IfBlock_offset = *(PDWORD)((PBYTE)ndisFilter_IfBlock + 12);

			ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((PBYTE)ndisGlobalFilterList + 3);
			ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK *)((PBYTE)ndisGlobalFilterList + 7 + *(PINT)((PBYTE)ndisGlobalFilterList + 3));

			DWORD count = 0;
			for(PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter)
			{
				PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK *)((PBYTE)filter + ndisFilter_IfBlock_offset);
				if(block)
				{
					PWCHAR copy = SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
					if(copy)
					{
						WCHAR adapter[MAX_PATH] = {0};

						swprintf(adapter, L"\\Device\\%ws", TrimGUID(copy, MAX_PATH / 2));
						ExFreePool(copy);

						UNICODE_STRING name = {0};
						RtlInitUnicodeString(&name, adapter);

						PFILE_OBJECT file = 0;
						PDEVICE_OBJECT device = 0;

						NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
						if(NT_SUCCESS(status))
						{
							PDRIVER_OBJECT driver = device->DriverObject;

							if(driver)
							{
								BOOL exists = FALSE;
								for(DWORD i = 0; i < NICs.Length; ++i)
								{
									if(NICs.Drivers[i].DriverObject == driver)
									{
										exists = TRUE;
										break;
									}
								}

								if(!exists)
								{
									PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
									nic->DriverObject = driver;

									driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver->MajorFunction[IRP_MJ_QUERY_INFORMATION];
									++NICs.Length;
								}
							}

							// Indirectly dereferences device object
							ObDereferenceObject(file);
						}
						else
						{
							DbgPrintEx(0, 0, "%s\n", "Unsuccess to get IoGetDeviceObjectPointer");
						}
					}

					// Current MAC
					PIF_PHYSICAL_ADDRESS_LH addr = &block->ifPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);
					addr = &block->PermanentPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);

					++count;
				}
			}
		}
		else
		{
			DbgPrintEx(0, 0, "%s\n", "ndisFilter_IfBlock are null");
		}
	}
	else
	{
		DbgPrintEx(0, 0, "%s\n", "ndisGlobalFilterList are null");
	}
	DbgPrintEx(0, 0, "%s\n", "Nci spoofing end");

	ObDereferenceObject(driverObject);
	return STATUS_SUCCESS;
}

/**** SMBIOS (and boot) ****/
void SpoofSMBIOS()
{
	DbgPrintEx(0, 0, "%s\n", "Spoofing smbios");
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if(!base)
	{
		DbgPrintEx(0, 0, "%s\n", "ntoskrnl.exe address are null");
		return;
	}

	PBYTE ExpBootEnvironmentInformation = FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if(ExpBootEnvironmentInformation)
	{
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		DbgPrintEx(0, 0, "%s\n", "Spoofing environment information");
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);
	}
	else
	{
		DbgPrintEx(0, 0, "%s\n", "Exp boot environment not found");
	}

	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if(WmipSMBiosTablePhysicalAddress)
	{
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		DbgPrintEx(0, 0, "%s\n", "Zeroing wmip smbios table");
		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PHYSICAL_ADDRESS));
	}
	else
	{
		DbgPrintEx(0, 0, "%s\n", "Can't find wmip smbios table phys address");
	}
	DbgPrintEx(0, 0, "%s\n", "Spoofing smbios end");
}

void Entrypoint()
{
	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	SEED = (DWORD)time;

	SpoofDisks();
	SpoofVolumes();
	SpoofNIC();
	SpoofSMBIOS();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);
	return STATUS_SUCCESS;
}