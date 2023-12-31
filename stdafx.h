#pragma once

#include <ata.h>
#include <classpnp.h>
#include <mountdev.h>
#include <mountmgr.h>
#include <ntdddisk.h>
#include <ntddk.h>
#include <ntddndis.h>
#include <ntddscsi.h>
#include <ntifs.h>
#include <ntimage.h>
#include <scsi.h>
#include <windef.h>

#include "util.h"

static DWORD SEED = 0;
static CHAR SERIAL[50];

typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
} NIC_DRIVER, *PNIC_DRIVER;

typedef struct _SWAP {
	UNICODE_STRING Name;
	PVOID *Swap;
	PVOID Original;
} SWAP, *PSWAP;

static struct {
	SWAP Buffer[0xFF];
	ULONG Length;
} SWAPS = {0};

// Appends swap to swap list
#define AppendSwap(name, swap, hook, original)                                                                             \
	{                                                                                                                      \
		UNICODE_STRING _n = name;                                                                                          \
		PSWAP _s = &SWAPS.Buffer[SWAPS.Length++];                                                                          \
		*(PVOID *)&original = _s->Original = InterlockedExchangePointer((PVOID *)(_s->Swap = (PVOID *)swap), (PVOID)hook); \
		_s->Name = _n;                                                                                                     \
	}

// Swaps MJ device control and appends it to swap list on success
#define SwapControl(driver, hook, original)                                                                                        \
	{                                                                                                                              \
		UNICODE_STRING str = driver;                                                                                               \
		PDRIVER_OBJECT object = 0;                                                                                                 \
		NTSTATUS _status = ObReferenceObjectByName(&str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &object); \
		if(NT_SUCCESS(_status))                                                                                                    \
		{                                                                                                                          \
			AppendSwap(str, &object->MajorFunction[IRP_MJ_DEVICE_CONTROL], hook, original);                                        \
			ObDereferenceObject(object);                                                                                           \
		}                                                                                                                          \
		else                                                                                                                       \
		{                                                                                                                          \
		}                                                                                                                          \
	}