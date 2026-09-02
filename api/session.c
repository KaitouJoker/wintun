/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "adapter.h"
#include "logger.h"
#include "main.h"
#include "wintun.h"
#include <Windows.h>
#include <devioctl.h>
#include <stdlib.h>
#include <intrin.h>

#pragma warning(disable : 4200) /* nonstandard: zero-sized array in struct/union */
#pragma warning(disable : 4324) /* structure was padded due to alignment specifier */

#define TUN_ALIGNMENT sizeof(ULONG)
#define TUN_ALIGN(Size) (((ULONG)(Size) + ((ULONG)TUN_ALIGNMENT - 1)) & ~((ULONG)TUN_ALIGNMENT - 1))
#define TUN_IS_ALIGNED(Size) (!((ULONG)(Size) & ((ULONG)TUN_ALIGNMENT - 1)))
#define TUN_MAX_PACKET_SIZE TUN_ALIGN(sizeof(TUN_PACKET) + WINTUN_MAX_IP_PACKET_SIZE)
#define TUN_RING_CAPACITY(Size) ((Size) - sizeof(TUN_RING) - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_SIZE(Capacity) (sizeof(TUN_RING) + (Capacity) + (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_WRAP(Value, Capacity) ((Value) & (Capacity - 1))
#define LOCK_SPIN_COUNT 0x10000
#define TUN_PACKET_RELEASE ((DWORD)0x80000000)

typedef struct _TUN_PACKET
{
    ULONG Size;
    UCHAR Data[];
} TUN_PACKET;

typedef struct _TUN_RING
{
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[];
} TUN_RING;

#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _TUN_REGISTER_RINGS
{
    struct
    {
        ULONG RingSize;
        TUN_RING *Ring;
        HANDLE TailMoved;
    } Send, Receive;
} TUN_REGISTER_RINGS;

typedef struct _TUN_SESSION
{
    ULONG Capacity;
    DECLSPEC_CACHEALIGN struct
    {
        ULONG Tail;
        ULONG TailRelease;
        ULONG PacketsToRelease;
        CRITICAL_SECTION Lock;
    } Receive;
    DECLSPEC_CACHEALIGN struct
    {
        ULONG Head;
        ULONG HeadRelease;
        ULONG PacketsToRelease;
        CRITICAL_SECTION Lock;
    } Send;
    DECLSPEC_CACHEALIGN TUN_REGISTER_RINGS Descriptor;
    HANDLE Handle;
    DECLSPEC_CACHEALIGN WINTUN_SESSION_STATS Stats;
    WINTUN_PACKET_FILTER_CALLBACK PacketFilter;
    VOID *PacketFilterContext;
} TUN_SESSION;

static inline VOID
UpdateIpDscp(UCHAR *Packet, UCHAR Dscp)
{
    UCHAR Version = Packet[0] >> 4;
    if (Version == 4)
    {
        DWORD Ihl = (Packet[0] & 0x0F) * 4;
        if (Ihl >= 20)
        {
            USHORT OldWord0 = *(USHORT *)&Packet[0];
            UCHAR OldTOS = Packet[1];
            UCHAR NewTOS = (UCHAR)((Dscp << 2) | (OldTOS & 0x03));
            if (OldTOS == NewTOS)
                return;
            Packet[1] = NewTOS;
            USHORT NewWord0 = *(USHORT *)&Packet[0];
            USHORT OldChecksum = *(USHORT *)&Packet[10];
            /* RFC 1624 Eqn. 3 incremental checksum: HC' = ~(~HC + ~m + m') */
            DWORD Sum = (~OldChecksum & 0xFFFF) + (~OldWord0 & 0xFFFF) + NewWord0;
            while (Sum >> 16)
                Sum = (Sum & 0xFFFF) + (Sum >> 16);
            *(USHORT *)&Packet[10] = (USHORT)(~Sum);
        }
    }
    else if (Version == 6)
    {
        /* IPv6 Traffic Class (bits 4..11) - no header checksum in IPv6 */
        UCHAR OldTClass = (UCHAR)(((Packet[0] & 0x0F) << 4) | ((Packet[1] & 0xF0) >> 4));
        UCHAR NewTClass = (UCHAR)((Dscp << 2) | (OldTClass & 0x03));
        Packet[0] = (UCHAR)((Packet[0] & 0xF0) | (NewTClass >> 4));
        Packet[1] = (UCHAR)((Packet[1] & 0x0F) | ((NewTClass & 0x0F) << 4));
    }
}

WINTUN_START_SESSION_FUNC WintunStartSession;
_Use_decl_annotations_
TUN_SESSION *WINAPI
WintunStartSession(WINTUN_ADAPTER *Adapter, DWORD Capacity)
{
    DWORD LastError;
    TUN_SESSION *Session = Zalloc(sizeof(TUN_SESSION));
    if (!Session)
    {
        LastError = GetLastError();
        goto cleanup;
    }
    const ULONG RingSize = TUN_RING_SIZE(Capacity);
    BYTE *AllocatedRegion = VirtualAlloc(0, (size_t)RingSize * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!AllocatedRegion)
    {
        LastError = LOG_LAST_ERROR(L"Failed to allocate ring memory (requested size: 0x%zx)", (size_t)RingSize * 2);
        goto cleanupRings;
    }
    Session->Descriptor.Send.RingSize = RingSize;
    Session->Descriptor.Send.Ring = (TUN_RING *)AllocatedRegion;
    Session->Descriptor.Send.TailMoved = CreateEventW(&SecurityAttributes, FALSE, FALSE, NULL);
    if (!Session->Descriptor.Send.TailMoved)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create send event");
        goto cleanupAllocatedRegion;
    }

    Session->Descriptor.Receive.RingSize = RingSize;
    Session->Descriptor.Receive.Ring = (TUN_RING *)(AllocatedRegion + RingSize);
    Session->Descriptor.Receive.TailMoved = CreateEventW(&SecurityAttributes, FALSE, FALSE, NULL);
    if (!Session->Descriptor.Receive.TailMoved)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create receive event");
        goto cleanupSendTailMoved;
    }

    Session->Handle = AdapterOpenDeviceObject(Adapter);
    if (Session->Handle == INVALID_HANDLE_VALUE)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to open adapter device object");
        goto cleanupReceiveTailMoved;
    }
    DWORD BytesReturned;
    if (!DeviceIoControl(
            Session->Handle,
            TUN_IOCTL_REGISTER_RINGS,
            &Session->Descriptor,
            sizeof(TUN_REGISTER_RINGS),
            NULL,
            0,
            &BytesReturned,
            NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to register rings");
        goto cleanupHandle;
    }
    Session->Capacity = Capacity;
    (VOID) InitializeCriticalSectionAndSpinCount(&Session->Receive.Lock, LOCK_SPIN_COUNT);
    (VOID) InitializeCriticalSectionAndSpinCount(&Session->Send.Lock, LOCK_SPIN_COUNT);
    return Session;
cleanupHandle:
    CloseHandle(Session->Handle);
cleanupReceiveTailMoved:
    CloseHandle(Session->Descriptor.Receive.TailMoved);
cleanupSendTailMoved:
    CloseHandle(Session->Descriptor.Send.TailMoved);
cleanupAllocatedRegion:
    VirtualFree(AllocatedRegion, 0, MEM_RELEASE);
cleanupRings:
    Free(Session);
cleanup:
    SetLastError(LastError);
    return NULL;
}

WINTUN_END_SESSION_FUNC WintunEndSession;
_Use_decl_annotations_
VOID WINAPI
WintunEndSession(TUN_SESSION *Session)
{
    DeleteCriticalSection(&Session->Send.Lock);
    DeleteCriticalSection(&Session->Receive.Lock);
    CloseHandle(Session->Handle);
    CloseHandle(Session->Descriptor.Send.TailMoved);
    CloseHandle(Session->Descriptor.Receive.TailMoved);
    VirtualFree(Session->Descriptor.Send.Ring, 0, MEM_RELEASE);
    Free(Session);
}

WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
_Use_decl_annotations_
HANDLE WINAPI
WintunGetReadWaitEvent(TUN_SESSION *Session)
{
    return Session->Descriptor.Send.TailMoved;
}

WINTUN_GET_SESSION_STATS_FUNC WintunGetSessionStats;
_Use_decl_annotations_
VOID WINAPI
WintunGetSessionStats(TUN_SESSION *Session, WINTUN_SESSION_STATS *Stats)
{
    if (!Session || !Stats)
        return;
    Stats->PacketsReceived = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.PacketsReceived, 0, 0);
    Stats->PacketsSent = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.PacketsSent, 0, 0);
    Stats->BytesReceived = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.BytesReceived, 0, 0);
    Stats->BytesSent = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.BytesSent, 0, 0);
    Stats->SpinHits = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.SpinHits, 0, 0);
    Stats->WaitHits = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.WaitHits, 0, 0);
    Stats->Discards = (DWORD64)InterlockedCompareExchange64((LONG64 *)&Session->Stats.Discards, 0, 0);
}

WINTUN_SET_PACKET_FILTER_FUNC WintunSetPacketFilter;
_Use_decl_annotations_
VOID WINAPI
WintunSetPacketFilter(TUN_SESSION *Session, WINTUN_PACKET_FILTER_CALLBACK Filter, VOID *Context)
{
    if (!Session)
        return;
    Session->PacketFilter = Filter;
    Session->PacketFilterContext = Context;
}

WINTUN_RECEIVE_PACKET_FAST_FUNC WintunReceivePacketFast;
_Use_decl_annotations_
BYTE *WINAPI
WintunReceivePacketFast(TUN_SESSION *Session, DWORD *PacketSize, DWORD SpinCycles)
{
    DWORD LastError;
    if (SpinCycles > 0)
    {
        ULONG InitialTail = ReadULongAcquire(&Session->Descriptor.Send.Ring->Tail);
        if (InitialTail >= Session->Capacity)
        {
            SetLastError(ERROR_HANDLE_EOF);
            return NULL;
        }
        /* Spin outside critical section to prevent blocking concurrent packet releases */
        ULONG InitialHead = ReadULongAcquire(&Session->Descriptor.Send.Ring->Head);
        if (InitialHead == InitialTail)
        {
            for (DWORD i = 0; i < SpinCycles; i++)
            {
                _mm_pause();
                InitialTail = ReadULongAcquire(&Session->Descriptor.Send.Ring->Tail);
                if (InitialHead != InitialTail)
                {
                    InterlockedIncrement64((LONG64 *)&Session->Stats.SpinHits);
                    break;
                }
            }
            if (InitialHead == InitialTail)
            {
                SetLastError(ERROR_NO_MORE_ITEMS);
                return NULL;
            }
        }
    }

    EnterCriticalSection(&Session->Send.Lock);
restartRx:
    if (Session->Send.Head >= Session->Capacity)
    {
        LastError = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    ULONG BuffTail = ReadULongAcquire(&Session->Descriptor.Send.Ring->Tail);
    if (BuffTail >= Session->Capacity)
    {
        LastError = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    if (Session->Send.Head == BuffTail)
    {
        LastError = ERROR_NO_MORE_ITEMS;
        goto cleanup;
    }
    const ULONG BuffContent = TUN_RING_WRAP(BuffTail - Session->Send.Head, Session->Capacity);
    if (BuffContent < sizeof(TUN_PACKET))
    {
        LastError = ERROR_INVALID_DATA;
        goto cleanup;
    }
    TUN_PACKET *BuffPacket = (TUN_PACKET *)&Session->Descriptor.Send.Ring->Data[Session->Send.Head];
    _mm_prefetch((const char *)BuffPacket, _MM_HINT_T0);
    _mm_prefetch((const char *)BuffPacket->Data, _MM_HINT_T0);
    if (BuffPacket->Size > WINTUN_MAX_IP_PACKET_SIZE)
    {
        LastError = ERROR_INVALID_DATA;
        goto cleanup;
    }
    const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + BuffPacket->Size);
    if (AlignedPacketSize > BuffContent)
    {
        LastError = ERROR_INVALID_DATA;
        goto cleanup;
    }
    *PacketSize = BuffPacket->Size;
    BYTE *Packet = BuffPacket->Data;
    Session->Send.Head = TUN_RING_WRAP(Session->Send.Head + AlignedPacketSize, Session->Capacity);
    Session->Send.PacketsToRelease++;
    if (Session->PacketFilter && !Session->PacketFilter(Packet, *PacketSize, FALSE, Session->PacketFilterContext))
    {
        InterlockedIncrement64((LONG64 *)&Session->Stats.Discards);
        /* Mark discarded packet as released immediately in ring and fetch next */
        BuffPacket->Size |= TUN_PACKET_RELEASE;
        while (Session->Send.PacketsToRelease)
        {
            const TUN_PACKET *ReleaseBuffPacket =
                (TUN_PACKET *)&Session->Descriptor.Send.Ring->Data[Session->Send.HeadRelease];
            if ((ReleaseBuffPacket->Size & TUN_PACKET_RELEASE) == 0)
                break;
            const ULONG AlignedReleaseSize =
                TUN_ALIGN(sizeof(TUN_PACKET) + (ReleaseBuffPacket->Size & ~TUN_PACKET_RELEASE));
            Session->Send.HeadRelease =
                TUN_RING_WRAP(Session->Send.HeadRelease + AlignedReleaseSize, Session->Capacity);
            Session->Send.PacketsToRelease--;
        }
        WriteULongRelease(&Session->Descriptor.Send.Ring->Head, Session->Send.HeadRelease);
        SpinCycles = 0; /* Subsequent packet in batch doesn't need to spin */
        goto restartRx;
    }
    InterlockedIncrement64((LONG64 *)&Session->Stats.PacketsReceived);
    InterlockedAdd64((LONG64 *)&Session->Stats.BytesReceived, *PacketSize);
    LeaveCriticalSection(&Session->Send.Lock);
    return Packet;
cleanup:
    LeaveCriticalSection(&Session->Send.Lock);
    SetLastError(LastError);
    return NULL;
}

WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
_Use_decl_annotations_
BYTE *WINAPI
WintunReceivePacket(TUN_SESSION *Session, DWORD *PacketSize)
{
    return WintunReceivePacketFast(Session, PacketSize, 0);
}

WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
_Use_decl_annotations_
VOID WINAPI
WintunReleaseReceivePacket(TUN_SESSION *Session, const BYTE *Packet)
{
    EnterCriticalSection(&Session->Send.Lock);
    TUN_PACKET *ReleasedBuffPacket = (TUN_PACKET *)(Packet - offsetof(TUN_PACKET, Data));
    ReleasedBuffPacket->Size |= TUN_PACKET_RELEASE;
    while (Session->Send.PacketsToRelease)
    {
        const TUN_PACKET *BuffPacket = (TUN_PACKET *)&Session->Descriptor.Send.Ring->Data[Session->Send.HeadRelease];
        if ((BuffPacket->Size & TUN_PACKET_RELEASE) == 0)
            break;
        const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + (BuffPacket->Size & ~TUN_PACKET_RELEASE));
        Session->Send.HeadRelease = TUN_RING_WRAP(Session->Send.HeadRelease + AlignedPacketSize, Session->Capacity);
        Session->Send.PacketsToRelease--;
    }
    WriteULongRelease(&Session->Descriptor.Send.Ring->Head, Session->Send.HeadRelease);
    LeaveCriticalSection(&Session->Send.Lock);
}

WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
_Use_decl_annotations_
BYTE *WINAPI
WintunAllocateSendPacket(TUN_SESSION *Session, DWORD PacketSize)
{
    DWORD LastError;
    if (PacketSize == 0 || PacketSize > WINTUN_MAX_IP_PACKET_SIZE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    EnterCriticalSection(&Session->Receive.Lock);
    if (Session->Receive.Tail >= Session->Capacity)
    {
        LastError = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + PacketSize);
    ULONG BuffHead = ReadULongAcquire(&Session->Descriptor.Receive.Ring->Head);
    if (BuffHead >= Session->Capacity)
    {
        LastError = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    ULONG BuffSpace = TUN_RING_WRAP(BuffHead - Session->Receive.Tail - TUN_ALIGNMENT, Session->Capacity);
    if (AlignedPacketSize > BuffSpace)
    {
        /* Micro-spin to cushion transient burst drops (prevents TCP resets in Netch) */
        for (DWORD Spin = 0; Spin < 128; ++Spin)
        {
            _mm_pause();
            BuffHead = ReadULongAcquire(&Session->Descriptor.Receive.Ring->Head);
            if (BuffHead >= Session->Capacity)
                break;
            BuffSpace = TUN_RING_WRAP(BuffHead - Session->Receive.Tail - TUN_ALIGNMENT, Session->Capacity);
            if (AlignedPacketSize <= BuffSpace)
                break;
        }
    }
    if (BuffHead >= Session->Capacity)
    {
        LastError = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    if (AlignedPacketSize > BuffSpace)
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanup;
    }
    TUN_PACKET *BuffPacket = (TUN_PACKET *)&Session->Descriptor.Receive.Ring->Data[Session->Receive.Tail];
    BuffPacket->Size = PacketSize | TUN_PACKET_RELEASE;
    BYTE *Packet = BuffPacket->Data;
    _mm_prefetch((const char *)BuffPacket, _MM_HINT_T0);
    Session->Receive.Tail = TUN_RING_WRAP(Session->Receive.Tail + AlignedPacketSize, Session->Capacity);
    Session->Receive.PacketsToRelease++;
    LeaveCriticalSection(&Session->Receive.Lock);
    return Packet;
cleanup:
    LeaveCriticalSection(&Session->Receive.Lock);
    SetLastError(LastError);
    return NULL;
}

WINTUN_SEND_PACKET_FUNC WintunSendPacket;
_Use_decl_annotations_
VOID WINAPI
WintunSendPacket(TUN_SESSION *Session, const BYTE *Packet)
{
    EnterCriticalSection(&Session->Receive.Lock);
    TUN_PACKET *ReleasedBuffPacket = (TUN_PACKET *)(Packet - offsetof(TUN_PACKET, Data));
    ReleasedBuffPacket->Size &= ~TUN_PACKET_RELEASE;
    while (Session->Receive.PacketsToRelease)
    {
        TUN_PACKET *BuffPacket =
            (TUN_PACKET *)&Session->Descriptor.Receive.Ring->Data[Session->Receive.TailRelease];
        if (BuffPacket->Size & TUN_PACKET_RELEASE)
            break;
        const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + BuffPacket->Size);
        if (Session->PacketFilter && !Session->PacketFilter(BuffPacket->Data, BuffPacket->Size, TRUE, Session->PacketFilterContext))
        {
            /* Corrupt IP version header so driver jumps to skipNbl without indicating packet */
            if (BuffPacket->Size > 0)
                BuffPacket->Data[0] = 0;
            InterlockedIncrement64((LONG64 *)&Session->Stats.Discards);
        }
        else
        {
            InterlockedIncrement64((LONG64 *)&Session->Stats.PacketsSent);
            InterlockedAdd64((LONG64 *)&Session->Stats.BytesSent, BuffPacket->Size);
        }
        Session->Receive.TailRelease =
            TUN_RING_WRAP(Session->Receive.TailRelease + AlignedPacketSize, Session->Capacity);
        Session->Receive.PacketsToRelease--;
    }
    if (Session->Descriptor.Receive.Ring->Tail != Session->Receive.TailRelease)
    {
        WriteULongRelease(&Session->Descriptor.Receive.Ring->Tail, Session->Receive.TailRelease);
        if (ReadAcquire(&Session->Descriptor.Receive.Ring->Alertable))
            SetEvent(Session->Descriptor.Receive.TailMoved);
    }
    LeaveCriticalSection(&Session->Receive.Lock);
}

WINTUN_SEND_PACKET_QOS_FUNC WintunSendPacketQoS;
_Use_decl_annotations_
VOID WINAPI
WintunSendPacketQoS(TUN_SESSION *Session, const BYTE *Packet, UCHAR Dscp)
{
    if (Packet && Dscp != WINTUN_DSCP_DEFAULT)
        UpdateIpDscp((UCHAR *)Packet, Dscp);
    WintunSendPacket(Session, Packet);
}

