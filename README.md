# [Wintun Network Adapter](https://www.wintun.net/)
### High-Performance & Low-Latency TUN Device Driver for Windows (v0.15.3)

This is an optimized layer 3 TUN driver engineered for Windows 10 and 11 (64-bit AMD64). Originally created by [WireGuard](https://www.wireguard.com/), this high-performance edition (`kart-wintun`) is specifically hardened and accelerated for real-time low-latency gaming (e.g. KartRider, Netch), high-throughput network proxies, and performance-critical VPN tunnels.

## Key Features in v0.15.3

- **Multiplayer Zero-Jitter Signaling**: Eliminates missed wakeups and random ping spikes via intelligent event signaling: `SetEvent(TailMoved)` is dispatched when `Alertable == TRUE` (driver sleeping) or `Head == OldTail` (ring was empty). Guarantees instantaneous wakeup on match start and solitary packets while eliminating ~1,000 syscalls/sec during active racing.
- **Spin-Counted Cache-Aligned Synchronization**: Utilizes cache-aligned `CRITICAL_SECTION` primitives (`LOCK_SPIN_COUNT = 0x10000`) with 64-byte isolation (`DECLSPEC_CACHEALIGN`). Allows concurrent worker threads to acquire locks in user space within ~20 cycles, eliminating thread sleep and 15ms scheduling latency jitter.
- **Cache-Line Isolation (False Sharing Elimination)**: Internal session rings and statistics are segregated with 64-byte alignment (`DECLSPEC_CACHEALIGN`), preventing cross-core cache invalidation storms under concurrent RX/TX operations.
- **RFC 1624 O(1) Fast Checksum & QoS Tagging**: Hardware-priority DiffServ QoS tagging via `WintunSendPacketQoS`, featuring constant-time IPv4 incremental checksum recalculation (accelerated from ~30 cycles to ~4 cycles) and full IPv6 Traffic Class support.
- **Memory Pre-faulting**: Pre-faults 4KiB ring buffer memory pages upon session initialization, eliminating demand-paging soft faults and initial packet burst jitter.
- **Ultra-Lean Binary Footprint**: Completely stripped legacy 32-bit WOW64 IPC bridging (`rundll32.c`), unused shell dependencies, and Windows 7 downlevel shims, shrinking the native DLL size from 712 KB down to **94.5 KB** while preserving 100% official WHQL-signed `wintun.sys` driver integrity.

## Installation

Wintun is deployed as a single, ultra-lightweight `wintun.dll` file (AMD64). Place the `wintun.dll` file side-by-side with your application executable (e.g. in the application root or `bin/` directory). The official WHQL-signed kernel driver (`wintun.sys`), catalog (`wintun.cat`), and installation scripts (`wintun.inf`) are embedded directly inside the DLL and extracted automatically on demand.

## Usage

Include [`wintun.h`](api/wintun.h) in your project and dynamically load `wintun.dll` using `LoadLibraryExW()` and `GetProcAddress()` to resolve the exported functions.

### 1. Adapter Lifecycle & Session Initialization

```C
/* Create or open an adapter */
WINTUN_ADAPTER_HANDLE Adapter = WintunCreateAdapter(L"GamingProxy", L"Wintun", NULL);
if (!Adapter)
    Adapter = WintunOpenAdapter(L"GamingProxy");

/* Start a session with a 4 MiB ring buffer */
WINTUN_SESSION_HANDLE Session = WintunStartSession(Adapter, 0x400000);
```

### 2. High-Priority Packet Transmission (with QoS Tagging)

```C
/* Allocate buffer space in the send ring */
BYTE *OutgoingPacket = WintunAllocateSendPacket(Session, PacketDataSize);
if (OutgoingPacket)
{
    memcpy(OutgoingPacket, PacketData, PacketDataSize);

    /* Send with Expedited Forwarding (EF: 0x2E) for real-time game UDP traffic */
    WintunSendPacketQoS(Session, OutgoingPacket, WINTUN_DSCP_EF);
}
else if (GetLastError() != ERROR_BUFFER_OVERFLOW)
{
    Log(L"Packet transmission failed");
}
```

### 3. Ultra-Low Latency Packet Intake (Spin-Wait Polling)

```C
/* Polling loop with configurable micro-spin for lowest latency */
for (;;)
{
    DWORD IncomingPacketSize;
    /* Spin for up to 64 cycles before yielding to prevent context switch latency */
    BYTE *IncomingPacket = WintunReceivePacketFast(Session, &IncomingPacketSize, 64);
    if (IncomingPacket)
    {
        ProcessPacket(IncomingPacket, IncomingPacketSize);
        WintunReleaseReceivePacket(Session, IncomingPacket);
    }
    else if (GetLastError() == ERROR_NO_MORE_ITEMS)
    {
        /* Ring empty: wait on the kernel read event */
        WaitForSingleObject(WintunGetReadWaitEvent(Session), INFINITE);
    }
    else
    {
        Log(L"Packet reception failed or adapter terminating");
        break;
    }
}
```

### 4. Telemetry & Statistics Monitoring

```C
WINTUN_SESSION_STATS Stats;
WintunGetSessionStats(Session, &Stats);
wprintf(L"TX: %llu pkts, RX: %llu pkts, Spin Hits: %llu, Discards: %llu\n",
        Stats.PacketsSent, Stats.PacketsReceived, Stats.SpinHits, Stats.Discards);
```

### 5. Teardown

```C
WintunEndSession(Session);
WintunCloseAdapter(Adapter);
```

---

## API Reference

### Macro Definitions

#### Capacity & Limits
- `WINTUN_MIN_RING_CAPACITY`: `0x20000` (128 KiB) - Minimum session ring buffer capacity.
- `WINTUN_MAX_RING_CAPACITY`: `0x4000000` (64 MiB) - Maximum session ring buffer capacity.
- `WINTUN_MAX_POOL`: `256` - Maximum pool name length including null terminator.
- `WINTUN_MAX_IP_PACKET_SIZE`: `0xFFFF` (65,535 bytes) - Maximum layer 3 IP packet size.

#### QoS DSCP Values
- `WINTUN_DSCP_DEFAULT`: `0x00` - Standard Best Effort.
- `WINTUN_DSCP_CS1`: `0x08` - Priority Class 1.
- `WINTUN_DSCP_AF11`: `0x0A` - Assured Forwarding 11.
- `WINTUN_DSCP_AF21`: `0x12` - Assured Forwarding 21.
- `WINTUN_DSCP_AF31`: `0x1A` - Assured Forwarding 31.
- `WINTUN_DSCP_AF41`: `0x22` - Assured Forwarding 41.
- `WINTUN_DSCP_CS5`: `0x28` - Class Selector 5.
- `WINTUN_DSCP_EF`: `0x2E` - Expedited Forwarding (Highest priority for real-time game UDP).

---

### Data Structures & Typedefs

#### `WINTUN_ADAPTER_HANDLE`
Opaque handle representing an active Wintun adapter instance.

#### `WINTUN_SESSION_HANDLE`
Opaque handle representing an active Wintun packet processing session.

#### `WINTUN_SESSION_STATS`
```C
typedef struct _WINTUN_SESSION_STATS
{
    DWORD64 PacketsReceived;
    DWORD64 PacketsSent;
    DWORD64 BytesReceived;
    DWORD64 BytesSent;
    DWORD64 SpinHits;
    DWORD64 WaitHits;
    DWORD64 Discards;
} WINTUN_SESSION_STATS;
```

#### `WINTUN_PACKET_FILTER_CALLBACK`
```C
typedef BOOL (CALLBACK *WINTUN_PACKET_FILTER_CALLBACK)(
    const BYTE *Packet,
    DWORD PacketSize,
    BOOL IsOutbound,
    VOID *Context);
```
Callback invoked on packet ingress/egress. Return `TRUE` to pass the packet, or `FALSE` to discard it.

#### `WINTUN_LOGGER_CALLBACK`
```C
typedef VOID (CALLBACK *WINTUN_LOGGER_CALLBACK)(
    WINTUN_LOGGER_LEVEL Level,
    DWORD64 Timestamp,
    const WCHAR *Message);
```

---

### Exported Functions

#### Adapter Management
- `WINTUN_ADAPTER_HANDLE WintunCreateAdapter(const WCHAR *Name, const WCHAR *TunnelType, const GUID *RequestedGUID)`: Creates a new Wintun network adapter.
- `WINTUN_ADAPTER_HANDLE WintunOpenAdapter(const WCHAR *Name)`: Opens an existing Wintun adapter.
- `VOID WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Adapter)`: Closes and releases an adapter handle.
- `BOOL WintunDeleteDriver(VOID)`: Uninstalls the driver when no active adapters remain.
- `VOID WintunGetAdapterLuid(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid)`: Retrieves the network LUID.
- `DWORD WintunGetRunningDriverVersion(VOID)`: Retrieves the loaded kernel driver version.
- `VOID WintunSetLogger(WINTUN_LOGGER_CALLBACK NewLogger)`: Configures a global diagnostic logger callback.

#### Session Lifecycle
- `WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity)`: Starts a packet session with the specified ring capacity (must be a power of two between 128 KiB and 64 MiB). Pages are pre-faulted on allocation.
- `VOID WintunEndSession(WINTUN_SESSION_HANDLE Session)`: Terminates the session and unmaps shared ring memory.
- `HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session)`: Returns the synchronization event signaled when incoming data is available.

#### Packet Transmission (TX)
- `BYTE *WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize)`: Allocates contiguous memory in the send ring. Features a 128-cycle micro-spin cushion for transient burst absorption.
- `VOID WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet)`: Commits and releases the packet, unconditionally signaling the kernel driver with a memory barrier.
- `VOID WintunSendPacketQoS(WINTUN_SESSION_HANDLE Session, const BYTE *Packet, UCHAR Dscp)`: Updates the IPv4/IPv6 QoS DiffServ header using RFC 1624 O(1) fast incremental checksums and transmits the packet.

#### Packet Reception (RX)
- `BYTE *WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize)`: Retrieves an available packet from the receive ring without spinning.
- `BYTE *WintunReceivePacketFast(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize, DWORD SpinCycles)`: Retrieves an available packet, spinning up to `SpinCycles` outside critical sections before returning `ERROR_NO_MORE_ITEMS`.
- `VOID WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet)`: Releases packet buffer memory back to the driver.

#### Telemetry & Inspection
- `VOID WintunGetSessionStats(WINTUN_SESSION_HANDLE Session, WINTUN_SESSION_STATS *Stats)`: Retrieves real-time session packet, byte, spin, and discard counters.
- `VOID WintunSetPacketFilter(WINTUN_SESSION_HANDLE Session, WINTUN_PACKET_FILTER_CALLBACK Filter, VOID *Context)`: Registers a thread-safe packet inspection and filtering callback.

---

## Building

### Requirements
- Visual Studio 2022 / 2026 Community (MSVC v143 or v145) with C/C++ tools
- Windows 11 SDK (10.0.26100.0 or later)
- Windows Driver Kit (WDK)

### Compilation
Open a Visual Studio Developer Command Prompt and run:

```powershell
# Build AMD64 wintun.dll
MSBuild.exe wintun.proj /target:Dll /p:Configuration=Release /p:Platform=x64

# Package distribution archive (dist/wintun-0.15.3.zip)
MSBuild.exe wintun.proj /target:Zip /p:Configuration=Release /p:Platform=x64
```

### Verification Benchmark
A gaming benchmark suite is included to verify ABI compatibility, QoS tagging, and telemetry structures:

```powershell
cl /FeRelease\amd64\kart_benchmark.exe /Iapi example\kart_benchmark.c /link /LIBPATH:Release\amd64 ws2_32.lib
Release\amd64\kart_benchmark.exe
```

---

## License

The Wintun codebase, documentation, and tools are licensed under the [GNU General Public License v2.0](COPYING).
Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
Gaming optimizations and low-latency extensions Copyright (C) 2026 KaitouJoker.
