#!/usr/bin/env python3
"""Native Windows HID firmware tool for Kensington SlimBlade Pro.

Subcommands:
    identify     Read-only enumeration of SlimBlade Pro (047D:80D7) and bootloaders.
    prepare-v449 Download, verify, and extract official v4.49 updater & container.bin.
    flash        Verify a 128,112-byte container and flash payload (>= 0x2000) over HID.

Protocol matches `crates/slimblade-protocol` and `crates/slimblade-linux/src/flash.rs`.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import io
from pathlib import Path
import struct
import sys
import time
import urllib.request
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIRMWARE_DIR = REPO_ROOT / "firmware"

V449_URL = "https://accobrands.co.jp/wp/wp-content/uploads/Kensington-Slimblade-Pro-V4.49.zip"
ZIP_FILENAME = "Kensington-Slimblade-Pro-V4.49.zip"
EXE_FILENAME = "Kensington Slimblade Pro V4.49.exe"
CONTAINER_FILENAME = "container.bin"

ZIP_SIZE = 1_037_410
ZIP_SHA256 = "dffe13ab063cb9614669914295b273bda0e5906bc5af75b3f73cd2da5f0f41ac"
EXE_SIZE = 3_008_000
EXE_SHA256 = "38fc1b333d316039e4eb732c70183b8c6c4cc831c90246425917e9dce64f7688"
CONTAINER_BASE_IN_EXE = 0x21F0DB - 0x1E7D1
CONTAINER_SIZE = 128_112
STOCK_CONTAINER_SHA256 = "e91502e8021e61c97a77fb12324e99ee4acb23bee55a5a67d18e26521ef856f7"
PAYLOAD_OFFSET = 0x2000
PAYLOAD_SIZE = 119_920
STOCK_PAYLOAD_SHA256 = "3b7849cafa2a8d4a0c2694c9771d70563563dc1c6cdbf84ede9b8648071604bf"
STOCK_PAYLOAD_CRC32 = 0xDD0FE246

STACK_HEADER_OFFSET = 0x1F70
STACK_CRC_RANGE = (0x1F80, CONTAINER_SIZE)
STACK_UID = 0x53535353
APP_HEADER_OFFSET = 0x2010
APP_CRC_RANGE = (0x2020, CONTAINER_SIZE)
APP_UID = 0x42424242

APP_VID = 0x047D
APP_PID = 0x80D7
BOOT_IDENTITIES = {
    (0x25A7, 0xFABE),
    (0x3554, 0xF600),
    (0x3554, 0xF800),
}
VENDOR_USAGE_PAGE = 0xFF02
VENDOR_USAGE = 0x0002

NORMAL_REPORT_ID = 0x08
NORMAL_REPORT_LENGTH = 17
BOOT_REPORT_ID = 0x06
BOOT_REPORT_LENGTH = 49
DOWNLOAD_BLOCK_LENGTH = 32

# Win32 constants
DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
ERROR_IO_PENDING = 997
ERROR_OPERATION_ABORTED = 995
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wt.DWORD),
        ("Data2", wt.WORD),
        ("Data3", wt.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wt.DWORD),
        ("Reserved", ctypes.c_size_t),
    ]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Size", wt.ULONG),
        ("VendorID", wt.USHORT),
        ("ProductID", wt.USHORT),
        ("VersionNumber", wt.USHORT),
    ]


class HIDP_CAPS(ctypes.Structure):
    _fields_ = [
        ("Usage", wt.USHORT),
        ("UsagePage", wt.USHORT),
        ("InputReportByteLength", wt.USHORT),
        ("OutputReportByteLength", wt.USHORT),
        ("FeatureReportByteLength", wt.USHORT),
        ("Reserved", wt.USHORT * 17),
        ("NumberLinkCollectionNodes", wt.USHORT),
        ("NumberInputButtonCaps", wt.USHORT),
        ("NumberInputValueCaps", wt.USHORT),
        ("NumberInputDataIndices", wt.USHORT),
        ("NumberOutputButtonCaps", wt.USHORT),
        ("NumberOutputValueCaps", wt.USHORT),
        ("NumberOutputDataIndices", wt.USHORT),
        ("NumberFeatureButtonCaps", wt.USHORT),
        ("NumberFeatureValueCaps", wt.USHORT),
        ("NumberFeatureDataIndices", wt.USHORT),
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wt.DWORD),
        ("OffsetHigh", wt.DWORD),
        ("hEvent", ctypes.c_void_p),
    ]


assert ctypes.sizeof(OVERLAPPED) == (32 if ctypes.sizeof(ctypes.c_void_p) == 8 else 20)

hid = ctypes.WinDLL("hid", use_last_error=True)
setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(GUID)]
hid.HidD_GetHidGuid.restype = None

hid.HidD_GetAttributes.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDD_ATTRIBUTES)]
hid.HidD_GetAttributes.restype = wt.BOOLEAN

hid.HidD_GetPreparsedData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_GetPreparsedData.restype = wt.BOOLEAN

hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidD_FreePreparsedData.restype = wt.BOOLEAN

hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]
hid.HidP_GetCaps.restype = wt.ULONG

hid.HidD_SetNumInputBuffers.argtypes = [ctypes.c_void_p, wt.ULONG]
hid.HidD_SetNumInputBuffers.restype = wt.BOOLEAN

setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wt.LPCWSTR, wt.HWND, wt.DWORD]
setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p

setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(GUID),
    wt.DWORD,
    ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
]
setupapi.SetupDiEnumDeviceInterfaces.restype = wt.BOOL

setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    ctypes.c_void_p,
]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wt.BOOL

setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.restype = wt.BOOL

kernel32.CreateFileW.argtypes = [
    wt.LPCWSTR,
    wt.DWORD,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    wt.DWORD,
    ctypes.c_void_p,
]
kernel32.CreateFileW.restype = ctypes.c_void_p

kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = wt.BOOL

kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.CreateEventW.restype = ctypes.c_void_p

kernel32.ResetEvent.argtypes = [ctypes.c_void_p]
kernel32.ResetEvent.restype = wt.BOOL

kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
kernel32.WaitForSingleObject.restype = wt.DWORD

kernel32.ReadFile.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(OVERLAPPED),
]
kernel32.ReadFile.restype = wt.BOOL

kernel32.WriteFile.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(OVERLAPPED),
]
kernel32.WriteFile.restype = wt.BOOL

kernel32.GetOverlappedResult.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(OVERLAPPED),
    ctypes.POINTER(wt.DWORD),
    wt.BOOL,
]
kernel32.GetOverlappedResult.restype = wt.BOOL

kernel32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(OVERLAPPED)]
kernel32.CancelIoEx.restype = wt.BOOL


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def updater_crc32(data: bytes) -> int:
    """Reflected CRC-32, poly 0xEDB88320, init 0xFFFFFFFF, NO final xor."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if (crc & 1) else (crc >> 1)
    return crc


def normal_checksum(report: bytes) -> int:
    return (0x55 - (sum(report) & 0xFF)) & 0xFF


def build_reset_to_loader_report() -> bytes:
    buf = bytearray(NORMAL_REPORT_LENGTH)
    buf[0] = NORMAL_REPORT_ID
    buf[1] = 0x0D
    buf[-1] = normal_checksum(buf)
    return bytes(buf)


def build_boot_query_report() -> bytes:
    buf = bytearray(BOOT_REPORT_LENGTH)
    buf[0] = BOOT_REPORT_ID
    buf[1] = 0xB2
    buf[-1] = normal_checksum(buf)
    return bytes(buf)


def build_boot_prepare_report(payload_len: int, payload_crc: int) -> bytes:
    buf = bytearray(BOOT_REPORT_LENGTH)
    buf[0] = BOOT_REPORT_ID
    buf[1] = 0xB0
    buf[5:9] = payload_len.to_bytes(4, "big")
    buf[9:13] = payload_crc.to_bytes(4, "big")
    return bytes(buf)


def build_boot_download_report(payload: bytes, offset: int) -> bytes:
    remaining = len(payload) - offset
    data_len = min(remaining, DOWNLOAD_BLOCK_LENGTH)
    final_block = data_len == remaining
    address = PAYLOAD_OFFSET + offset

    buf = bytearray(BOOT_REPORT_LENGTH)
    buf[0] = BOOT_REPORT_ID
    buf[1] = 0xB1
    buf[2] = 0xC1 if final_block else 0xC0
    buf[3] = data_len
    buf[5:9] = address.to_bytes(4, "big")
    buf[17:] = b"\xff" * DOWNLOAD_BLOCK_LENGTH
    buf[17:17 + data_len] = payload[offset:offset + data_len]
    return bytes(buf)


def is_valid_handle(handle: int | None) -> bool:
    return handle is not None and handle != 0 and handle != INVALID_HANDLE_VALUE


def enumerate_target_hid_nodes() -> list[dict]:
    """Enumerate present Windows HID interfaces matching SlimBlade Pro or known loaders."""
    target_prefixes = tuple(
        f"vid_{vid:04x}&pid_{pid:04x}" for (vid, pid) in [(APP_VID, APP_PID), *sorted(BOOT_IDENTITIES)]
    )
    guid = GUID()
    hid.HidD_GetHidGuid(ctypes.byref(guid))
    hdev = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    )
    if not is_valid_handle(hdev):
        raise ctypes.WinError(ctypes.get_last_error())

    nodes = []
    try:
        idx = 0
        detail_hdr_size = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
        while True:
            did = SP_DEVICE_INTERFACE_DATA()
            did.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            if not setupapi.SetupDiEnumDeviceInterfaces(
                hdev, None, ctypes.byref(guid), idx, ctypes.byref(did)
            ):
                break
            idx += 1

            req_len = wt.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                hdev, ctypes.byref(did), None, 0, ctypes.byref(req_len), None
            )
            if req_len.value <= 4:
                continue

            buf = ctypes.create_string_buffer(req_len.value)
            ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0] = detail_hdr_size
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                hdev, ctypes.byref(did), buf, req_len.value, None, None
            ):
                continue

            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
            lower_path = path.lower()
            if not any(tag in lower_path for tag in target_prefixes):
                continue

            h0 = kernel32.CreateFileW(
                path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
            )
            if not is_valid_handle(h0):
                continue
            try:
                attr = HIDD_ATTRIBUTES(Size=ctypes.sizeof(HIDD_ATTRIBUTES))
                if not hid.HidD_GetAttributes(h0, ctypes.byref(attr)):
                    continue
                caps = HIDP_CAPS()
                ppd = ctypes.c_void_p()
                if hid.HidD_GetPreparsedData(h0, ctypes.byref(ppd)):
                    try:
                        hid.HidP_GetCaps(ppd, ctypes.byref(caps))
                    finally:
                        hid.HidD_FreePreparsedData(ppd)
                nodes.append(
                    {
                        "path": path,
                        "vid": attr.VendorID,
                        "pid": attr.ProductID,
                        "bcd_device": attr.VersionNumber,
                        "usage_page": caps.UsagePage,
                        "usage": caps.Usage,
                        "in_len": caps.InputReportByteLength,
                        "out_len": caps.OutputReportByteLength,
                        "feat_len": caps.FeatureReportByteLength,
                    }
                )
            finally:
                kernel32.CloseHandle(h0)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return nodes


def find_vendor_nodes(identity_set: set[tuple[int, int]], in_len: int, out_len: int) -> list[dict]:
    return [
        node
        for node in enumerate_target_hid_nodes()
        if (node["vid"], node["pid"]) in identity_set
        and node["usage_page"] == VENDOR_USAGE_PAGE
        and node["usage"] == VENDOR_USAGE
        and node["in_len"] == in_len
        and node["out_len"] == out_len
    ]


class WindowsHidDevice:
    """Overlapped read/write HID handle with safe timeout cancellation."""

    def __init__(self, path: str, num_input_buffers: int = 256):
        self.path = path
        self.handle = kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        if not is_valid_handle(self.handle):
            raise OSError(f"CreateFileW({path}) failed: {ctypes.WinError(ctypes.get_last_error())}")

        if not hid.HidD_SetNumInputBuffers(self.handle, num_input_buffers):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(f"HidD_SetNumInputBuffers failed: {ctypes.WinError(err)}")

        self._read_event = kernel32.CreateEventW(None, True, False, None)
        self._write_event = kernel32.CreateEventW(None, True, False, None)
        if not is_valid_handle(self._read_event) or not is_valid_handle(self._write_event):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(f"CreateEventW failed: {ctypes.WinError(err)}")

    def close(self) -> None:
        for attr in ("_read_event", "_write_event", "handle"):
            h = getattr(self, attr, None)
            if is_valid_handle(h):
                kernel32.CloseHandle(h)
                setattr(self, attr, None)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def write_report(self, data: bytes, timeout_s: float = 5.0) -> None:
        kernel32.ResetEvent(self._write_event)
        ov = OVERLAPPED(hEvent=self._write_event)
        buf = ctypes.create_string_buffer(data, len(data))
        transferred = wt.DWORD(0)

        ok = kernel32.WriteFile(
            self.handle, buf, len(data), ctypes.byref(transferred), ctypes.byref(ov)
        )
        if not ok:
            err = ctypes.get_last_error()
            if err != ERROR_IO_PENDING:
                raise OSError(err, f"WriteFile failed (winerr={err}): {ctypes.FormatError(err).strip()}")
            wait_ms = max(1, int(timeout_s * 1000))
            wait_rc = kernel32.WaitForSingleObject(self._write_event, wait_ms)
            if wait_rc == WAIT_TIMEOUT:
                kernel32.CancelIoEx(self.handle, ctypes.byref(ov))
                kernel32.GetOverlappedResult(
                    self.handle, ctypes.byref(ov), ctypes.byref(transferred), True
                )
                raise TimeoutError(f"HID write timed out after {timeout_s:.2f}s")
            if wait_rc != WAIT_OBJECT_0:
                err = ctypes.get_last_error()
                kernel32.CancelIoEx(self.handle, ctypes.byref(ov))
                kernel32.GetOverlappedResult(
                    self.handle, ctypes.byref(ov), ctypes.byref(transferred), True
                )
                raise OSError(err, f"WaitForSingleObject(write) failed: {wait_rc}")
            if not kernel32.GetOverlappedResult(
                self.handle, ctypes.byref(ov), ctypes.byref(transferred), False
            ):
                err = ctypes.get_last_error()
                raise OSError(err, f"GetOverlappedResult(write) failed (winerr={err}): {ctypes.FormatError(err).strip()}")

        if transferred.value != len(data):
            raise OSError(f"short HID write: {transferred.value} of {len(data)} bytes")

    def read_report(self, report_len: int, timeout_s: float) -> bytes | None:
        if timeout_s <= 0:
            return None
        kernel32.ResetEvent(self._read_event)
        ov = OVERLAPPED(hEvent=self._read_event)
        buf = ctypes.create_string_buffer(report_len)
        transferred = wt.DWORD(0)

        ok = kernel32.ReadFile(
            self.handle, buf, report_len, ctypes.byref(transferred), ctypes.byref(ov)
        )
        if not ok:
            err = ctypes.get_last_error()
            if err != ERROR_IO_PENDING:
                raise OSError(err, f"ReadFile failed (winerr={err}): {ctypes.FormatError(err).strip()}")
            wait_ms = max(1, int(timeout_s * 1000))
            wait_rc = kernel32.WaitForSingleObject(self._read_event, wait_ms)
            if wait_rc == WAIT_TIMEOUT:
                kernel32.CancelIoEx(self.handle, ctypes.byref(ov))
                got_ok = kernel32.GetOverlappedResult(
                    self.handle, ctypes.byref(ov), ctypes.byref(transferred), True
                )
                if got_ok and transferred.value > 0:
                    return buf.raw[: transferred.value]
                err2 = ctypes.get_last_error()
                if not got_ok and err2 not in (0, ERROR_OPERATION_ABORTED):
                    raise OSError(err2, f"GetOverlappedResult(cancel-read) failed (winerr={err2}): {ctypes.FormatError(err2).strip()}")
                return None
            if wait_rc != WAIT_OBJECT_0:
                err = ctypes.get_last_error()
                kernel32.CancelIoEx(self.handle, ctypes.byref(ov))
                kernel32.GetOverlappedResult(
                    self.handle, ctypes.byref(ov), ctypes.byref(transferred), True
                )
                raise OSError(err, f"WaitForSingleObject(read) failed: {wait_rc}")
            if not kernel32.GetOverlappedResult(
                self.handle, ctypes.byref(ov), ctypes.byref(transferred), False
            ):
                err = ctypes.get_last_error()
                raise OSError(err, f"GetOverlappedResult(read) failed (winerr={err}): {ctypes.FormatError(err).strip()}")

        return buf.raw[: transferred.value]

    def read_boot_report(self, timeout_s: float) -> bytes | None:
        deadline = time.monotonic() + timeout_s
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                return None
            pkt = self.read_report(BOOT_REPORT_LENGTH, remain)
            if pkt is None:
                return None
            if len(pkt) == BOOT_REPORT_LENGTH and pkt[0] == BOOT_REPORT_ID:
                return pkt


def validate_container_bytes(image: bytes, expected_sha256: str) -> bytes:
    if len(image) != CONTAINER_SIZE:
        raise ValueError(f"expected {CONTAINER_SIZE} bytes, got {len(image)}")

    actual_sha = sha256_hex(image)
    if actual_sha != expected_sha256.lower():
        raise ValueError(f"container sha256 mismatch: expected {expected_sha256.lower()}, got {actual_sha}")

    stack_crc_hdr, _, stack_uid = struct.unpack_from("<III", image, STACK_HEADER_OFFSET)
    if stack_uid != STACK_UID:
        raise ValueError(f"invalid STACK_UID at {STACK_HEADER_OFFSET:#x}: {stack_uid:#010x}")
    calc_stack_crc = updater_crc32(image[STACK_CRC_RANGE[0]:STACK_CRC_RANGE[1]])
    if stack_crc_hdr != calc_stack_crc:
        raise ValueError(f"STACK_CRC mismatch: header={stack_crc_hdr:#010x}, calc={calc_stack_crc:#010x}")

    app_crc_hdr, _, app_uid = struct.unpack_from("<III", image, APP_HEADER_OFFSET)
    if app_uid != APP_UID:
        raise ValueError(f"invalid APP_UID at {APP_HEADER_OFFSET:#x}: {app_uid:#010x}")
    calc_app_crc = updater_crc32(image[APP_CRC_RANGE[0]:APP_CRC_RANGE[1]])
    if app_crc_hdr != calc_app_crc:
        raise ValueError(f"APP_CRC mismatch: header={app_crc_hdr:#010x}, calc={calc_app_crc:#010x}")

    payload = image[PAYLOAD_OFFSET:]
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(f"unexpected payload length: {len(payload)} != {PAYLOAD_SIZE}")
    return payload


def cmd_identify(_args: argparse.Namespace) -> int:
    nodes = enumerate_target_hid_nodes()
    if not nodes:
        print("No SlimBlade Pro (047d:80d7) or bootloader (25a7:fabe / 3554:f600 / 3554:f800) HID nodes found.")
        return 1
    for node in nodes:
        role = " [VENDOR]" if (node["usage_page"] == VENDOR_USAGE_PAGE and node["usage"] == VENDOR_USAGE) else ""
        print(
            f"{node['vid']:04x}:{node['pid']:04x} bcdDevice={node['bcd_device']:04x} "
            f"UP={node['usage_page']:04x} U={node['usage']:04x} "
            f"In={node['in_len']} Out={node['out_len']} Feat={node['feat_len']}{role}\n"
            f"  {node['path']}"
        )
    return 0


def cmd_prepare_v449(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / ZIP_FILENAME
    exe_path = out_dir / EXE_FILENAME
    container_path = out_dir / CONTAINER_FILENAME

    if zip_path.exists() and sha256_hex(zip_path.read_bytes()) == ZIP_SHA256:
        zip_bytes = zip_path.read_bytes()
        print(f"Using cached {zip_path} ({len(zip_bytes)} bytes)")
    else:
        print(f"Downloading {V449_URL} ...")
        req = urllib.request.Request(V449_URL, headers={"User-Agent": "Mozilla/5.0"})
        zip_bytes = urllib.request.urlopen(req, timeout=30).read()
        if len(zip_bytes) != ZIP_SIZE or sha256_hex(zip_bytes) != ZIP_SHA256:
            sys.exit(f"ZIP verification failed: len={len(zip_bytes)} sha256={sha256_hex(zip_bytes)}")
        zip_path.write_bytes(zip_bytes)
        print(f"Saved {zip_path} (sha256={ZIP_SHA256})")

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        exe_bytes = zf.read(EXE_FILENAME)
    if len(exe_bytes) != EXE_SIZE or sha256_hex(exe_bytes) != EXE_SHA256:
        sys.exit(f"EXE verification failed: len={len(exe_bytes)} sha256={sha256_hex(exe_bytes)}")
    exe_path.write_bytes(exe_bytes)
    print(f"Extracted {exe_path} (sha256={EXE_SHA256})")

    container = exe_bytes[CONTAINER_BASE_IN_EXE:CONTAINER_BASE_IN_EXE + CONTAINER_SIZE]
    payload = validate_container_bytes(container, STOCK_CONTAINER_SHA256)
    if sha256_hex(payload) != STOCK_PAYLOAD_SHA256:
        sys.exit(f"Stock payload sha256 mismatch: {sha256_hex(payload)}")
    if updater_crc32(payload) != STOCK_PAYLOAD_CRC32:
        sys.exit(f"Stock payload CRC mismatch: {updater_crc32(payload):#010x}")
    container_path.write_bytes(container)
    print(f"Extracted {container_path} (sha256={STOCK_CONTAINER_SHA256}, payload_crc={STOCK_PAYLOAD_CRC32:08x})")
    return 0


def wait_for_queried_loader(timeout_s: float = 10.0) -> tuple[dict, WindowsHidDevice]:
    deadline = time.monotonic() + timeout_s
    last_error = "no recognized loader HID node appeared"
    while time.monotonic() < deadline:
        candidates = find_vendor_nodes(BOOT_IDENTITIES, BOOT_REPORT_LENGTH, BOOT_REPORT_LENGTH)
        for node in candidates:
            remain = deadline - time.monotonic()
            if remain <= 0:
                break
            query_timeout = min(1.0, max(0.2, remain))
            dev = None
            try:
                dev = WindowsHidDevice(node["path"])
                dev.write_report(build_boot_query_report(), timeout_s=query_timeout)
                resp = dev.read_boot_report(query_timeout)
                if resp is None:
                    last_error = "loader disappeared or did not answer B2"
                    dev.close()
                    continue
                if resp[1] != 0xB2 or resp[2] != 0xD2:
                    dev.close()
                    raise RuntimeError(
                        f"unexpected B2 response (no erase attempted): {resp[:8].hex()}"
                    )
                return node, dev
            except OSError as exc:
                last_error = str(exc)
                if dev is not None:
                    dev.close()
        time.sleep(0.05)
    raise RuntimeError(f"loader unavailable before erase: {last_error}")


def transfer_payload(dev: WindowsHidDevice, payload: bytes, timeout_s: float = 30.0) -> int:
    payload_crc = updater_crc32(payload)
    prepare_pkt = build_boot_prepare_report(len(payload), payload_crc)
    dev.write_report(prepare_pkt, timeout_s=5.0)

    prepare_deadline = time.monotonic() + max(timeout_s, 15.0)
    saw_echo = False
    saw_complete = False
    while time.monotonic() < prepare_deadline:
        remain = prepare_deadline - time.monotonic()
        resp = dev.read_boot_report(remain)
        if resp is None:
            break
        if resp[1] == 0xB0:
            saw_echo = True
            continue
        if resp[1:4] == b"\x5b\xb5\x02":
            status = resp[4]
            if status == 0x00:
                continue
            if status == 0x01:
                saw_complete = True
                break
            raise RuntimeError(f"loader returned unknown erase status {status:#04x}")
    if not (saw_echo and saw_complete):
        raise RuntimeError(
            f"loader did not complete prepare/erase phase (saw_echo={saw_echo}, saw_complete={saw_complete})"
        )
    print(f"prepare/erase=ok payload={len(payload)} crc={payload_crc:08x}")

    total_blocks = (len(payload) + DOWNLOAD_BLOCK_LENGTH - 1) // DOWNLOAD_BLOCK_LENGTH
    next_percent = 5
    for idx, offset in enumerate(range(0, len(payload), DOWNLOAD_BLOCK_LENGTH), start=1):
        pkt = build_boot_download_report(payload, offset)
        dev.write_report(pkt, timeout_s=5.0)

        blk_deadline = time.monotonic() + 5.0
        echoed = None
        while time.monotonic() < blk_deadline:
            cand = dev.read_boot_report(blk_deadline - time.monotonic())
            if cand is None:
                break
            if cand[1] == 0xB1:
                echoed = cand
                break
        if echoed != pkt:
            raise RuntimeError(
                f"download block {idx}/{total_blocks} echo mismatch "
                f"(got={'none' if echoed is None else echoed[:16].hex()})"
            )
        percent = (idx * 100) // total_blocks
        if percent >= next_percent or idx == total_blocks:
            print(f"write/verify: {percent}% ({idx}/{total_blocks})", flush=True)
            next_percent = percent + 5
    return total_blocks


def cmd_flash(args: argparse.Namespace) -> int:
    expected = args.expected_sha256.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        sys.exit("--expected-sha256 must be a 64-character hex SHA-256 digest")

    container_path = Path(args.container)
    image = container_path.read_bytes()
    payload = validate_container_bytes(image, expected)
    print(f"container={container_path}")
    print(f"sha256={expected}")
    print(f"payload={len(payload)} bytes (crc={updater_crc32(payload):08x})")

    boot_nodes = find_vendor_nodes(BOOT_IDENTITIES, BOOT_REPORT_LENGTH, BOOT_REPORT_LENGTH)
    if not boot_nodes:
        if not args.enter_loader:
            sys.exit(
                "No bootloader (25a7:fabe) found; pass --enter-loader to reset 047d:80d7 into bootloader."
            )
        app_nodes = find_vendor_nodes({(APP_VID, APP_PID)}, NORMAL_REPORT_LENGTH, NORMAL_REPORT_LENGTH)
        if not app_nodes:
            sys.exit("No 047d:80d7 vendor HID interface found (ensure SlimBlade Pro is switched to Wired).")
        if len(app_nodes) > 1:
            sys.exit(f"Multiple 047d:80d7 devices connected ({len(app_nodes)}); disconnect extras first.")
        app_node = app_nodes[0]
        print(
            f"entering loader from {app_node['vid']:04x}:{app_node['pid']:04x} "
            f"bcdDevice={app_node['bcd_device']:04x} ..."
        )
        with WindowsHidDevice(app_node["path"]) as app_dev:
            app_dev.write_report(build_reset_to_loader_report(), timeout_s=3.0)

    loader_node, loader_dev = wait_for_queried_loader(timeout_s=10.0)
    try:
        print(
            f"loader={loader_node['vid']:04x}:{loader_node['pid']:04x} b2=d2 "
            f"path={loader_node['path']}"
        )
        blocks = transfer_payload(loader_dev, payload)
    except Exception as exc:
        loader_dev.close()
        sys.exit(f"FLASH FAILED: {exc}")
    loader_dev.close()

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        app_nodes = find_vendor_nodes({(APP_VID, APP_PID)}, NORMAL_REPORT_LENGTH, NORMAL_REPORT_LENGTH)
        if app_nodes:
            node = app_nodes[0]
            print(f"application={node['vid']:04x}:{node['pid']:04x} bcdDevice={node['bcd_device']:04x}")
            print(f"flash complete: {blocks} blocks echoed")
            return 0
        time.sleep(0.2)

    sys.exit("final block echoed, but 047d:80d7 did not re-enumerate within 20s")


def main() -> int:
    ap = argparse.ArgumentParser(description="Windows HID flasher for Kensington SlimBlade Pro")
    sub = ap.add_subparsers(dest="command", required=True)

    p_id = sub.add_parser("identify", help="List connected SlimBlade Pro / loader HID nodes")
    p_id.set_defaults(func=cmd_identify)

    p_prep = sub.add_parser("prepare-v449", help="Download, verify, and extract official v4.49 files")
    p_prep.add_argument("--out-dir", default=str(DEFAULT_FIRMWARE_DIR), help="Directory for firmware files")
    p_prep.set_defaults(func=cmd_prepare_v449)

    p_flash = sub.add_parser("flash", help="Validate container and flash over Windows HID")
    p_flash.add_argument("--container", required=True, help="Path to 128,112-byte container binary")
    p_flash.add_argument("--expected-sha256", required=True, help="Expected 64-hex SHA-256 of container")
    p_flash.add_argument(
        "--enter-loader",
        action="store_true",
        help="Send 0x0d reset-to-loader command to 047d:80d7 if not already in bootloader",
    )
    p_flash.set_defaults(func=cmd_flash)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
