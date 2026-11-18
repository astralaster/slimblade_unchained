#!/usr/bin/env python3
"""Measure SlimBlade Pro mouse report interval on Windows via Win32 Raw Input.

Usage:
    python tools/measure_rate_windows.py              # 047d:80d7 wired, 8 s
    python tools/measure_rate_windows.py --pid 80d6   # 2.4 GHz receiver
    python tools/measure_rate_windows.py -s 10

Spin the ball continuously while running. Reports are only emitted when motion or
button state changes, so stationary pauses appear as gaps >= 50 ms and are filtered
out of the active cadence histogram (matching tools/measure_rate.py).
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import sys
import time

WM_INPUT = 0x00FF
PM_REMOVE = 0x0001
QS_ALLINPUT = 0x04FF
WAIT_TIMEOUT = 0x00000102
HWND_MESSAGE = ctypes.c_void_p(-3).value
RIDEV_INPUTSINK = 0x00000100
RID_INPUT = 0x10000003
RIM_TYPEMOUSE = 0
RIDI_DEVICENAME = 0x20000007

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT),
        ("style", wt.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE),
        ("hIcon", wt.HICON),
        ("hCursor", wt.HCURSOR),
        ("hbrBackground", wt.HBRUSH),
        ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR),
        ("hIconSm", wt.HICON),
    ]


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", wt.USHORT),
        ("usUsage", wt.USHORT),
        ("dwFlags", wt.DWORD),
        ("hwndTarget", wt.HWND),
    ]


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", wt.DWORD),
        ("dwSize", wt.DWORD),
        ("hDevice", wt.HANDLE),
        ("wParam", wt.WPARAM),
    ]


class RAWMOUSE_BUTTONS(ctypes.Structure):
    _fields_ = [("usButtonFlags", wt.USHORT), ("usButtonData", wt.USHORT)]


class RAWMOUSE_UNION(ctypes.Union):
    _fields_ = [("ulButtons", wt.ULONG), ("buttons", RAWMOUSE_BUTTONS)]


class RAWMOUSE(ctypes.Structure):
    _fields_ = [
        ("usFlags", wt.USHORT),
        ("u", RAWMOUSE_UNION),
        ("ulRawButtons", wt.ULONG),
        ("lLastX", wt.LONG),
        ("lLastY", wt.LONG),
        ("ulExtraInformation", wt.ULONG),
    ]


class RAWINPUT_MOUSE(ctypes.Structure):
    _fields_ = [("header", RAWINPUTHEADER), ("mouse", RAWMOUSE)]


assert RAWMOUSE.lLastX.offset == 12
assert ctypes.sizeof(RAWMOUSE) == 24

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleW.restype = wt.HMODULE

user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DefWindowProcW.restype = LRESULT

user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
user32.RegisterClassExW.restype = wt.ATOM

user32.UnregisterClassW.argtypes = [wt.LPCWSTR, wt.HINSTANCE]
user32.UnregisterClassW.restype = wt.BOOL

user32.CreateWindowExW.argtypes = [
    wt.DWORD,
    wt.LPCWSTR,
    wt.LPCWSTR,
    wt.DWORD,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    wt.HWND,
    wt.HMENU,
    wt.HINSTANCE,
    wt.LPVOID,
]
user32.CreateWindowExW.restype = wt.HWND

user32.DestroyWindow.argtypes = [wt.HWND]
user32.DestroyWindow.restype = wt.BOOL

user32.RegisterRawInputDevices.argtypes = [ctypes.POINTER(RAWINPUTDEVICE), wt.UINT, wt.UINT]
user32.RegisterRawInputDevices.restype = wt.BOOL

user32.GetRawInputData.argtypes = [
    wt.HANDLE,
    wt.UINT,
    ctypes.c_void_p,
    ctypes.POINTER(wt.UINT),
    wt.UINT,
]
user32.GetRawInputData.restype = wt.UINT

user32.GetRawInputDeviceInfoW.argtypes = [wt.HANDLE, wt.UINT, ctypes.c_void_p, ctypes.POINTER(wt.UINT)]
user32.GetRawInputDeviceInfoW.restype = wt.UINT

user32.MsgWaitForMultipleObjects.argtypes = [wt.DWORD, ctypes.c_void_p, wt.BOOL, wt.DWORD, wt.DWORD]
user32.MsgWaitForMultipleObjects.restype = wt.DWORD

user32.PeekMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT, wt.UINT]
user32.PeekMessageW.restype = wt.BOOL

user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
user32.TranslateMessage.restype = wt.BOOL

user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.restype = LRESULT


def get_device_name(h_device: int) -> str:
    if not h_device:
        return ""
    chars = wt.UINT(0)
    user32.GetRawInputDeviceInfoW(h_device, RIDI_DEVICENAME, None, ctypes.byref(chars))
    if chars.value == 0:
        return ""
    buf = ctypes.create_unicode_buffer(chars.value)
    res = user32.GetRawInputDeviceInfoW(h_device, RIDI_DEVICENAME, buf, ctypes.byref(chars))
    if res == 0xFFFFFFFF:
        return ""
    return buf.value


def capture_raw_mouse(vid: str, pid: str, seconds: float):
    needle = f"vid_{vid.lower()}&pid_{pid.lower()}"
    device_cache: dict[int, tuple[bool, str]] = {}
    matched_devices: set[str] = set()
    stamps: list[float] = []
    deltas: list[tuple[int, int]] = []
    raw_buf = ctypes.create_string_buffer(256)

    def on_message(hwnd, msg, wparam, lparam):
        if msg == WM_INPUT:
            now = time.perf_counter()
            size = wt.UINT(ctypes.sizeof(raw_buf))
            copied = user32.GetRawInputData(
                lparam, RID_INPUT, raw_buf, ctypes.byref(size), ctypes.sizeof(RAWINPUTHEADER)
            )
            if copied != 0xFFFFFFFF and copied >= ctypes.sizeof(RAWINPUT_MOUSE):
                ri = RAWINPUT_MOUSE.from_buffer_copy(raw_buf.raw[: ctypes.sizeof(RAWINPUT_MOUSE)])
                if ri.header.dwType == RIM_TYPEMOUSE:
                    hdev = ri.header.hDevice or 0
                    cached = device_cache.get(hdev)
                    if cached is None:
                        name = get_device_name(hdev)
                        is_match = needle in name.lower()
                        cached = (is_match, name)
                        device_cache[hdev] = cached
                    if cached[0]:
                        matched_devices.add(cached[1])
                        stamps.append(now)
                        deltas.append((ri.mouse.lLastX, ri.mouse.lLastY))
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    wndproc = WNDPROC(on_message)
    hinst = kernel32.GetModuleHandleW(None)
    cls_name = f"SlimBladeRawInput_{id(wndproc)}"
    wc = WNDCLASSEXW(
        cbSize=ctypes.sizeof(WNDCLASSEXW),
        lpfnWndProc=wndproc,
        hInstance=hinst,
        lpszClassName=cls_name,
    )
    if not user32.RegisterClassExW(ctypes.byref(wc)):
        raise ctypes.WinError(ctypes.get_last_error())

    hwnd = None
    try:
        hwnd = user32.CreateWindowExW(
            0, cls_name, "SlimBladeRateMeasure", 0, 0, 0, 0, 0, HWND_MESSAGE, None, hinst, None
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())

        rid = RAWINPUTDEVICE(usUsagePage=0x01, usUsage=0x02, dwFlags=RIDEV_INPUTSINK, hwndTarget=hwnd)
        if not user32.RegisterRawInputDevices(ctypes.byref(rid), 1, ctypes.sizeof(RAWINPUTDEVICE)):
            raise ctypes.WinError(ctypes.get_last_error())

        msg = wt.MSG()
        deadline = time.perf_counter() + seconds
        while True:
            remain = deadline - time.perf_counter()
            if remain <= 0:
                break
            wait_ms = max(1, int(remain * 1000))
            rc = user32.MsgWaitForMultipleObjects(0, None, False, wait_ms, QS_ALLINPUT)
            if rc == WAIT_TIMEOUT:
                break
            while user32.PeekMessageW(ctypes.byref(msg), hwnd, 0, 0, PM_REMOVE):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
    finally:
        unreg = RAWINPUTDEVICE(usUsagePage=0x01, usUsage=0x02, dwFlags=0x00000001, hwndTarget=None)
        user32.RegisterRawInputDevices(ctypes.byref(unreg), 1, ctypes.sizeof(RAWINPUTDEVICE))
        if hwnd:
            user32.DestroyWindow(hwnd)
        user32.UnregisterClassW(cls_name, hinst)

    return matched_devices, stamps, deltas


def report(matched_devices, stamps, deltas) -> int:
    if matched_devices:
        for dev in sorted(matched_devices):
            print(f"device       : {dev}")
    if len(stamps) < 10:
        print("not enough reports — was the ball moving?")
        return 1

    span = stamps[-1] - stamps[0]
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    live = sorted(g for g in gaps if g < 0.050)

    print(f"reports      : {len(stamps)} over {span:.3f} s  ({(len(stamps) - 1) / span:.1f}/s)")
    if not live:
        print("no continuous motion captured")
        return 1

    median = live[len(live) // 2]
    p90 = live[int(len(live) * 0.90)]
    p99 = live[int(len(live) * 0.99)]
    print(f"interval     : median {median * 1000:.3f} ms  ->  {1 / median:.1f} Hz")
    print(
        f"               p90 {p90 * 1000:.2f} ms   p99 {p99 * 1000:.2f} ms   "
        f"max<50ms {live[-1] * 1000:.2f} ms"
    )

    buckets: dict[int, int] = {}
    for gap in live:
        ticks = max(1, round(gap * 1000))
        buckets[ticks] = buckets.get(ticks, 0) + 1
    print("frame ticks  :")
    for ticks in sorted(buckets):
        share = 100 * buckets[ticks] / len(live)
        label = f"{ticks} ms" if ticks < 9 else ">=9 ms"
        print(f"  {label:>6}   {buckets[ticks]:6d}  {share:5.1f}%  {'#' * int(share / 2)}")

    dx = sum(abs(x) for x, _ in deltas)
    dy = sum(abs(y) for _, y in deltas)
    zero = sum(1 for x, y in deltas if x == 0 and y == 0)
    print(f"motion       : sum|dx| {dx}  sum|dy| {dy}  ->  {(dx + dy) / span:.0f} counts/s")
    print(
        f"               mean |dx| {dx / len(deltas):.2f}  mean |dy| {dy / len(deltas):.2f}  per report"
    )
    print(f"zero-delta   : {zero}/{len(deltas)} ({100 * zero / len(deltas):.1f}%)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure SlimBlade Pro polling rate on Windows")
    ap.add_argument("--vid", default="047d", help="USB vendor id (hex)")
    ap.add_argument("-p", "--pid", default="80d7", help="USB product id: 80d7 wired, 80d6 2.4 GHz")
    ap.add_argument("-s", "--seconds", type=float, default=8.0, help="Capture duration in seconds")
    args = ap.parse_args()

    print(f"listening for Raw Input mouse vid_{args.vid.lower()}&pid_{args.pid.lower()} for {args.seconds:.1f}s (spin the ball)...")
    matched_devices, stamps, deltas = capture_raw_mouse(args.vid, args.pid, args.seconds)
    return report(matched_devices, stamps, deltas)


if __name__ == "__main__":
    sys.exit(main())
