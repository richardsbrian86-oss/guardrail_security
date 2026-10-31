"""Windows handles used to reject links and pin directory ancestry during I/O."""
import contextlib
import ctypes
from ctypes import wintypes
import os
from pathlib import Path


class BoundaryError(Exception):
    pass


if os.name == "nt":
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel.GetDriveTypeW.restype = wintypes.UINT


class FileInfo(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
               ("accessed", wintypes.FILETIME), ("modified", wintypes.FILETIME),
               ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
               ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
               ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]


def info(handle):
    result = FileInfo()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(result)):
        raise BoundaryError("handle_query_failed")
    return result


def open_handle(path, access=0x80000000, sharing=1, creation=3):
    if os.name != "nt":
        raise BoundaryError("windows_required")
    # OPEN_REPARSE_POINT + BACKUP_SEMANTICS; never CREATE_ALWAYS/truncate.
    handle = kernel.CreateFileW(str(path), access, sharing, None, creation,
                                0x00200000 | 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise BoundaryError("file_unavailable")
    try:
        details = info(handle)
        if details.attributes & 0x400:
            raise BoundaryError("reparse_point_denied")
        if not details.attributes & 0x10 and details.links != 1:
            raise BoundaryError("hardlink_denied")
        buffer = ctypes.create_unicode_buffer(32768)
        size = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not size or size >= len(buffer):
            raise BoundaryError("handle_query_failed")
        final = buffer.value
        if not final.startswith("\\\\?\\") or final.startswith("\\\\?\\UNC\\"):
            raise BoundaryError("nonlocal_path_denied")
        if os.path.normcase(final[4:]) != os.path.normcase(str(path)):
            raise BoundaryError("path_alias_denied")
        return handle
    except BaseException:
        kernel.CloseHandle(handle)
        raise


@contextlib.contextmanager
def pin_directory(path, mutation=False):
    """Reject reparse points and hold ancestry against rename/deletion.

    Windows rename needs write sharing on parent directory handles. A mutating
    caller therefore requires deployment ACLs excluding external directory
    writers; this lock alone cannot stop reparse metadata changes by that user.
    """
    if os.name != "nt":
        raise BoundaryError("windows_required")
    path = Path(path)
    if not path.is_absolute() or path.drive.startswith("\\"):
        raise BoundaryError("absolute_local_path_required")
    if kernel.GetDriveTypeW(path.anchor) != 3:
        raise BoundaryError("fixed_local_drive_required")
    handles = []
    try:
        for part in [*reversed(path.parents), path]:
            # Attribute-only handles do not establish the needed sharing lock.
            handle = open_handle(part, access=0x80000000,
                                 sharing=3 if mutation else 1)  # GENERIC_READ
            handles.append(handle)
            if not info(handle).attributes & 0x10:
                raise BoundaryError("directory_required")
        yield
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


@contextlib.contextmanager
def locked_file(path, create=False):
    """A read handle or exclusive CREATE_NEW handle, verified before data access."""
    handle = open_handle(path, access=0xC0000000 if create else 0x80000000,
                         sharing=0 if create else 1, creation=1 if create else 3)
    try:
        if info(handle).attributes & 0x10:
            raise BoundaryError("regular_file_required")
        fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if create else os.O_RDONLY))
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, "w+b" if create else "rb") as stream:
        yield stream


@contextlib.contextmanager
def exclusive_lock(path):
    handle = open_handle(path, access=0xC0000000, sharing=0, creation=4)  # OPEN_ALWAYS
    try:
        if info(handle).attributes & 0x10:
            raise BoundaryError("regular_file_required")
        yield
    finally:
        kernel.CloseHandle(handle)
