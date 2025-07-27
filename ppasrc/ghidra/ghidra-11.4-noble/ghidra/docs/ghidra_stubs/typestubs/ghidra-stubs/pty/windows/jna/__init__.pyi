from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.sun.jna # type: ignore
import com.sun.jna.win32 # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class JobApiNative(com.sun.jna.win32.StdCallLibrary):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[JobApiNative]

    def AssignProcessToJobObject(self, hJob: com.sun.jna.platform.win32.WinNT.HANDLE, hProcess: com.sun.jna.platform.win32.WinNT.HANDLE) -> com.sun.jna.platform.win32.WinDef.BOOL:
        ...

    def CreateJobObjectW(self, lpJobAttributes: ConsoleApiNative.SECURITY_ATTRIBUTES.ByReference, lpName: com.sun.jna.WString) -> com.sun.jna.platform.win32.WinNT.HANDLE:
        ...

    def TerminateJobObject(self, hJob: com.sun.jna.platform.win32.WinNT.HANDLE, uExitCode: typing.Union[jpype.JInt, int]) -> com.sun.jna.platform.win32.WinDef.BOOL:
        ...


class ConsoleApiNative(com.sun.jna.win32.StdCallLibrary):

    class COORD(com.sun.jna.Structure):

        class ByValue(ConsoleApiNative.COORD, com.sun.jna.Structure.ByValue):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class ByReference(ConsoleApiNative.COORD, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        X: jpype.JShort
        Y: jpype.JShort

        def __init__(self):
            ...


    class SECURITY_ATTRIBUTES(com.sun.jna.Structure):

        class ByReference(ConsoleApiNative.SECURITY_ATTRIBUTES, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        FIELDS: typing.Final[java.util.List[java.lang.String]]
        nLength: com.sun.jna.platform.win32.WinDef.DWORD
        lpSecurityDescriptor: com.sun.jna.platform.win32.WinDef.ULONGLONG
        bInheritedHandle: com.sun.jna.platform.win32.WinDef.BOOL

        def __init__(self):
            ...


    class PROC_THREAD_ATTRIBUTE_LIST(com.sun.jna.Structure):

        class ByReference(ConsoleApiNative.PROC_THREAD_ATTRIBUTE_LIST, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        FIELDS: typing.Final[java.util.List[java.lang.String]]
        dwFlags: com.sun.jna.platform.win32.WinDef.DWORD
        Size: com.sun.jna.platform.win32.WinDef.ULONG
        Count: com.sun.jna.platform.win32.WinDef.ULONG
        Reserved: com.sun.jna.platform.win32.WinDef.ULONG
        Unknown: com.sun.jna.platform.win32.WinDef.ULONGLONG

        def __init__(self):
            ...


    class STARTUPINFOEX(com.sun.jna.Structure):

        class ByReference(ConsoleApiNative.STARTUPINFOEX, com.sun.jna.Structure.ByReference):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]
        FIELDS: typing.Final[java.util.List[java.lang.String]]
        StartupInfo: com.sun.jna.platform.win32.WinBase.STARTUPINFO
        lpAttributeList: com.sun.jna.Pointer

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ConsoleApiNative]
    FAIL: typing.Final[com.sun.jna.platform.win32.WinDef.BOOL]

    def ClosePseudoConsole(self, hPC: com.sun.jna.platform.win32.WinNT.HANDLE):
        ...

    def CreatePipe(self, hReadPipe: com.sun.jna.platform.win32.WinNT.HANDLEByReference, hWritePipe: com.sun.jna.platform.win32.WinNT.HANDLEByReference, lpPipeAttributes: ConsoleApiNative.SECURITY_ATTRIBUTES.ByReference, nSize: com.sun.jna.platform.win32.WinDef.DWORD) -> com.sun.jna.platform.win32.WinDef.BOOL:
        ...

    def CreateProcessW(self, lpApplicationName: com.sun.jna.WString, lpCommandLine: com.sun.jna.WString, lpProcessAttributes: com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES, lpThreadAttributes: com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES, bInheritHandles: typing.Union[jpype.JBoolean, bool], dwCreationFlags: com.sun.jna.platform.win32.WinDef.DWORD, lpEnvironment: com.sun.jna.WString, lpCurrentDirectory: com.sun.jna.WString, lpStartupInfo: ConsoleApiNative.STARTUPINFOEX, lpProcessInformation: com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION) -> com.sun.jna.platform.win32.WinDef.BOOL:
        ...

    def CreatePseudoConsole(self, size: ConsoleApiNative.COORD.ByValue, hInput: com.sun.jna.platform.win32.WinNT.HANDLE, hOutput: com.sun.jna.platform.win32.WinNT.HANDLE, dwFlags: com.sun.jna.platform.win32.WinDef.DWORD, phPC: com.sun.jna.platform.win32.WinNT.HANDLEByReference) -> com.sun.jna.platform.win32.WinNT.HRESULT:
        ...

    def InitializeProcThreadAttributeList(self, lpAttributeList: com.sun.jna.Pointer, dwAttributeCount: com.sun.jna.platform.win32.WinDef.DWORD, dwFlags: com.sun.jna.platform.win32.WinDef.DWORD, lpSize: com.sun.jna.platform.win32.WinDef.UINTByReference) -> com.sun.jna.platform.win32.WinDef.BOOL:
        ...

    def ResizePseudoConsole(self, hPC: com.sun.jna.platform.win32.WinNT.HANDLE, size: ConsoleApiNative.COORD.ByValue) -> com.sun.jna.platform.win32.WinNT.HRESULT:
        ...

    def UpdateProcThreadAttribute(self, lpAttributeList: com.sun.jna.Pointer, dwFlags: com.sun.jna.platform.win32.WinDef.DWORD, Attribute: com.sun.jna.platform.win32.WinDef.DWORD, lpValue: com.sun.jna.platform.win32.WinDef.PVOID, cbSize: com.sun.jna.platform.win32.WinDef.DWORD, lpPreviousValue: com.sun.jna.platform.win32.WinDef.PVOID, lpReturnSize: com.sun.jna.platform.win32.WinDef.ULONGLONGByReference) -> com.sun.jna.platform.win32.WinDef.BOOL:
        ...



__all__ = ["JobApiNative", "ConsoleApiNative"]
