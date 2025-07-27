from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.plugins.fsbrowser
import java.lang # type: ignore


class ImportFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_IMPORT_SINGLE: typing.Final = "FSB Import Single"

    def __init__(self):
        ...


class LibrarySearchPathFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BatchImportFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ExportFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_EXPORT_ALL: typing.Final = "FSB Export All"
    FSB_EXPORT: typing.Final = "FSB Export"

    def __init__(self):
        ...


class ImageFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_VIEW_AS_IMAGE: typing.Final = "FSB View As Image"

    def __init__(self):
        ...


class ClearCachedPwdFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RefreshFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ListMountedFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TextFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_VIEW_AS_TEXT: typing.Final = "FSB View As Text"

    def __init__(self):
        ...


class CloseFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_CLOSE: typing.Final = "FSB Close"

    def __init__(self):
        ...


class OpenWithFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddToProgramFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpenFsFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_OPEN_FILE_SYSTEM_CHOOSER: typing.Final = "FSB Open File System Chooser"
    FSB_OPEN_FILE_SYSTEM_IN_NEW_WINDOW: typing.Final = "FSB Open File System In New Window"
    FSB_OPEN_FILE_SYSTEM_NESTED: typing.Final = "FSB Open File System Nested"

    def __init__(self):
        ...


class GetInfoFSBFileHandler(ghidra.plugins.fsbrowser.FSBFileHandler):

    class_: typing.ClassVar[java.lang.Class]
    FSB_GET_INFO: typing.Final = "FSB Get Info"

    def __init__(self):
        ...



__all__ = ["ImportFSBFileHandler", "LibrarySearchPathFSBFileHandler", "BatchImportFSBFileHandler", "ExportFSBFileHandler", "ImageFSBFileHandler", "ClearCachedPwdFSBFileHandler", "RefreshFSBFileHandler", "ListMountedFSBFileHandler", "TextFSBFileHandler", "CloseFSBFileHandler", "OpenWithFSBFileHandler", "AddToProgramFSBFileHandler", "OpenFsFSBFileHandler", "GetInfoFSBFileHandler"]
