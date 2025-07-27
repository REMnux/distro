from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.formats.gfilesystem
import java.awt # type: ignore
import java.io # type: ignore


class GFileSystemExtractAllTask(ghidra.formats.gfilesystem.AbstractFileExtractorTask):
    """
    :obj:`Task` that recursively extracts all files from a :obj:`GFileSystem` directory
    and writes them to a local filesystem.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, srcFSRL: ghidra.formats.gfilesystem.FSRL, outputDirectory: jpype.protocol.SupportsPath, parentComponent: java.awt.Component):
        ...



__all__ = ["GFileSystemExtractAllTask"]
