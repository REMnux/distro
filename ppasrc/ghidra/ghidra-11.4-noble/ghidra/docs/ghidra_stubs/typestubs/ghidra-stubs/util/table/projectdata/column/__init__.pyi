from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.main.datatable


class ProcessorProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressSizeProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.Integer]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LanguageProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ExecutablePathProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CompilerProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EndianProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[ghidra.program.model.lang.Endian]):
    """
    Column for the ProjectDataTable (Frontend) to display the endianness of a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CreatedWithProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FormatProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DomainFileSizeProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.Long]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Md5ProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CreationDateProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.util.Date]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ProcessorProjectDataColumn", "AddressSizeProjectDataColumn", "LanguageProjectDataColumn", "ExecutablePathProjectDataColumn", "CompilerProjectDataColumn", "EndianProjectDataColumn", "CreatedWithProjectDataColumn", "FormatProjectDataColumn", "DomainFileSizeProjectDataColumn", "Md5ProjectDataColumn", "CreationDateProjectDataColumn"]
