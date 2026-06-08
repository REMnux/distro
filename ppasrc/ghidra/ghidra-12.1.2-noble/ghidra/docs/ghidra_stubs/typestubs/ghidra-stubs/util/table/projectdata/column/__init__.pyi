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

    def __init__(self) -> None:
        ...


class AddressSizeProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.Integer]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class LanguageProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ExecutablePathProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class CompilerProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class EndianProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[ghidra.program.model.lang.Endian]):
    """
    Column for the ProjectDataTable (Frontend) to display the endianness of a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class CreatedWithProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class FormatProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class DomainFileSizeProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.Long]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class Md5ProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class CreationDateProjectDataColumn(ghidra.framework.main.datatable.ProjectDataColumn[java.util.Date]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...



__all__ = ["ProcessorProjectDataColumn", "AddressSizeProjectDataColumn", "LanguageProjectDataColumn", "ExecutablePathProjectDataColumn", "CompilerProjectDataColumn", "EndianProjectDataColumn", "CreatedWithProjectDataColumn", "FormatProjectDataColumn", "DomainFileSizeProjectDataColumn", "Md5ProjectDataColumn", "CreationDateProjectDataColumn"]
