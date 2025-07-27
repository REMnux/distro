from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.replace
import java.lang # type: ignore


class DataTypesSearchAndReplaceHandler(ghidra.features.base.replace.SearchAndReplaceHandler):
    """
    :obj:`SearchAndReplaceHandler` for handling search and replace for datatype names,
    structure and union field names, structure and union field comments, enum value names,
    and enum value comments.
    """

    @typing.type_check_only
    class DataTypeSearchType(ghidra.features.base.replace.SearchType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: ghidra.features.base.replace.SearchAndReplaceHandler, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class NameSearchType(DataTypesSearchAndReplaceHandler.DataTypeSearchType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: ghidra.features.base.replace.SearchAndReplaceHandler):
            ...


    @typing.type_check_only
    class FieldNameSearchType(DataTypesSearchAndReplaceHandler.DataTypeSearchType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: ghidra.features.base.replace.SearchAndReplaceHandler):
            ...


    @typing.type_check_only
    class DataTypeCommentsSearchType(DataTypesSearchAndReplaceHandler.DataTypeSearchType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: ghidra.features.base.replace.SearchAndReplaceHandler):
            ...


    @typing.type_check_only
    class EnumValueSearchType(DataTypesSearchAndReplaceHandler.DataTypeSearchType):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: ghidra.features.base.replace.SearchAndReplaceHandler):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DatatypeCategorySearchAndReplaceHandler(ghidra.features.base.replace.SearchAndReplaceHandler):
    """
    :obj:`SearchAndReplaceHandler` for handling search and replace for datatype category names.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramTreeSearchAndReplaceHandler(ghidra.features.base.replace.SearchAndReplaceHandler):
    """
    :obj:`SearchAndReplaceHandler` for handling search and replace for program tree modules and
    fragments.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SymbolsSearchAndReplaceHandler(ghidra.features.base.replace.SearchAndReplaceHandler):
    """
    :obj:`SearchAndReplaceHandler` for handling search and replace for symbols. Specifically, it
    provides :obj:`SearchType`s for renaming labels, functions, namespaces, classes, local 
    variables, and parameters.
    """

    @typing.type_check_only
    class SymbolSearchType(ghidra.features.base.replace.SearchType):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ListingCommentsSearchAndReplaceHandler(ghidra.features.base.replace.SearchAndReplaceHandler):
    """
    :obj:`SearchAndReplaceHandler` for handling search and replace for listing comments on 
    instructions or data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MemoryBlockSearchAndReplaceHandler(ghidra.features.base.replace.SearchAndReplaceHandler):
    """
    :obj:`SearchAndReplaceHandler` for handling search and replace for memory block names.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["DataTypesSearchAndReplaceHandler", "DatatypeCategorySearchAndReplaceHandler", "ProgramTreeSearchAndReplaceHandler", "SymbolsSearchAndReplaceHandler", "ListingCommentsSearchAndReplaceHandler", "MemoryBlockSearchAndReplaceHandler"]
