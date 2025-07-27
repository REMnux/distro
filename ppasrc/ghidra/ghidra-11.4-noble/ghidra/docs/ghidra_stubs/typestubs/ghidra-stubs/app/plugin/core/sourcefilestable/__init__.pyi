from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.table.threaded
import ghidra.app.plugin
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.database.sourcemap
import ghidra.program.model.address
import ghidra.program.model.sourcemap
import ghidra.util.table
import java.lang # type: ignore


class SourceFileRowObject(java.lang.Object):
    """
    The row object used by :obj:`SourceFilesTableModel`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, sourceManager: ghidra.program.model.sourcemap.SourceFileManager):
        """
        Constructor
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :param ghidra.program.model.sourcemap.SourceFileManager sourceManager: source file manager
        """

    def getFileName(self) -> str:
        ...

    def getNumSourceMapEntries(self) -> int:
        ...

    def getPath(self) -> str:
        ...

    def getSourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        ...

    def getSourceFileIdType(self) -> ghidra.program.database.sourcemap.SourceFileIdType:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def fileName(self) -> java.lang.String:
        ...

    @property
    def sourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        ...

    @property
    def sourceFileIdType(self) -> ghidra.program.database.sourcemap.SourceFileIdType:
        ...

    @property
    def numSourceMapEntries(self) -> jpype.JInt:
        ...


class SourceFilesTableModel(docking.widgets.table.threaded.ThreadedTableModelStub[SourceFileRowObject]):
    """
    A table model for displaying all of the :obj:`SourceFile`s which have been added
    to a program's :obj:`SourceFileManager`.
    """

    @typing.type_check_only
    class PathColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceFileRowObject, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IdTypeColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceFileRowObject, ghidra.program.database.sourcemap.SourceFileIdType, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FileNameColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceFileRowObject, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TransformedPathColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceFileRowObject, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IdentifierColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceFileRowObject, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NumMappedEntriesColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceFileRowObject, java.lang.Integer, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class SourceMapEntryRowObject(java.lang.Object):
    """
    A row object class for :obj:`SourceMapEntryTableModel`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, baseAddress: ghidra.program.model.address.Address, lineNumber: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JLong, int], count: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param ghidra.program.model.address.Address baseAddress: base address
        :param jpype.JInt or int lineNumber: source line number
        :param jpype.JLong or int length: length of entry
        :param jpype.JInt or int count: number of mappings for source line
        """

    def getBaseAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the base address
        
        :return: base address
        :rtype: ghidra.program.model.address.Address
        """

    def getCount(self) -> int:
        """
        Returns the number of entries for this line number
        
        :return: number of entries
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of the associated source map entry
        
        :return: entry length
        :rtype: int
        """

    def getLineNumber(self) -> int:
        """
        Returns the source file line number
        
        :return: line number
        :rtype: int
        """

    @property
    def baseAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...


class SourceMapEntryToProgramLocationRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[SourceMapEntryRowObject, ghidra.program.util.ProgramLocation]):
    """
    A row mapper for :obj:`SourceMapEntryRowObject`s.  Returns a :obj:`ProgramLocation` 
    corresponding to the base address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SourceFilesTableProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    A :obj:`ComponentProviderAdapter` for displaying source file information about a program.
    This includes the :obj:`SourceFile`s added to the program's :obj:`SourceFileManager` as
    well as source file path transformations.
    """

    @typing.type_check_only
    class SourceFilesTableActionContext(docking.DefaultActionContext):

        class_: typing.ClassVar[java.lang.Class]

        def getSelectedRowCount(self) -> int:
            ...

        @property
        def selectedRowCount(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class TransformTableActionContext(docking.DefaultActionContext):

        class_: typing.ClassVar[java.lang.Class]

        def getSelectedRowCount(self) -> int:
            ...

        @property
        def selectedRowCount(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceFilesPlugin: SourceFilesTablePlugin):
        """
        Constructor
        
        :param SourceFilesTablePlugin sourceFilesPlugin: plugin
        """


class TransformerTableModel(docking.widgets.table.threaded.ThreadedTableModelStub[ghidra.program.model.sourcemap.SourcePathTransformRecord]):
    """
    A table model for source path transform information
    """

    @typing.type_check_only
    class SourceColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.sourcemap.SourcePathTransformRecord, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TargetColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.sourcemap.SourcePathTransformRecord, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IsDirectoryTransformColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.program.model.sourcemap.SourcePathTransformRecord, java.lang.Boolean, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: SourceFilesTablePlugin):
        """
        Constructor
        
        :param SourceFilesTablePlugin plugin: plugin
        """


class SourceMapEntryTableModel(ghidra.util.table.GhidraProgramTableModel[SourceMapEntryRowObject]):
    """
    A table model for displaying all the :obj:`SourceMapEntry`s for a given :obj:`SourceFile`.
    """

    @typing.type_check_only
    class BaseAddressTableColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceMapEntryRowObject, ghidra.program.model.address.Address, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EndAddressTableColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceMapEntryRowObject, ghidra.program.model.address.Address, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LengthTableColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceMapEntryRowObject, java.lang.Long, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LineNumberTableColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceMapEntryRowObject, java.lang.Integer, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CountTableColumn(docking.widgets.table.AbstractDynamicTableColumn[SourceMapEntryRowObject, java.lang.Integer, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class SourceFilesTablePlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.options.OptionsChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool plugintool: tool
        """


class SourceMapEntryToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[SourceMapEntryRowObject, ghidra.program.model.address.Address]):
    """
    A row mapper for :obj:`SourceMapEntryRowObject`s.  Returns the base address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SourceFileRowObject", "SourceFilesTableModel", "SourceMapEntryRowObject", "SourceMapEntryToProgramLocationRowMapper", "SourceFilesTableProvider", "TransformerTableModel", "SourceMapEntryTableModel", "SourceFilesTablePlugin", "SourceMapEntryToAddressTableRowMapper"]
