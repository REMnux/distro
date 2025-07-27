from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.cache
import generic.concurrent
import ghidra.app.decompiler
import ghidra.app.util
import ghidra.app.util.importer
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class XmlExporter(Exporter):
    """
    An implementation of exporter that creates
    an XML representation of the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new XML exporter.
        """


class OriginalFileExporter(Exporter):
    """
    An :obj:`Exporter` that can export :obj:`the originally imported file <FileBytes>`.
     
    
    WARNING: Programs written to disk with this exporter may be runnable on your native platform.
    Use caution when exporting potentially malicious programs.
    """

    @typing.type_check_only
    class FileBytesInputStream(java.io.InputStream):
        """
        An :obj:`InputStream` that reads a :obj:`FileBytes` modified or unmodified (original) bytes
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new :obj:`OriginalFileExporter`
        """


@typing.type_check_only
class AbstractLineDispenser(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProgramTextWriter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AsciiExporter(Exporter):
    """
    An implementation of exporter that creates
    an Ascii representation of the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new Ascii exporter.
        """


class GzfExporter(Exporter):

    class_: typing.ClassVar[java.lang.Class]
    EXTENSION: typing.Final = "gzf"
    SUFFIX: typing.Final = ".gzf"
    NAME: typing.Final = "Ghidra Zip File"

    def __init__(self):
        ...

    def canExportDomainObject(self, domainObjectClass: java.lang.Class[ghidra.framework.model.DomainObject]) -> bool:
        ...

    def supportsAddressRestrictedExport(self) -> bool:
        """
        Returns false.  GZF export only supports entire database.
        """


class ExporterException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        ...


@typing.type_check_only
class ProgramTextOptions(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class IntelHexExporter(Exporter):
    """
    Exports the current program (or program selection) as bytes in Intel Hex format. 
     
    
    The output defaults to lines of 16-bytes but this is configurable using the
    :obj:`.recordSizeOption` attribute. This allows users to select any record size
    up to the max of 0xFF. Users may also choose to ``Drop Extra Bytes``, which will
    cause only lines that match the max record size to be printed; any other 
    bytes will be dropped. If this option is not set, every byte will be represented in the output.
    """

    @typing.type_check_only
    class BoundedIntegerVerifier(javax.swing.InputVerifier):
        """
        Verifier for a :obj:`HintTextField` that ensures input is a numeric value between
        0 and 0xFF.
         
        
        Input may be specified in either decimal or hex.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RecordSizeOption(ghidra.app.util.Option):
        """
        Option for exporting Intel Hex records that allows users to specify a record size for the
        output. Users may also optionally select the ``Drop Extra Bytes`` option that 
        will cause only those records that match the maximum size to be output to the file.
        
        
        .. seealso::
        
            | :obj:`RecordSizeComponent`
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[typing.Any]):
            ...

        @typing.overload
        def __init__(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[typing.Any], value: java.lang.Object, arg: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
            ...

        def dropExtraBytes(self) -> bool:
            ...

        def setDropBytes(self, dropBytes: typing.Union[jpype.JBoolean, bool]):
            ...

        def setRecordSize(self, recordSize: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class RecordSizeComponent(javax.swing.JPanel):
        """
        Component that displays two widgets for setting export options: 
         
         
        * input: a :obj:`HintTextField` for entering numeric digits; these 
        represent the record size for each line of output
        * dropCb: a :obj:`JCheckBox` for specifying a setting that enforces that every line in 
        the output matches the specified record size
        
         
        Note: If the ``Drop Extra Bytes`` option is set, any bytes that are left over 
        after outputting all lines that match the record size will be omitted from the output.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recordSize: typing.Union[jpype.JInt, int]):
            ...

        def dropExtraBytes(self) -> bool:
            ...

        def getValue(self) -> int:
            ...

        def setDropBytes(self, dropBytes: typing.Union[jpype.JBoolean, bool]):
            ...

        def setRecordSize(self, recordSize: typing.Union[jpype.JInt, int]):
            ...

        @property
        def value(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new Intel Hex exporter. This will use a record size of 16 (the default)
        and will export ALL bytes in the program or selection (even if the total length
        is not a multiple of 16.
        """

    @typing.overload
    def __init__(self, recordSize: typing.Union[jpype.JInt, int], dropBytes: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new Intel Hex exporter with a custom record size.
        
        :param jpype.JInt or int recordSize: the record size to use when writing to the output file
        :param jpype.JBoolean or bool dropBytes: if true, bytes at the end of the file that don't match the specified 
        record size will be dropped
        """


@typing.type_check_only
class CommentLineDispenser(AbstractLineDispenser):
    ...
    class_: typing.ClassVar[java.lang.Class]


class StringComparer(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def compareLines(expectedList: java.util.List[java.lang.String], actualFile: jpype.protocol.SupportsPath):
        ...


class GdtExporter(Exporter):

    class_: typing.ClassVar[java.lang.Class]
    EXTENSION: typing.Final = "gdt"
    SUFFIX: typing.Final = ".gdt"
    NAME: typing.Final = "Ghidra Data Type Archive File"

    def __init__(self):
        ...

    def supportsAddressRestrictedExport(self) -> bool:
        """
        Returns false.  GDT export only supports entire database.
        """


class HtmlExporter(Exporter):
    """
    An implementation of exporter that creates
    an HTML representation of the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new HTML exporter.
        """


class Exporter(ghidra.util.classfinder.ExtensionPoint):
    """
    The interface that all exporters must implement.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canExportDomainFile(self, domainFile: ghidra.framework.model.DomainFile) -> bool:
        """
        Returns true if exporter can export the specified :obj:`DomainFile` without instantiating 
        a :obj:`DomainObject`.  This method should be used prior to exporting using the
        :meth:`export(File, DomainFile, TaskMonitor) <.export>` method.  All exporter capable of a 
        :obj:`DomainFile` export must also support a export of a :obj:`DomainObject` so that any
        possible data modification/upgrade is included within resulting export.
        
        :param ghidra.framework.model.DomainFile domainFile: domain file
        :return: true if export can occur else false if not
        :rtype: bool
        """

    @typing.overload
    def canExportDomainObject(self, domainObjectClass: java.lang.Class[ghidra.framework.model.DomainObject]) -> bool:
        """
        Returns true if this exporter is capable of exporting the given domain file/object content
        type.  For example, some exporters have the ability to export programs, other exporters can 
        export project data type archives.
         
        
        NOTE: This method should only be used as a preliminary check, if neccessary, to identify 
        exporter implementations that are capable of handling a specified content type/class.  Prior
        to export a final check should be performed based on the export or either a 
        :obj:`DomainFile` or :obj:`DomainObject`:
         
        
        :obj:`DomainFile` export - the method :meth:`canExportDomainFile(DomainFile) <.canExportDomainFile>` should be 
        used to verify a direct project file export is possible using the 
        :meth:`export(File, DomainFile, TaskMonitor) <.export>` method.
         
        
        :obj:`DomainObject` export - the method :meth:`canExportDomainObject(DomainObject) <.canExportDomainObject>` should 
        be used to verify an export of a specific object is possible using the 
        :meth:`export(File, DomainObject, AddressSetView, TaskMonitor) <.export>` method.
         
        avoid opening DomainFile when possible.
        
        :param java.lang.Class[ghidra.framework.model.DomainObject] domainObjectClass: the class of the domain object to test for exporting.
        :return: true if this exporter knows how to export the given domain object type.
        :rtype: bool
        """

    @typing.overload
    def canExportDomainObject(self, domainObject: ghidra.framework.model.DomainObject) -> bool:
        """
        Returns true if this exporter knows how to export the given domain object considering any
        constraints based on the specific makeup of the object.  This method should be used prior to
        exporting using the :meth:`export(File, DomainObject, AddressSetView, TaskMonitor) <.export>` method.
        
        :param ghidra.framework.model.DomainObject domainObject: the domain object to test for exporting.
        :return: true if this exporter knows how to export the given domain object.
        :rtype: bool
        """

    @typing.overload
    def export(self, file: jpype.protocol.SupportsPath, domainObj: ghidra.framework.model.DomainObject, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Actually does the work of exporting a :obj:`DomainObject`.  Export will include all 
        saved and unsaved modifications which may have been made to the object.
        
        :param jpype.protocol.SupportsPath file: the output file to write the exported info
        :param ghidra.framework.model.DomainObject domainObj: the domain object to export
        :param ghidra.program.model.address.AddressSetView addrSet: the address set if only a portion of the program should be exported
                            NOTE: see :meth:`supportsAddressRestrictedExport() <.supportsAddressRestrictedExport>`.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the program was successfully exported; otherwise, false.  If the program
        was not successfully exported, the message log should be checked to find the source of
        the error.
        :rtype: bool
        :raises ExporterException: if export error occurs
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def export(self, file: jpype.protocol.SupportsPath, domainFile: ghidra.framework.model.DomainFile, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Actually does the work of exporting a domain file, if supported (see
        :meth:`canExportDomainFile(DomainFile) <.canExportDomainFile>`).  Export is performed without instantiation of a
        :obj:`DomainObject`.
        
        :param jpype.protocol.SupportsPath file: the output file to write the exported info
        :param ghidra.framework.model.DomainFile domainFile: the domain file to be exported (e.g., packed DB file)
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the file was successfully exported; otherwise, false.  If the file
        was not successfully exported, the message log should be checked to find the source of
        the error.
        :rtype: bool
        :raises ExporterException: if export error occurs
        :raises IOException: if an IO error occurs
        """

    def getDefaultFileExtension(self) -> str:
        """
        Returns the default extension for this exporter.
        For example, .html for .xml.
        
        :return: the default extension for this exporter
        :rtype: str
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help location for this exporter.
        It should return null only if no help documentation exists.
        
        :return: the help location for this exporter
        :rtype: ghidra.util.HelpLocation
        """

    def getMessageLog(self) -> ghidra.app.util.importer.MessageLog:
        """
        Returns the message log the may have been created during an export.
        The message log is used to log warnings and other non-critical messages.
        
        :return: the message log
        :rtype: ghidra.app.util.importer.MessageLog
        """

    def getName(self) -> str:
        """
        Returns the display name of this exporter.
        
        :return: the display name of this exporter
        :rtype: str
        """

    def getOptions(self, domainObjectService: ghidra.app.util.DomainObjectService) -> java.util.List[ghidra.app.util.Option]:
        """
        Returns the available options for this exporter.
        The program is needed because some exporters
        may have options that vary depending on the specific
        program being exported.
        
        :param ghidra.app.util.DomainObjectService domainObjectService: a service for retrieving the applicable domainObject.
        :return: the available options for this exporter
        :rtype: java.util.List[ghidra.app.util.Option]
        """

    def setExporterServiceProvider(self, provider: ghidra.framework.plugintool.ServiceProvider):
        """
        Sets the exporter service provider.
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the exporter service provider
        """

    def setOptions(self, options: java.util.List[ghidra.app.util.Option]):
        """
        Sets the options. This method is not for defining the options, but
        rather it is for setting the values of options. If invalid options
        are passed in, then OptionException should be thrown.
        
        :param java.util.List[ghidra.app.util.Option] options: the option values for this exporter
        :raises OptionException: if invalid options are passed in
        """

    def supportsAddressRestrictedExport(self) -> bool:
        """
        Returns true if this exporter can perform a restricted export of a :obj:`DomainObject`
        based upon a specified :obj:`AddressSetView`.
        
        :return: true if this exporter can export less than the entire domain file.
        :rtype: bool
        """

    @property
    def messageLog(self) -> ghidra.app.util.importer.MessageLog:
        ...

    @property
    def options(self) -> java.util.List[ghidra.app.util.Option]:
        ...

    @options.setter
    def options(self, value: java.util.List[ghidra.app.util.Option]):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def defaultFileExtension(self) -> java.lang.String:
        ...


@typing.type_check_only
class ReferenceLineDispenser(AbstractLineDispenser):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getXRefList(cu: ghidra.program.model.listing.CodeUnit) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...


class BinaryExporter(Exporter):
    """
    An :obj:`Exporter` that can export memory blocks as raw bytes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CppExporter(Exporter):

    @typing.type_check_only
    class CPPResult(java.lang.Record, java.lang.Comparable[CppExporter.CPPResult]):

        class_: typing.ClassVar[java.lang.Class]

        def address(self) -> ghidra.program.model.address.Address:
            ...

        def bodyCode(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def globals(self) -> java.util.List[java.lang.String]:
            ...

        def hashCode(self) -> int:
            ...

        def headerCode(self) -> str:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class DecompilerFactory(generic.cache.CountingBasicFactory[ghidra.app.decompiler.DecompInterface]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ParallelDecompilerCallback(generic.concurrent.QCallback[ghidra.program.model.listing.Function, CppExporter.CPPResult]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ChunkingTaskMonitor(ghidra.util.task.TaskMonitorAdapter):
        """
        A class that exists because we are doing something that the ConcurrentQ was not
        designed for--chunking.  We do not want out monitor being reset every time we start a new
        chunk. So, we wrap a real monitor, overriding the behavior such that initialize() has
        no effect when it is called by the queue.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    CREATE_C_FILE: typing.Final = "Create C File (.c)"
    CREATE_HEADER_FILE: typing.Final = "Create Header File (.h)"
    USE_CPP_STYLE_COMMENTS: typing.Final = "Use C++ Style Comments (//)"
    EMIT_TYPE_DEFINITONS: typing.Final = "Emit Data-type Definitions"
    EMIT_REFERENCED_GLOBALS: typing.Final = "Emit Referenced Globals"
    FUNCTION_TAG_FILTERS: typing.Final = "Function Tags to Filter"
    FUNCTION_TAG_EXCLUDE: typing.Final = "Function Tags Excluded"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, options: ghidra.app.decompiler.DecompileOptions, createHeader: typing.Union[jpype.JBoolean, bool], createFile: typing.Union[jpype.JBoolean, bool], emitTypes: typing.Union[jpype.JBoolean, bool], emitGlobals: typing.Union[jpype.JBoolean, bool], excludeTags: typing.Union[jpype.JBoolean, bool], tags: typing.Union[java.lang.String, str]):
        ...



__all__ = ["XmlExporter", "OriginalFileExporter", "AbstractLineDispenser", "ProgramTextWriter", "AsciiExporter", "GzfExporter", "ExporterException", "ProgramTextOptions", "IntelHexExporter", "CommentLineDispenser", "StringComparer", "GdtExporter", "HtmlExporter", "Exporter", "ReferenceLineDispenser", "BinaryExporter", "CppExporter"]
