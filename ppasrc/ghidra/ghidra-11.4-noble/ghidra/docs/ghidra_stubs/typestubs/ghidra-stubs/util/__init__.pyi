from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.database.sourcemap
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.exception
import ghidra.util.task
import java.awt # type: ignore
import java.awt.dnd # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.net # type: ignore
import java.time # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.concurrent.atomic # type: ignore
import java.util.concurrent.locks # type: ignore
import java.util.function # type: ignore
import java.util.jar # type: ignore
import java.util.regex # type: ignore
import java.util.stream # type: ignore
import java.util.zip # type: ignore
import javax.swing # type: ignore
import javax.swing.text # type: ignore
import junit.framework # type: ignore
import utility.application


C = typing.TypeVar("C")
E = typing.TypeVar("E")
T = typing.TypeVar("T")
U = typing.TypeVar("U")
V = typing.TypeVar("V")


class BrowserLoader(java.lang.Object):
    """
    BrowserLoader opens a web browser and displays the given url.
    
    
    .. seealso::
    
        | :obj:`ManualViewerCommandWrappedOption`
    """

    @typing.type_check_only
    class ImmediateOptionsChangeListener(ghidra.framework.options.OptionsChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BrowserRunner(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def display(url: java.net.URL):
        """
        Display the content specified by url in a web browser window.  This call will launch 
        a new thread and then immediately return.
        
        :param java.net.URL url: The URL to show.
        """

    @staticmethod
    @typing.overload
    def display(url: java.net.URL, fileURL: java.net.URL, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        """
        Display the content specified by url in a web browser window.  This call will launch 
        a new thread and then immediately return.
        
        :param java.net.URL url: The web URL to show (e.g., http://localhost...).
        :param java.net.URL fileURL: The file URL to show (e.g., file:///path/to/file).
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: A service provider from which to get system resources.
        """


class ManualViewerCommandWrappedOption(ghidra.framework.options.CustomOption):

    class_: typing.ClassVar[java.lang.Class]
    OPTIONS_CATEGORY_NAME: typing.Final = "Processor Manuals"
    MANUAL_VIEWER_OPTIONS: typing.Final = "Manual Viewer Options"

    def __init__(self):
        ...

    def getCommandArguments(self) -> jpype.JArray[java.lang.String]:
        ...

    def getCommandString(self) -> str:
        ...

    @staticmethod
    def getDefaultBrowserLoaderOptions() -> ManualViewerCommandWrappedOption:
        ...

    def getUrlReplacementString(self) -> str:
        ...

    def setCommandArguments(self, commandArguments: jpype.JArray[java.lang.String]):
        ...

    def setCommandString(self, commandString: typing.Union[java.lang.String, str]):
        ...

    def setUrlReplacementString(self, urlReplacementString: typing.Union[java.lang.String, str]):
        ...

    @property
    def urlReplacementString(self) -> java.lang.String:
        ...

    @urlReplacementString.setter
    def urlReplacementString(self, value: java.lang.String):
        ...

    @property
    def commandString(self) -> java.lang.String:
        ...

    @commandString.setter
    def commandString(self, value: java.lang.String):
        ...

    @property
    def commandArguments(self) -> jpype.JArray[java.lang.String]:
        ...

    @commandArguments.setter
    def commandArguments(self, value: jpype.JArray[java.lang.String]):
        ...


@typing.type_check_only
class StackFrameImpl(ghidra.program.model.listing.StackFrame):
    """
    
    Implements a simple stack frame for a function.  Each frame consists of a
    local sections, parameter section, and save information (return address,
    saved registers).
    
    
     
    When a frame is created, the parameter stack start offset must be set up.
    If the parameter start is >= 0, then the stack grows in the negative
    direction. If the parameter start < 0, then the stack grows in the positive
    direction. When a frame is created the parameter start offset must be
    specified. Later the parameter start offset can be changed, but it must
    remain positive/negative if the frame was created with a positive/negative
    value.
     
    
     
    WARNING! This implementation is deficient and is only used by the UndefinedFunction
    implementation
    """

    class_: typing.ClassVar[java.lang.Class]

    def createVariable(self, name: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Variable:
        """
        Create a new stack variable.  
         
        Specified source is always ignored
        and the variable instance returned will never be a parameter.
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.StackFrame.createVariable(String, int, DataType, SourceType)`
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Returns whether some other stack frame is "equivalent to" this one.
        The stack frame is considered equal to another even if they are each
        part of a different function.
        
        :param java.lang.Object obj: the object to compare for equality.
        """

    def getParameterCount(self) -> int:
        """
        Gets the number of parameters in the stack frame regardless
        of the direction the stack grows in.
        
        :return: the number of parameters in the stack frame.
        :rtype: int
        """

    @property
    def parameterCount(self) -> jpype.JInt:
        ...


class GhidraJarBuilder(ghidra.GhidraLaunchable):

    @typing.type_check_only
    class Jar(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def addFile(self, jarPath: typing.Union[java.lang.String, str], file: jpype.protocol.SupportsPath, module: generic.jar.ApplicationModule):
            ...

        def addJarEntry(self, jarFile: java.util.jar.JarFile, jarEntry: java.util.jar.JarEntry, module: generic.jar.ApplicationModule):
            ...

        def close(self):
            ...

        def setPathPrefix(self, string: typing.Union[java.lang.String, str]):
            ...

        def writeExtensionPointClassFile(self):
            ...

        def writeGhidraExtensionsDir(self):
            """
            Puts a directory in the jar for Ghidra Extensions. This may be empty (if
            no extensions are installed) but should exist nonetheless.
            
            :raises IOException: if there's an error writing to the jar
            """

        def writeModuleListFile(self, moduleList: java.util.List[generic.jar.ApplicationModule]):
            ...


    @typing.type_check_only
    class Zip(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def addFile(self, zipPath: typing.Union[java.lang.String, str], file: jpype.protocol.SupportsPath):
            ...

        def addZipEntry(self, zipFile: java.util.zip.ZipFile, zipEntry: java.util.zip.ZipEntry):
            ...

        def close(self):
            ...


    @typing.type_check_only
    class FileExtensionFilter(java.io.FileFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, layout: utility.application.ApplicationLayout):
        ...

    def addAllModules(self):
        ...

    def addExcludedFileExtension(self, excludedExtension: typing.Union[java.lang.String, str]):
        ...

    def addFileFilter(self, filter: java.io.FileFilter):
        ...

    def addModule(self, name: typing.Union[java.lang.String, str]) -> bool:
        ...

    def addModuleToJar(self, module: generic.jar.ApplicationModule):
        ...

    def buildJar(self, outputFile: jpype.protocol.SupportsPath, extraBinDir: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        ...

    def buildSrcZip(self, outputFile: jpype.protocol.SupportsPath, monitor: ghidra.util.task.TaskMonitor):
        ...

    def getAllModules(self) -> java.util.List[generic.jar.ApplicationModule]:
        ...

    def getExcludedModules(self) -> java.util.List[generic.jar.ApplicationModule]:
        ...

    def getIncludedModules(self) -> java.util.List[generic.jar.ApplicationModule]:
        ...

    def getModule(self, name: typing.Union[java.lang.String, str]) -> generic.jar.ApplicationModule:
        ...

    def isModuleIncluded(self, moduleName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def launch(self, layout: ghidra.GhidraApplicationLayout, args: jpype.JArray[java.lang.String]):
        """
        Entry point for buildGhidraJar.bat.
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def removeAllProcessorModules(self):
        ...

    def removeModule(self, name: typing.Union[java.lang.String, str]) -> bool:
        ...

    def setExcludeHelp(self, excludeHelp: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMainClass(self, mainClass: typing.Union[java.lang.String, str]):
        ...

    @property
    def allModules(self) -> java.util.List[generic.jar.ApplicationModule]:
        ...

    @property
    def module(self) -> generic.jar.ApplicationModule:
        ...

    @property
    def moduleIncluded(self) -> jpype.JBoolean:
        ...

    @property
    def excludedModules(self) -> java.util.List[generic.jar.ApplicationModule]:
        ...

    @property
    def includedModules(self) -> java.util.List[generic.jar.ApplicationModule]:
        ...


class MultiComparableArrayIterator(java.lang.Object, typing.Generic[T]):
    """
    ``MultiComparableArrayIterator`` takes multiple arrays of comparable
    objects and iterates through them simultaneously. The arrays must contain objects
    that are comparable within each array and between the multiple arrays.
    All arrays must be sorted in ascending order when handed to this class. 
    Iterating returns the next object(s) from one or more of the arrays based on
    the compareTo() of the next objects in each of the arrays. If a particular
    array doesn't contain the next object, based on all arrays, then a null is 
    returned as the next object for that array.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, arrays: jpype.JArray[jpype.JArray[T]]):
        """
        Constructor of a multi-comparable object array iterator for traversing 
        multiple comparable object arrays simultaneously.
         
        Important: The items in each array must be in ascending order.
        
        :param jpype.JArray[jpype.JArray[T]] arrays: the array of Comparable object arrays. 
        Each array needs to be in ascending order.
        """

    @typing.overload
    def __init__(self, arrays: jpype.JArray[jpype.JArray[T]], forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor of a multi comparable object array iterator for traversing 
        multiple comparable object arrays simultaneously.
        
        :param jpype.JArray[jpype.JArray[T]] arrays: the array of Comparable object arrays.
        Each array needs to be in ascending order.
        :param jpype.JBoolean or bool forward: true indicates that the iterator return comparable objects from min to max.
        false indicates to iterate backwards (from max to min).
        """

    def hasNext(self) -> bool:
        """
        Determines whether or not any of the original arrays has a
        next object.
        
        :return: true if a next object can be obtained from any of
        the comparable object arrays.
        :rtype: bool
        """

    def next(self) -> jpype.JArray[T]:
        """
        Returns the next comparable object(s). The next object could be from any 
        one or more of the arrays. The object array returned corresponds to the 
        comparable arrays originally passed to the constructor. All objects 
        returned are effectively the same as determined by the compareTo() method. 
        If the next object for one of the original comparable arrays is not the 
        same as the next overall object, then a null is returned in its place.
        
        :return: an array with the next object found for each of the original arrays.
        Some of these may be null, indicating the corresponding comparable array 
        didn't possess the next object. However, that comparable array may still 
        have objects on subsequent calls.
        There will be as many elements in this array as the number of comparable 
        arrays passed to the constructor.
        :rtype: jpype.JArray[T]
        """


class UndefinedFunction(ghidra.program.model.listing.Function):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, p: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address):
        """
        Undefined Function constructor.
        Function will adopt the default calling convention prototype
        defined by the program's compiler specification.  The
        associated stack frame will also follow this default
        convention.
        
        :param ghidra.program.model.listing.Program p: program containing the function
        :param ghidra.program.model.address.Address entry: function entry point
        """

    @staticmethod
    def findFunction(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> UndefinedFunction:
        """
        Identifies a ``UndefinedFunction`` based on the location given based upon the current
        listing disassembly at time of construction using a block model.
        
        :param ghidra.program.model.listing.Program program: program to be searched
        :param ghidra.program.model.address.Address address: address within body of function
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: function or null if invalid parameters, not found, or cancelled
        :rtype: UndefinedFunction
        """

    @staticmethod
    def findFunctionUsingIsolatedBlockModel(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> UndefinedFunction:
        ...

    @staticmethod
    def findFunctionUsingSimpleBlockModel(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> UndefinedFunction:
        ...


class ManualViewerCommandEditor(java.beans.PropertyEditorSupport, ghidra.framework.options.CustomOptionsEditor):

    @typing.type_check_only
    class LaunchDataInputPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LaunchErrorDialog(javax.swing.JDialog):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, url: java.net.URL, fileURL: java.net.URL):
        ...


class SourceFileUtils(java.lang.Object):
    """
    A utility class for creating :obj:`SourceFile`s from native paths, e.g., windows paths.
    """

    class SourceLineBounds(java.lang.Record):
        """
        A record containing the minimum and maximum mapped line numbers
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def max(self) -> int:
            ...

        def min(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def byteArrayToHexString(bytes: jpype.JArray[jpype.JByte]) -> str:
        """
        Converts a byte array to a ``String`` of hexadecimal digits.
        
        :param jpype.JArray[jpype.JByte] bytes: array to convert
        :return: string
        :rtype: str
        """

    @staticmethod
    def byteArrayToLong(bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Converts a byte array of length 8 to a ``long`` value.  The byte at position 0 
        of the array will be the most significant byte of the resulting long.
        
        :param jpype.JArray[jpype.JByte] bytes: array to convert
        :return: long
        :rtype: int
        :raises IllegalArgumentException: if bytes.length != 8
        """

    @staticmethod
    @typing.overload
    def getSourceFileFromPathString(path: typing.Union[java.lang.String, str]) -> ghidra.program.database.sourcemap.SourceFile:
        """
        Creates a :obj:`SourceFile` from ``path`` with id type :obj:`SourceFileIdType.NONE`
        and empty identifier.  The path will be transformed using 
        :meth:`FSUtilities.normalizeNativePath(String) <FSUtilities.normalizeNativePath>` and then :obj:`URI.normalize`.
        
        :param java.lang.String or str path: path
        :return: source file
        :rtype: ghidra.program.database.sourcemap.SourceFile
        """

    @staticmethod
    @typing.overload
    def getSourceFileFromPathString(path: typing.Union[java.lang.String, str], idType: ghidra.program.database.sourcemap.SourceFileIdType, identifier: jpype.JArray[jpype.JByte]) -> ghidra.program.database.sourcemap.SourceFile:
        """
        Creates a :obj:`SourceFile` from ``path`` with the provided id type and identifier.
        The path will be transformed using:meth:`FSUtilities.normalizeNativePath(String) <FSUtilities.normalizeNativePath>` and 
        then :obj:`URI.normalize`.
        
        :param java.lang.String or str path: path
        :param ghidra.program.database.sourcemap.SourceFileIdType idType: id type
        :param jpype.JArray[jpype.JByte] identifier: identifier
        :return: source file
        :rtype: ghidra.program.database.sourcemap.SourceFile
        """

    @staticmethod
    def getSourceLineBounds(program: ghidra.program.model.listing.Program, sourceFile: ghidra.program.database.sourcemap.SourceFile) -> SourceFileUtils.SourceLineBounds:
        """
        Returns a :obj:`SourceLineBounds` record containing the minimum and maximum mapped line
        for ``sourceFile`` in ``program``.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :return: source line bounds or null
        :rtype: SourceFileUtils.SourceLineBounds
        """

    @staticmethod
    def hexStringToByteArray(hexString: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Converts a ``String`` of hexadecimal character to an array of bytes. An initial "0x"
        or "0X" is ignored, as is the case of the digits a-f.
        
        :param java.lang.String or str hexString: String to convert
        :return: byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def longToByteArray(l: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        """
        Converts a ``long`` value to an byte array of length 8.  The most significant byte
        of the long will be at position 0 of the resulting array.
        
        :param jpype.JLong or int l: long
        :return: byte array
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def normalizeDwarfPath(path: typing.Union[java.lang.String, str], baseDir: typing.Union[java.lang.String, str]) -> str:
        """
        Normalizes paths encountered in DWARF debug info.
        Relative paths are made absolute with base /``baseDir``/.  If normalization of "/../" 
        subpaths results in a path "above" /``baseDir``/, the returned path will be based at 
        "baseDir_i" where i is the count of initial "/../" in the normalized path.
        Additionally, any backslashes are converted to forward slashes (backslashes can occur in
        files produced by MinGW).
        
        :param java.lang.String or str path: path to normalize
        :param java.lang.String or str baseDir: name of artificial root directory
        :return: normalized path
        :rtype: str
        :raises IllegalArgumentException: if the path is not valid or if baseDir contains a
        non-alphanumeric, non-underscore character
        """


class GhidraBigEndianDataConverter(BigEndianDataConverter, GhidraDataConverter):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[GhidraBigEndianDataConverter]

    def __init__(self):
        ...


class GhidraLittleEndianDataConverter(LittleEndianDataConverter, GhidraDataConverter):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[GhidraLittleEndianDataConverter]

    def __init__(self):
        ...


class ManualEntry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mnemonic: typing.Union[java.lang.String, str], manualPath: typing.Union[java.lang.String, str], missingManualDescription: typing.Union[java.lang.String, str], pageNumber: typing.Union[java.lang.String, str]):
        ...

    def getManualPath(self) -> str:
        ...

    def getMissingManualDescription(self) -> str:
        ...

    def getMnemonic(self) -> str:
        ...

    def getPageNumber(self) -> str:
        ...

    @property
    def manualPath(self) -> java.lang.String:
        ...

    @property
    def pageNumber(self) -> java.lang.String:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def missingManualDescription(self) -> java.lang.String:
        ...


class GhidraDataConverter(DataConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getBigInteger(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Generate a BigInteger value by invoking buf.getBytes at the specified offset.
        
        :param ghidra.program.model.mem.MemBuffer buf: MemBuffer source of bytes
        :param jpype.JInt or int offset: offset in mem buffer to read
        :param jpype.JInt or int size: number of bytes
        :param jpype.JBoolean or bool signed: boolean flag
        :return: BigInteger value
        :rtype: java.math.BigInteger
        :raises MemoryAccessException: if failed to read specified number of bytes
        at the specified offset
        """

    @staticmethod
    def getInstance(isBigEndian: typing.Union[jpype.JBoolean, bool]) -> GhidraDataConverter:
        """
        Returns the correct GhidraDataConverter static instance for the requested endian-ness.
        
        :param jpype.JBoolean or bool isBigEndian: boolean flag, true means big endian
        :return: static GhidraDataConverter instance
        :rtype: GhidraDataConverter
        """

    def getInt(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Generate a int value by invoking buf.getBytes at the specified offset.
        
        :param ghidra.program.model.mem.MemBuffer buf: MemBuffer source of bytes
        :param jpype.JInt or int offset: offset in mem buffer to read
        :return: int value
        :rtype: int
        :raises MemoryAccessException: if failed to read 4-bytes at the specified offset
        """

    def getLong(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Generate a long value by invoking buf.getBytes at the specified offset.
        
        :param ghidra.program.model.mem.MemBuffer buf: MemBuffer source of bytes
        :param jpype.JInt or int offset: offset in mem buffer to read
        :return: long value
        :rtype: int
        :raises MemoryAccessException: if failed to read 8-bytes at the specified offset
        """

    def getShort(self, buf: ghidra.program.model.mem.MemBuffer, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Generate a short value by invoking buf.getBytes at the specified offset.
        
        :param ghidra.program.model.mem.MemBuffer buf: MemBuffer source of bytes
        :param jpype.JInt or int offset: offset in mem buffer to read
        :return: short value
        :rtype: int
        :raises MemoryAccessException: if failed to read 2-bytes at the specified offset
        """


class XmlProgramUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def parseAddress(factory: ghidra.program.model.address.AddressFactory, addrString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Parses the address string.
        
        :param ghidra.program.model.address.AddressFactory factory: the address factory
        :param java.lang.String or str addrString: the address string to parse
        :return: the parsed address, or null
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def toString(addr: ghidra.program.model.address.Address) -> str:
        """
        Creates a string representation of the specifed address.
        
        :param ghidra.program.model.address.Address addr: the address to convert to a string
        :return: the string representation of the address
        :rtype: str
        """


class Lock(java.lang.Object):
    """
    Ghidra synchronization lock. This class allows creation of named locks for
    synchronizing modification of multiple tables in the Ghidra database.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates an instance of a lock for synchronization within Ghidra.
        
        :param java.lang.String or str name: the name of this lock
        """

    def acquire(self):
        """
        Acquire this synchronization lock. (i.e. begin synchronizing on this named
        lock.)
        """

    def getOwner(self) -> java.lang.Thread:
        """
        Gets the thread that currently owns the lock.
        
        :return: the thread that owns the lock or null.
        :rtype: java.lang.Thread
        """

    def release(self):
        """
        Releases this lock, since you are through with the code that needed
        synchronization.
        """

    @property
    def owner(self) -> java.lang.Thread:
        ...


class VersionExceptionHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def isUpgradeOK(parent: java.awt.Component, domainFile: ghidra.framework.model.DomainFile, actionName: typing.Union[java.lang.String, str], ve: ghidra.util.exception.VersionException) -> bool:
        ...

    @staticmethod
    def showVersionError(parent: java.awt.Component, filename: typing.Union[java.lang.String, str], contentType: typing.Union[java.lang.String, str], actionName: typing.Union[java.lang.String, str], ve: ghidra.util.exception.VersionException):
        ...


class NotOwnerException(ghidra.util.exception.UsrException):
    """
    Exception thrown if user is not the owner of a file or
    data object being accessed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message explaining exception.
        """


class PropertyFile(java.lang.Object):
    """
    Class that represents a file of property names and values. The file
    extension used is PROPERTY_EXT.
    """

    @typing.type_check_only
    class PropertyEntryType(java.lang.Enum[PropertyFile.PropertyEntryType]):

        class_: typing.ClassVar[java.lang.Class]
        INT_TYPE: typing.Final[PropertyFile.PropertyEntryType]
        LONG_TYPE: typing.Final[PropertyFile.PropertyEntryType]
        BOOLEAN_TYPE: typing.Final[PropertyFile.PropertyEntryType]
        STRING_TYPE: typing.Final[PropertyFile.PropertyEntryType]

        @staticmethod
        def lookup(rep: typing.Union[java.lang.String, str]) -> PropertyFile.PropertyEntryType:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PropertyFile.PropertyEntryType:
            ...

        @staticmethod
        def values() -> jpype.JArray[PropertyFile.PropertyEntryType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    PROPERTY_EXT: typing.Final = ".prp"
    """
    File extension indicating the file is a property file.
    """


    def __init__(self, dir: jpype.protocol.SupportsPath, storageName: typing.Union[java.lang.String, str], parentPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Construct a new or existing PropertyFile.
        This form ignores retained property values for NAME and PARENT path.
        
        :param jpype.protocol.SupportsPath dir: parent directory
        :param java.lang.String or str storageName: stored property file name (without extension)
        :param java.lang.String or str parentPath: path to parent
        :param java.lang.String or str name: name of the property file
        :raises IOException:
        """

    def delete(self):
        """
        Delete the file for this PropertyFile.
        """

    def exists(self) -> bool:
        """
        Return whether the file for this PropertyFile exists.
        """

    def getBoolean(self, propertyName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Return the boolean value with the given propertyName.
        
        :param java.lang.String or str propertyName: name of property that is a boolean
        :param jpype.JBoolean or bool defaultValue: value to use if the property does not exist
        :return: boolean value
        :rtype: bool
        """

    def getFileID(self) -> str:
        """
        Returns the FileID associated with this file.
        
        :return: FileID associated with this file
        :rtype: str
        """

    def getFolder(self) -> java.io.File:
        """
        Return the parent file to this PropertyFile.
        """

    def getInt(self, propertyName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Return the int value with the given propertyName.
        
        :param java.lang.String or str propertyName: name of property that is an int
        :param jpype.JInt or int defaultValue: value to use if the property does not exist
        :return: int value
        :rtype: int
        """

    def getLong(self, propertyName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Return the long value with the given propertyName.
        
        :param java.lang.String or str propertyName: name of property that is a long
        :param jpype.JLong or int defaultValue: value to use if the property does not exist
        :return: long value
        :rtype: int
        """

    def getName(self) -> str:
        """
        Return the name of this PropertyFile.  A null value may be returned
        if this is an older property file and the name was not specified at
        time of construction.
        """

    def getParentPath(self) -> str:
        """
        Return the path to the parent of this PropertyFile.
        """

    def getPath(self) -> str:
        """
        Return the path to this PropertyFile.  A null value may be returned
        if this is an older property file and the name and parentPath was not specified at
        time of construction.
        """

    def getStorageName(self) -> str:
        """
        Return the storage name of this PropertyFile.  This name does not include the property
        file extension (.prp)
        """

    def getString(self, propertyName: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Return the string value with the given propertyName.
        
        :param java.lang.String or str propertyName: name of property that is a string
        :param java.lang.String or str defaultValue: value to use if the property does not exist
        :return: string value
        :rtype: str
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if file is writable
        """

    def lastModified(self) -> int:
        """
        Return the time of last modification in number of milliseconds.
        """

    def moveTo(self, newParent: jpype.protocol.SupportsPath, newStorageName: typing.Union[java.lang.String, str], newParentPath: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Move this PropertyFile to the newParent file.
        
        :param jpype.protocol.SupportsPath newParent: new parent of the file
        :param java.lang.String or str newStorageName: new storage name
        :param java.lang.String or str newParentPath: parent path of the new parent
        :param java.lang.String or str newName: new name for this PropertyFile
        :raises IOException: thrown if there was a problem accessing the
        :raises DuplicateFileException: thrown if a file with the newName
        already exists
        """

    def putBoolean(self, propertyName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        """
        Assign the boolean value to the given propertyName.
        
        :param java.lang.String or str propertyName: name of property to set
        :param jpype.JBoolean or bool value: value to set
        """

    def putInt(self, propertyName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Assign the int value to the given propertyName.
        
        :param java.lang.String or str propertyName: name of property to set
        :param jpype.JInt or int value: value to set
        """

    def putLong(self, propertyName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Assign the long value to the given propertyName.
        
        :param java.lang.String or str propertyName: name of property to set
        :param jpype.JLong or int value: value to set
        """

    def putString(self, propertyName: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Assign the string value to the given propertyName.
        
        :param java.lang.String or str propertyName: name of property to set
        :param java.lang.String or str value: value to set
        """

    def readState(self):
        """
        Read in this PropertyFile into a SaveState object.
        
        :raises IOException: thrown if there was a problem reading the file
        """

    def remove(self, propertyName: typing.Union[java.lang.String, str]):
        """
        Remove the specified property
        
        :param java.lang.String or str propertyName:
        """

    def setFileID(self, fileId: typing.Union[java.lang.String, str]):
        """
        Set the FileID associated with this file.
        
        :param java.lang.String or str fileId:
        """

    def writeState(self):
        """
        Write the contents of this PropertyFile.
        
        :raises IOException: thrown if there was a problem writing the file
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def folder(self) -> java.io.File:
        ...

    @property
    def parentPath(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def storageName(self) -> java.lang.String:
        ...

    @property
    def fileID(self) -> java.lang.String:
        ...

    @fileID.setter
    def fileID(self, value: java.lang.String):
        ...


class MD5Utilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SALT_LENGTH: typing.Final = 4
    UNSALTED_HASH_LENGTH: typing.Final = 32
    SALTED_HASH_LENGTH: typing.Final = 36

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def getMD5Hash(msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate MD5 hash in a hex character representation
        
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: hex hash value in text format
        :rtype: jpype.JArray[jpype.JChar]
        """

    @staticmethod
    @typing.overload
    def getMD5Hash(in_: java.io.InputStream) -> str:
        """
        Generate MD5 message digest hash for specified input stream.  
        Stream will be read until EOF is reached.
        
        :param java.io.InputStream in: input stream
        :return: message digest hash
        :rtype: str
        :raises IOException: if reading input stream produces an error
        """

    @staticmethod
    @typing.overload
    def getMD5Hash(file: jpype.protocol.SupportsPath) -> str:
        """
        Generate MD5 message digest hash for specified file contents.
        
        :param jpype.protocol.SupportsPath file: file to be read
        :return: message digest hash
        :rtype: str
        :raises IOException: if opening or reading file produces an error
        """

    @staticmethod
    @typing.overload
    def getMD5Hash(values: java.util.List[java.lang.String]) -> str:
        """
        Generate combined MD5 message digest hash for all values in the 
        specified values list.
        
        :param java.util.List[java.lang.String] values: list of text strings
        :return: MD5 message digest hash
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getSaltedMD5Hash(salt: jpype.JArray[jpype.JChar], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate salted MD5 hash for specified message.  Supplied salt is 
        returned as prefix to returned hash.
        
        :param jpype.JArray[jpype.JChar] salt: digest salt (use empty string for no salt)
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: salted hash using specified salt which is
        returned as a prefix to the hash
        :rtype: jpype.JArray[jpype.JChar]
        """

    @staticmethod
    @typing.overload
    def getSaltedMD5Hash(msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate salted MD5 hash for specified message using random salt.  
        First 4-characters of returned hash correspond to the salt data.
        
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: salted hash using randomly generated salt which is
        returned as a prefix to the hash
        :rtype: jpype.JArray[jpype.JChar]
        """

    @staticmethod
    def hexDump(data: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JChar]:
        """
        Convert binary data to a sequence of hex characters.
        
        :param jpype.JArray[jpype.JByte] data: binary data
        :return: hex character representation of data
        :rtype: jpype.JArray[jpype.JChar]
        """


class NamingUtilities(java.lang.Object):
    """
    Utility class with static methods for validating project file names.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_NAME_LENGTH: typing.Final = 60
    """
    Max length for a name.
    """


    @staticmethod
    def demangle(mangledName: typing.Union[java.lang.String, str]) -> str:
        """
        Performs the inverse of the mangle method.  A string is returned such that
        all characters following a MANGLE_CHAR are converted to uppercase.  Two MANGLE
        chars in a row are replace by a single MANGLE_CHAR.
        
        :param java.lang.String or str mangledName: mangled name string
        :return: demangle name
        :rtype: str
        """

    @staticmethod
    @deprecated("this method may be removed in a subsequent release due to \n limited use and applicability (project names and project file names have\n different naming restrictions).")
    def findInvalidChar(name: typing.Union[java.lang.String, str]) -> str:
        """
        Find the invalid character in the given name.
         
        
        This method should only be used with :meth:`isValidName(String) <.isValidName>`} and **not**
        :meth:`isValidProjectName(String) <.isValidProjectName>`
        
        :param java.lang.String or str name: the name with an invalid character
        :return: the invalid character or 0 if no invalid character can be found
        :rtype: str
        
        .. deprecated::
        
        this method may be removed in a subsequent release due to 
        limited use and applicability (project names and project file names have
        different naming restrictions).
        
        .. seealso::
        
            | :obj:`.isValidName(String)`
        """

    @staticmethod
    def isValidMangledName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Performs a validity check on a mangled name
        
        :param java.lang.String or str name: mangled name
        :return: true if name can be demangled else false
        :rtype: bool
        """

    @staticmethod
    @deprecated("method has been deprecated due to improper and widespread use.  \n New methods include NamingUtilities.isValidProjectName(String) and \n LocalFileSystem.testValidName(String,boolean).")
    def isValidName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests whether the given string is a valid.
        Rules:
         
        * All characters must be a letter, digit (0..9), period, hyphen, underscore or space
        * May not exceed a length of 60 characters
        
        
        :param java.lang.String or str name: name to validate
        :return: true if specified name is valid, else false
        :rtype: bool
        
        .. deprecated::
        
        method has been deprecated due to improper and widespread use.  
        New methods include :meth:`NamingUtilities.isValidProjectName(String) <NamingUtilities.isValidProjectName>` and 
        :meth:`LocalFileSystem.testValidName(String,boolean) <LocalFileSystem.testValidName>`.
        """

    @staticmethod
    def isValidProjectName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests whether the given string is a valid project name.
        Rules:
         
        * Name may not start with period
        * All characters must be a letter, digit (0..9), period, hyphen, underscore or space
        * May not exceed a length of 60 characters
        
        
        :param java.lang.String or str name: name to validate
        :return: true if specified name is valid, else false
        :rtype: bool
        """

    @staticmethod
    def mangle(name: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a string such that all uppercase characters in the given string are
        replaced by the MANGLE_CHAR followed by the lowercase version of the character.
        MANGLE_CHARs are replaced by 2 MANGLE_CHARs.
        
        This method is to get around the STUPID windows problem where filenames are
        not case sensitive.  Under Windows, Foo.exe and foo.exe represent
        the same filename.  To fix this we mangle names first such that Foo.exe becomes
        _foo.exe.
        
        :param java.lang.String or str name: name string to be mangled
        :return: mangled name
        :rtype: str
        """


class HashUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MD5_ALGORITHM: typing.ClassVar[java.lang.String]
    SHA256_ALGORITHM: typing.ClassVar[java.lang.String]
    SALT_LENGTH: typing.Final = 4
    MD5_UNSALTED_HASH_LENGTH: typing.Final = 32
    MD5_SALTED_HASH_LENGTH: typing.Final = 36
    SHA256_UNSALTED_HASH_LENGTH: typing.Final = 64
    SHA256_SALTED_HASH_LENGTH: typing.Final = 68

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate hash in a hex character representation
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: hex hash value in text format
        :rtype: jpype.JArray[jpype.JChar]
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], in_: java.io.InputStream) -> str:
        """
        Generate message digest hash for specified input stream.  Stream will be read
        until EOF is reached.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param java.io.InputStream in: input stream
        :return: message digest hash
        :rtype: str
        :raises IOException: if reading input stream produces an error
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], file: jpype.protocol.SupportsPath) -> str:
        """
        Generate message digest hash for specified file contents.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.protocol.SupportsPath file: file to be read
        :return: message digest hash
        :rtype: str
        :raises IOException: if opening or reading file produces an error
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], values: java.util.List[java.lang.String]) -> str:
        """
        Generate combined message digest hash for all values in the 
        specified values list.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param java.util.List[java.lang.String] values: list of text strings
        :return: message digest hash
        :rtype: str
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getHash(algorithm: typing.Union[java.lang.String, str], values: jpype.JArray[jpype.JByte]) -> str:
        """
        Generate combined message digest hash for the bytes in the specified array.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JByte] values: array of bytes to hash
        :return: message digest hash
        :rtype: str
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getSaltedHash(algorithm: typing.Union[java.lang.String, str], salt: jpype.JArray[jpype.JChar], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate salted hash for specified message.  Supplied salt is 
        returned as prefix to returned hash.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JChar] salt: digest salt (use empty string for no salt)
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: salted hash using specified salt which is
        returned as a prefix to the hash
        :rtype: jpype.JArray[jpype.JChar]
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    @typing.overload
    def getSaltedHash(algorithm: typing.Union[java.lang.String, str], msg: jpype.JArray[jpype.JChar]) -> jpype.JArray[jpype.JChar]:
        """
        Generate salted hash for specified message using random salt.  
        First 4-characters of returned hash correspond to the salt data.
        
        :param java.lang.String or str algorithm: message digest algorithm
        :param jpype.JArray[jpype.JChar] msg: message text
        :return: salted hash using randomly generated salt which is
        returned as a prefix to the hash
        :rtype: jpype.JArray[jpype.JChar]
        :raises IllegalArgumentException: if specified algorithm is not supported
        
        .. seealso::
        
            | :obj:`MessageDigest`for supported hash algorithms
        """

    @staticmethod
    def hexDump(data: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JChar]:
        """
        Convert binary data to a sequence of hex characters.
        
        :param jpype.JArray[jpype.JByte] data: binary data
        :return: hex character representation of data
        :rtype: jpype.JArray[jpype.JChar]
        """


class HTMLUtilities(java.lang.Object):
    """
    A helper class providing static methods for formatting text with common HTML tags.
    
     
    Many clients use this class to render content as HTML.  Below are a few use cases along
    with the method that should be used for each.
     
    +-----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |                                     Use Case                                      |                                               Function                                                |                                           Description                                           |
    +===================================================================================+=======================================================================================================+=================================================================================================+
    |                                                                                   |:meth:`toHTML(String) <.toHTML>`                                                                       |                                                                                                 |
    |A client wishes to display a simple text message (that itself contains no HTML     |                                                                                                       |The given text has all newline characters (\n) replaced with <BR> tags so                        |
    |markup) as HTML.  The message may contain newline characters.                      |                                                                                                       |that the HTML display of the text will visually display multiple lines.  Also,                   |
    |                                                                                   |                                                                                                       |the final text is prepended with <HTML> so that the Java HTML rendering                          |
    |                                                                                   |                                                                                                       |engine will render the result as HTML.                                                           |
    |                                                                                   |                                                                                                       |                                                                                                 |
    +-----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |                                                                                   |:meth:`toWrappedHTML(String) <.toWrappedHTML>` or :meth:`toWrappedHTML(String, int) <.toWrappedHTML>`  |                                                                                                 |
    |A client wishes to display a simple text message (that itself may or may not       |                                                                                                       |This text works the same as :meth:`toHTML(String) <.toHTML>` with the addition of                |
    |contain HTML markup) as HTML.  Further, the client wishes to not only split        |                                                                                                       |line-wrapping text that passes the given cutoff.                                                 |
    |lines at newline characters, but also wishes to ensure that no line is longer      |                                                                                                       |                                                                                                 |
    |than a specified limit.                                                            |                                                                                                       |                                                                                                 |
    |                                                                                   |                                                                                                       |                                                                                                 |
    +-----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |                                                                                   |:meth:`toLiteralHTML(String, int) <.toLiteralHTML>`                                                    |                                                                                                 |
    |A client wishes to display a text message with dynamic content, unknown at the     |                                                                                                       |This method works the same as :meth:`toWrappedHTML(String) <.toWrappedHTML>`, with the addition  |
    |time of programming.                                                               |                                                                                                       |of 'friendly encoding', or escaping, any embedded HTML content.  The effect of                   |
    |                                                                                   |                                                                                                       |this is that any existing HTML markup is not rendered as HTML, but is displayed                  |
    |                                                                                   |                                                                                                       |as plain text.                                                                                   |
    |                                                                                   |                                                                                                       |                                                                                                 |
    +-----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |                                                                                   |:meth:`toLiteralHTMLForTooltip(String) <.toLiteralHTMLForTooltip>`                                     |                                                                                                 |
    |A client wishes to display, as a tooltip, a text message with                      |                                                                                                       |This method works the same as :meth:`toLiteralHTML(String, int) <.toLiteralHTML>`, with the      |
    |dynamic content, unknown at the time of programming.  Tooltips are unique from     |                                                                                                       |addition of capping the max text length, as well as setting the line-wrap length                 |
    |general HTML in that we want them to share a common line wrapping length.          |                                                                                                       |to :obj:`.DEFAULT_MAX_LINE_LENGTH`.                                                              |
    |                                                                                   |                                                                                                       |                                                                                                 |
    +-----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    |                                                                                   |:meth:`lineWrapWithHTMLLineBreaks(String) <.lineWrapWithHTMLLineBreaks>` or                            |                                                                                                 |
    |A client wishes to convert newlines in text into HTML line breaks, without adding  |:meth:`lineWrapWithHTMLLineBreaks(String, int) <.lineWrapWithHTMLLineBreaks>`                          |This first method will simply convert all newline characters to                                  |
    |HTML tags around the text, which allows them to embed this text into a             |                                                                                                       |<BR> tags.  The second method adds the ability to trigger line-wrapping                          |
    |larger HTML document.                                                              |                                                                                                       |at the given length as well.                                                                     |
    |                                                                                   |                                                                                                       |                                                                                                 |
    +-----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]
    HTML: typing.Final = "<html>"
    HTML_CLOSE: typing.Final = "</html>"
    BR: typing.Final = "<br>"
    PRE: typing.Final = "<pre>"
    PRE_CLOSE: typing.Final = "</pre>"
    LINK_PLACEHOLDER_OPEN: typing.Final = "<!-- LINK __CONTENT__ -->"
    LINK_PLACEHOLDER_CLOSE: typing.Final = "<!-- /LINK -->"
    HTML_SPACE: typing.Final = "&nbsp;"
    HTML_NEW_LINE: typing.Final = "<br>"

    def __init__(self):
        ...

    @staticmethod
    def bold(text: typing.Union[java.lang.String, str]) -> str:
        """
        Surrounds the specified text with the HTML begin and end tags for bold.
        
        :param java.lang.String or str text: the original text
        :return: the text with the bold HTML tags
        :rtype: str
        """

    @staticmethod
    def charNeedsHTMLEscaping(codePoint: typing.Union[jpype.JInt, int]) -> bool:
        """
        Tests a unicode code point (i.e., 32 bit character) to see if it needs to be escaped before
        being added to a HTML document because it is non-printable or a non-standard control
        character
        
        :param jpype.JInt or int codePoint: character to test
        :return: boolean true if character should be escaped
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def colorString(color: java.awt.Color, text: typing.Union[java.lang.String, str]) -> str:
        """
        Surrounds the indicated text with HTML font coloring tags so that the
        text will display in color within HTML.  The given color will be converted to its
        hex value.
        
        :param java.awt.Color color: The Java color object to use
        :param java.lang.String or str text: the original text
        :return: the string for HTML colored text
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def colorString(rgbColor: typing.Union[java.lang.String, str], text: typing.Union[java.lang.String, str]) -> str:
        """
        Surrounds the indicated text with HTML font coloring tags so that the
        text will display in color within HTML.
        
        :param java.lang.String or str rgbColor: (e.g., "#8c0000") a string indicating the RGB hexadecimal color
        :param java.lang.String or str text: the original text
        :return: the string for HTML colored text
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def colorString(rgbColor: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]) -> str:
        """
        Surrounds the indicated numeric value with HTML font coloring tags so that the
        numeric value will display in color within HTML.
        
        :param java.lang.String or str rgbColor: (e.g., "#8c0000") a string indicating the RGB hexadecimal color
        :param jpype.JInt or int value: the numeric value to be converted to text and wrapped with color tags.
        :return: the string for the HTML colored number
        :rtype: str
        """

    @staticmethod
    def convertLinkPlaceholdersToHyperlinks(text: typing.Union[java.lang.String, str]) -> str:
        """
        Takes HTML text wrapped by :meth:`wrapWithLinkPlaceholder(String, String) <.wrapWithLinkPlaceholder>` and replaces
        the custom link comment tags with HTML anchor (``A``) tags, where the
        ``HREF`` value is the value that was in the ``CONTENT`` attribute.
        
        :param java.lang.String or str text: the text for which to replace the markup
        :return: the updated text
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def escapeHTML(text: typing.Union[java.lang.String, str], makeSpacesNonBreaking: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Escapes any HTML special characters in the specified text.
         
        
        Does not otherwise modify the input text or wrap lines.
         
        
        Calling this twice will result in text being double-escaped, which will not display correctly.
         
        
        See also ``StringEscapeUtils#escapeHtml3(String)`` if you need quote-safe html encoding.
        
        :param java.lang.String or str text: plain-text that might have some characters that should NOT be interpreted as HTML
        :param jpype.JBoolean or bool makeSpacesNonBreaking: true to convert spaces into &nbsp;
        :return: string with any html characters replaced with equivalents
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def escapeHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        Escapes any HTML special characters in the specified text.
        
        :param java.lang.String or str text: plain-text that might have some characters that should NOT be interpreted as HTML
        :return: string with any html characters replaced with equivalents
        :rtype: str
        
        .. seealso::
        
            | :obj:`.escapeHTML(String, boolean)`
        """

    @staticmethod
    @typing.overload
    def friendlyEncodeHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        Converts any special or reserved characters in the specified string into HTML-escaped
        entities.  Use this method when you have content containing HTML that you do not want
        interpreted as HTML, such as when displaying text that uses angle brackets around words.
        
         
        For example, consider the following
        
        
        
         
        +----------------+------------------------------+----------------+-----------------------------+
        |     Input      |            Output            |  Rendered as   | (Without Friendly Encoding) |
        +================+==============================+================+=============================+
        |                |                              |                |                             |
        |Hi <b>mom </b>  |Hi&nbsp;**&lt;**b**&gt;**mom  |Hi <b>mom </b>  |Hi **mom **                  |
        |                |&nbsp;**&lt;**/b**&gt;**      |                |                             |
        +----------------+------------------------------+----------------+-----------------------------+
        
        
          
        
        
        
        
        :param java.lang.String or str text: string to be encoded
        :return: the encoded HTML string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def friendlyEncodeHTML(text: typing.Union[java.lang.String, str], skipLeadingWhitespace: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        See :meth:`friendlyEncodeHTML(String) <.friendlyEncodeHTML>`
        
        :param java.lang.String or str text: string to be encoded
        :param jpype.JBoolean or bool skipLeadingWhitespace: true signals to ignore any leading whitespace characters.
                This is useful when line wrapping to force wrapped lines to the left
        :return: the encoded HTML string
        :rtype: str
        """

    @staticmethod
    def fromHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        Checks the given string to see it is HTML, according to :obj:`BasicHTML` and then
        will return the text without any markup tags if it is.
        
        :param java.lang.String or str text: the text to convert
        :return: the converted String
        :rtype: str
        """

    @staticmethod
    def isHTML(text: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given text is HTML.  For this to be true, the text must begin with
        the <HTML> tag.
        
        :param java.lang.String or str text: the text to check
        :return: true if the given text is HTML
        :rtype: bool
        """

    @staticmethod
    def isUnbreakableHTML(text: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the text cannot be broken into lines due to
        the usage of particular HTML constructs.
        
        :param java.lang.String or str text: the text to check
        :return: true if the text cannot be correctly broken into lines
        :rtype: bool
        """

    @staticmethod
    def italic(text: typing.Union[java.lang.String, str]) -> str:
        """
        Surrounds the specified text with the HTML begin and end tags for italic.
        
        :param java.lang.String or str text: the original text
        :return: the text with the italic HTML tags
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def lineWrapWithHTMLLineBreaks(text: typing.Union[java.lang.String, str]) -> str:
        """
        This is just a convenience call to :meth:`lineWrapWithHTMLLineBreaks(String, int) <.lineWrapWithHTMLLineBreaks>` with
        a max line length of 0, which signals to not to wrap on line length, but only on
        newline characters.
        
        :param java.lang.String or str text: the text to wrap
        :return: the updated text
        :rtype: str
        
        .. seealso::
        
            | :obj:`.lineWrapWithHTMLLineBreaks(String, int)`
        """

    @staticmethod
    @typing.overload
    def lineWrapWithHTMLLineBreaks(text: typing.Union[java.lang.String, str], maxLineLength: typing.Union[jpype.JInt, int]) -> str:
        """
        Replaces all newline characters with HTML <BR> tags.
        
         
        Unlike :meth:`toWrappedHTML(String) <.toWrappedHTML>`, this method does **not** add the
        <HTML> tag to the given text.
        
         
        Call this method when you wish to create your own HTML content, with parts of that
        content line wrapped.
        
        :param java.lang.String or str text: the text to wrap
        :param jpype.JInt or int maxLineLength: the max length of the line; 0 if no max is desired
        :return: the updated text
        :rtype: str
        """

    @staticmethod
    def setFont(text: typing.Union[java.lang.String, str], color: java.awt.Color, ptSize: typing.Union[jpype.JInt, int]) -> str:
        """
        Sets the font size and color of the given text by wrapping it in <span> tags.
        
        :param java.lang.String or str text: the text to size
        :param java.awt.Color color: the color of the text
        :param jpype.JInt or int ptSize: the point size of the text
        :return: the updated String
        :rtype: str
        """

    @staticmethod
    def setFontSize(text: typing.Union[java.lang.String, str], ptSize: typing.Union[jpype.JInt, int]) -> str:
        """
        Sets the font size of the given text by wrapping it in <span> tags.
        
        :param java.lang.String or str text: the text to size
        :param jpype.JInt or int ptSize: the point size of the text
        :return: the updated String
        :rtype: str
        """

    @staticmethod
    def spaces(num: typing.Union[jpype.JInt, int]) -> str:
        """
        Creates a string with the indicated number of HTML space characters (``&nbsp;``).
        
        :param jpype.JInt or int num: the number of HTML spaces
        :return: the string of HTML spaces
        :rtype: str
        """

    @staticmethod
    def styleText(attributes: javax.swing.text.SimpleAttributeSet, text: typing.Union[java.lang.String, str]) -> str:
        """
        Escapes and wraps the given text in ``SPAN`` tag with font attributes specified in the
        given attributes.  Specifically, these attributes are used:
        
         
        * :obj:`StyleConstants.Foreground` - :obj:`Color` object
        * :obj:`StyleConstants.FontFamily` - font name
        * :obj:`StyleConstants.FontSize` - size in pixels
        * :obj:`StyleConstants.Italic` - true if italic
        * :obj:`StyleConstants.Bold` - true if bold
        
         
        
        See :obj:`GAttributes` for a convenient way to create the correct attributes for a font and
        color.
        
        :param javax.swing.text.SimpleAttributeSet attributes: the attributes
        :param java.lang.String or str text: the content to style
        :return: the styled content
        :rtype: str
        
        .. seealso::
        
            | :obj:`GAttributes`
        """

    @staticmethod
    def toHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        Convert the given string to HTML by adding the HTML tag and
        replacing new line chars with HTML <BR> tags.
        
        :param java.lang.String or str text: The text to convert to HTML
        :return: the converted text
        :rtype: str
        """

    @staticmethod
    def toHexString(color: java.awt.Color) -> str:
        """
        Returns a color string of the format #RRGGBB.  As an example, :obj:`Color.RED` would be
        returned as #FF0000 (the values are padded with 0s to make to fill up 2 digits per
        component).
        
        :param java.awt.Color color: The color to convert.
        :return: a string of the format #RRGGBB.
        :rtype: str
        """

    @staticmethod
    def toLiteralHTML(text: typing.Union[java.lang.String, str], maxLineLength: typing.Union[jpype.JInt, int]) -> str:
        """
        A convenience method to split the given HTML into lines, based on the given length, and
        then to :meth:`friendlyEncodeHTML(String) <.friendlyEncodeHTML>` the text.
        
         
        This method preserves all whitespace between line breaks.
        
         
        **Note: **This method is not intended to handle text that already contains
        entity escaped text.  The result will not render correctly as HTML.
        
        :param java.lang.String or str text: the text to update
        :param jpype.JInt or int maxLineLength: the max line length upon which to wrap; 0 for no max length
        :return: the updated text
        :rtype: str
        """

    @staticmethod
    def toLiteralHTMLForTooltip(text: typing.Union[java.lang.String, str]) -> str:
        """
        A very specific method that will:
         
        1. 
        Make sure the HTML length is clipped to a reasonable size
        
        2. Escape any embedded HTML (so that it is not interpreted as HTML)
        
        3. 
        Put the entire result in HTML
        
        
        
        :param java.lang.String or str text: the text to convert
        :return: the converted value.
        :rtype: str
        """

    @staticmethod
    def toRGBString(color: java.awt.Color) -> str:
        """
        Returns a color string of the format rrrgggbbb.  As an example, :obj:`Color.RED` would be
        returned as 255000000 (the values are padded with 0s to make to fill up 3 digits per
        component).
        
        :param java.awt.Color color: The color to convert.
        :return: a string of the format rrrgggbbb.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toWrappedHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        This is just a convenience method to call :meth:`toWrappedHTML(String, int) <.toWrappedHTML>` with a
        max line length of 75.
        
        :param java.lang.String or str text: The text to convert
        :return: converted text
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toWrappedHTML(text: typing.Union[java.lang.String, str], maxLineLength: typing.Union[jpype.JInt, int]) -> str:
        """
        Similar to :meth:`toHTML(String) <.toHTML>` in that it will wrap the given text in
        HTML tags and split the content into multiple lines.  The difference is that this method
        will split lines that pass the given maximum length **and** on ``'\n'``
        characters.  Alternatively, :meth:`toHTML(String) <.toHTML>` will only split the given
        text on ``'\n'`` characters.
        
        :param java.lang.String or str text: The text to convert
        :param jpype.JInt or int maxLineLength: The maximum number of characters that should appear in a line;
                0 signals not to wrap the line based upon length
        :return: converted text
        :rtype: str
        """

    @staticmethod
    def underline(text: typing.Union[java.lang.String, str]) -> str:
        """
        Surrounds the specified text with the HTML begin and end tags for underlined text.
        
        :param java.lang.String or str text: the original text
        :return: the text with the underline HTML tags
        :rtype: str
        """

    @staticmethod
    def wrapAsHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        Marks the given text as HTML in order to be rendered thusly by Java widgets.
        
        :param java.lang.String or str text: the original text
        :return: the text marked as HTML
        :rtype: str
        """

    @staticmethod
    def wrapWithLinkPlaceholder(htmlText: typing.Union[java.lang.String, str], content: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the given text wrapped in :obj:`.LINK_PLACEHOLDER_OPEN` and close tags.
        If ``foo`` is passed for the HTML text, with a content value of ``123456``, then
        the output will look like:
         
            <!-- LINK CONTENT="123456" -->foo<!-- /LINK -->
         
        
        :param java.lang.String or str htmlText: the HTML text to wrap
        :param java.lang.String or str content: the value that will be put into the ``CONTENT`` section of the
                generated HTML.  This can later be retrieved by clients transforming this text.
        :return: the wrapped text
        :rtype: str
        """


class TrackedTaskListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def taskAdded(self, task: ghidra.util.task.Task):
        """
        A callback for when a Task is starting to be tracked.
        
        :param ghidra.util.task.Task task: The task being tracked.
        """

    def taskRemoved(self, task: ghidra.util.task.Task):
        """
        A callback when a task is no longer being tracked.
        
        :param ghidra.util.task.Task task: The task that is no longer tracked.
        """


class WebColors(java.lang.Object):
    """
    Class for web color support. This class defines many of the colors used by html. This class
    includes methods for converting a color to a string (name or hex value) and for converting
    those strings back to a color.
     
    
    Usage Note: Java's HTML rendering engine supports colors in hex form ('#aabb11').  Also, the
    engine supports many web color names ('silver').  However, not all web color names defined in
    this file are supported.  Thus, when specifying HTML colors, do not rely on these web color
    names.
    """

    class_: typing.ClassVar[java.lang.Class]
    BLACK: typing.Final[java.awt.Color]
    NAVY: typing.Final[java.awt.Color]
    DARK_BLUE: typing.Final[java.awt.Color]
    MEDIUM_BLUE: typing.Final[java.awt.Color]
    BLUE: typing.Final[java.awt.Color]
    DARK_GREEN: typing.Final[java.awt.Color]
    GREEN: typing.Final[java.awt.Color]
    TEAL: typing.Final[java.awt.Color]
    DARK_CYAN: typing.Final[java.awt.Color]
    DEEP_SKY_BLUE: typing.Final[java.awt.Color]
    DARK_TURQUOSE: typing.Final[java.awt.Color]
    LIME: typing.Final[java.awt.Color]
    SPRING_GREEN: typing.Final[java.awt.Color]
    AQUA: typing.Final[java.awt.Color]
    CYAN: typing.Final[java.awt.Color]
    MIDNIGHT_BLUE: typing.Final[java.awt.Color]
    DOGER_BLUE: typing.Final[java.awt.Color]
    LIGHT_SEA_GREEN: typing.Final[java.awt.Color]
    FOREST_GREEN: typing.Final[java.awt.Color]
    SEA_GREEN: typing.Final[java.awt.Color]
    DARK_SLATE_GRAY: typing.Final[java.awt.Color]
    LIME_GREEN: typing.Final[java.awt.Color]
    TURQUOISE: typing.Final[java.awt.Color]
    ROYAL_BLUE: typing.Final[java.awt.Color]
    STEEL_BLUE: typing.Final[java.awt.Color]
    DARK_SLATE_BLUE: typing.Final[java.awt.Color]
    INDIGO: typing.Final[java.awt.Color]
    CADET_BLUE: typing.Final[java.awt.Color]
    REBECCA_PURPLE: typing.Final[java.awt.Color]
    DIM_GRAY: typing.Final[java.awt.Color]
    SLATE_BLUE: typing.Final[java.awt.Color]
    OLIVE_DRAB: typing.Final[java.awt.Color]
    SLATE_GRAY: typing.Final[java.awt.Color]
    LAWN_GREEN: typing.Final[java.awt.Color]
    CHARTREUSE: typing.Final[java.awt.Color]
    AQUAMARINE: typing.Final[java.awt.Color]
    MAROON: typing.Final[java.awt.Color]
    PURPLE: typing.Final[java.awt.Color]
    OLIVE: typing.Final[java.awt.Color]
    GRAY: typing.Final[java.awt.Color]
    SYY_BLUE: typing.Final[java.awt.Color]
    LIGHT_SKY_BLUE: typing.Final[java.awt.Color]
    BLUE_VIOLET: typing.Final[java.awt.Color]
    DARK_RED: typing.Final[java.awt.Color]
    DARK_MAGENTA: typing.Final[java.awt.Color]
    SADDLE_BROWN: typing.Final[java.awt.Color]
    DARK_SEA_GREEN: typing.Final[java.awt.Color]
    LIGHT_GREEN: typing.Final[java.awt.Color]
    MEDIUM_PURPLE: typing.Final[java.awt.Color]
    DARK_VIOLET: typing.Final[java.awt.Color]
    PALE_GREEN: typing.Final[java.awt.Color]
    DARK_ORCHID: typing.Final[java.awt.Color]
    YELLOW_GREEN: typing.Final[java.awt.Color]
    SIENNA: typing.Final[java.awt.Color]
    BROWN: typing.Final[java.awt.Color]
    DARK_GRAY: typing.Final[java.awt.Color]
    LIGHT_BLUE: typing.Final[java.awt.Color]
    GREEN_YELLOW: typing.Final[java.awt.Color]
    PALE_TURQUOISE: typing.Final[java.awt.Color]
    POWDER_BLUE: typing.Final[java.awt.Color]
    FIRE_BRICK: typing.Final[java.awt.Color]
    DARK_GOLDENROD: typing.Final[java.awt.Color]
    MEDIUM_ORCHID: typing.Final[java.awt.Color]
    ROSY_BROWN: typing.Final[java.awt.Color]
    DARK_KHAKI: typing.Final[java.awt.Color]
    SILVER: typing.Final[java.awt.Color]
    INDIAN_RED: typing.Final[java.awt.Color]
    PERU: typing.Final[java.awt.Color]
    CHOCOLATE: typing.Final[java.awt.Color]
    TAN: typing.Final[java.awt.Color]
    LIGHT_GRAY: typing.Final[java.awt.Color]
    THISTLE: typing.Final[java.awt.Color]
    ORCHID: typing.Final[java.awt.Color]
    GOLDEN_ROD: typing.Final[java.awt.Color]
    PALE_VIOLET_RED: typing.Final[java.awt.Color]
    CRIMSON: typing.Final[java.awt.Color]
    GAINSBORO: typing.Final[java.awt.Color]
    PLUM: typing.Final[java.awt.Color]
    BURLYWOOD: typing.Final[java.awt.Color]
    LIGHT_CYAN: typing.Final[java.awt.Color]
    LAVENDER: typing.Final[java.awt.Color]
    DARK_SALMON: typing.Final[java.awt.Color]
    VIOLET: typing.Final[java.awt.Color]
    PALE_GOLDENROD: typing.Final[java.awt.Color]
    LIGHT_CORAL: typing.Final[java.awt.Color]
    KHAKE: typing.Final[java.awt.Color]
    ALICE_BLUE: typing.Final[java.awt.Color]
    HONEY_DEW: typing.Final[java.awt.Color]
    AZURE: typing.Final[java.awt.Color]
    SANDY_BROWN: typing.Final[java.awt.Color]
    WHEAT: typing.Final[java.awt.Color]
    BEIGE: typing.Final[java.awt.Color]
    WHITE_SMOKE: typing.Final[java.awt.Color]
    MINT_CREAM: typing.Final[java.awt.Color]
    GHOST_WHITE: typing.Final[java.awt.Color]
    SALMON: typing.Final[java.awt.Color]
    ANTIQUE_WHITE: typing.Final[java.awt.Color]
    LINEN: typing.Final[java.awt.Color]
    OLDLACE: typing.Final[java.awt.Color]
    RED: typing.Final[java.awt.Color]
    FUCHSIA: typing.Final[java.awt.Color]
    MAGENTA: typing.Final[java.awt.Color]
    DEEP_PINK: typing.Final[java.awt.Color]
    ORANGE_RED: typing.Final[java.awt.Color]
    TOMATO: typing.Final[java.awt.Color]
    HOT_PINK: typing.Final[java.awt.Color]
    CORAL: typing.Final[java.awt.Color]
    DARK_ORANGE: typing.Final[java.awt.Color]
    LIGHT_SALMON: typing.Final[java.awt.Color]
    ORANGE: typing.Final[java.awt.Color]
    LIGHT_PINK: typing.Final[java.awt.Color]
    PINK: typing.Final[java.awt.Color]
    GOLD: typing.Final[java.awt.Color]
    PEACH_PUFF: typing.Final[java.awt.Color]
    NAVAJO_WHITE: typing.Final[java.awt.Color]
    MOCCASIN: typing.Final[java.awt.Color]
    BISQUE: typing.Final[java.awt.Color]
    MISTY_ROSE: typing.Final[java.awt.Color]
    BLANCHED_ALMOND: typing.Final[java.awt.Color]
    PAPAYA_WHIP: typing.Final[java.awt.Color]
    LAVENDER_BLUSH: typing.Final[java.awt.Color]
    SEASHELL: typing.Final[java.awt.Color]
    CORNSILK: typing.Final[java.awt.Color]
    LEMON_CHIFFON: typing.Final[java.awt.Color]
    FLORAL_WHITE: typing.Final[java.awt.Color]
    SNOW: typing.Final[java.awt.Color]
    YELLOW: typing.Final[java.awt.Color]
    LIGHT_YELLOW: typing.Final[java.awt.Color]
    IVORY: typing.Final[java.awt.Color]
    WHITE: typing.Final[java.awt.Color]
    MEDIUM_SPRING_GREEN: typing.Final[java.awt.Color]
    LIGHT_GOLDENROD: typing.Final[java.awt.Color]
    MEDIUM_VIOLET_RED: typing.Final[java.awt.Color]
    LIGHT_STEEL_BLUE: typing.Final[java.awt.Color]
    LIGHT_SLATE_GRAY: typing.Final[java.awt.Color]
    MEDIUM_SLATE_BLUE: typing.Final[java.awt.Color]
    MEDIUM_SEA_GREEN: typing.Final[java.awt.Color]
    MEDUM_AQUA_MARINE: typing.Final[java.awt.Color]
    MEDIUM_TURQOISE: typing.Final[java.awt.Color]
    DARK_OLIVE_GREEN: typing.Final[java.awt.Color]
    CORNFLOWER_BLUE: typing.Final[java.awt.Color]

    @staticmethod
    def getColor(colorString: typing.Union[java.lang.String, str]) -> java.awt.Color:
        """
        Attempts to convert the given string into a color in a most flexible manner. It first checks
        if the given string matches the name of a known web color as defined above. If so it
        returns that color. Otherwise it tries to parse the string in any one of the following
        formats:
         
        #rrggbb
        #rrggbbaa
        0xrrggbb
        0xrrggbbaa
        rgb(red, green, blue)
        rgba(red, green, alpha)
         
        In the hex digit formats, the hex digits "rr", "gg", "bb", "aa" represent the values for red,
        green, blue, and alpha, respectively. In the "rgb" and "rgba" formats the red, green, and
        blue values are all integers between 0-255, while the alpha value is a float value from 0.0 to
        1.0.
         
        
        
        
        :param java.lang.String or str colorString: the color name
        :return: a color for the given string or null
        :rtype: java.awt.Color
        """

    @staticmethod
    def getColorOrDefault(value: typing.Union[java.lang.String, str], defaultColor: java.awt.Color) -> java.awt.Color:
        """
        Tries to find a color for the given String value. The String value can either be
        a hex string (see :meth:`Color.decode(String) <Color.decode>`) or a web color name as defined
        above
        
        :param java.lang.String or str value: the string value to interpret as a color
        :param java.awt.Color defaultColor: a default color to return if the string can't be converted to a color
        :return: a color for the given string value or the default color if the string can't be translated
        :rtype: java.awt.Color
        """

    @staticmethod
    def toColorName(color: java.awt.Color) -> str:
        ...

    @staticmethod
    def toHexString(color: java.awt.Color) -> str:
        """
        Returns the hex value string for the given color
        
        :param java.awt.Color color: the color
        :return: the string
        :rtype: str
        """

    @staticmethod
    def toRgbString(color: java.awt.Color) -> str:
        """
        Returns the rgb value string for the given color
        
        :param java.awt.Color color: the color
        :return: the string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toString(color: java.awt.Color) -> str:
        """
        Converts a color to a string value. If there is a defined color for the given color value,
        the color name will be returned. Otherwise, it will return a hex string for the color as
        follows. If the color has an non-opaque alpha value, it will be of the form #rrggbb. If
        it has an alpha value,then the format will be #rrggbbaa.
        
        :param java.awt.Color color: the color to convert to a string.
        :return: the string representation for the given color.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toString(color: java.awt.Color, useNameIfPossible: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Converts a color to a string value.  If the color is a WebColor and the useNameIfPossible
        is true, the name of the color will be returned. OOtherwise, it will return a hex string for the color as
        follows. If the color has an non-opaque alpha value, it will be of the form #rrggbb. If
        it has an alpha value ,then the format will be #rrggbbaa.
        
        :param java.awt.Color color: the color to convert to a string.
        :param jpype.JBoolean or bool useNameIfPossible: if true, the name of the color will be returned if the color is
        a WebColor
        :return: the string representation for the given color.
        :rtype: str
        """

    @staticmethod
    def toWebColorName(color: java.awt.Color) -> str:
        """
        Returns the WebColor name for the given color. Returns null if the color is not a WebColor
        
        :param java.awt.Color color: the color to lookup a WebColor name.
        :return: the WebColor name for the given color. Returns null if the color is not a WebColor
        :rtype: str
        """


class ColorUtils(java.lang.Object):

    class ColorBlender(java.lang.Object):
        """
        Blender of colors
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def add(self, color: java.awt.Color):
            """
            Add a color into the mixture, in a quantity proportional to its alpha value
            
            :param java.awt.Color color: the color to mix
            """

        def clear(self):
            """
            Reset the mixture
            """

        def getColor(self, defaultColor: java.awt.Color) -> java.awt.Color:
            """
            Get the color of the current mixture
            
            :param java.awt.Color defaultColor: the default (background) color, if the mixture has no color
            :return: the resulting color
            :rtype: java.awt.Color
            """

        @property
        def color(self) -> java.awt.Color:
            ...


    class_: typing.ClassVar[java.lang.Class]
    HUE_RED: typing.Final = 0.0
    HUE_ORANGE: typing.Final = 0.0833333358168602
    HUE_YELLOW: typing.Final = 0.1666666716337204
    HUE_LIME: typing.Final = 0.25
    HUE_GREEN: typing.Final = 0.3333333432674408
    HUE_PINE: typing.Final = 0.4166666567325592
    HUE_TURQUISE: typing.Final = 0.5
    HUE_SAPPHIRE: typing.Final = 0.5833333134651184
    HUE_BLUE: typing.Final = 0.6666666865348816
    HUE_ROYAL: typing.Final = 0.75
    HUE_PURPLE: typing.Final = 0.8333333134651184
    HUE_PINK: typing.Final = 0.9166666865348816
    COMPARATOR: typing.ClassVar[java.util.Comparator[java.awt.Color]]
    """
    A color :obj:`Comparator` for ordering colors.
    """


    def __init__(self):
        ...

    @staticmethod
    def addColors(primary: java.awt.Color, secondary: java.awt.Color) -> java.awt.Color:
        """
        Combines colors in a way the makes them stand out from each other more than just averaging
        them together. Basically if the colors are bright, the result is a darker value than the
        primary, adjusted based on the values in the secondary. If the colors are dark, then the
        result is a brighter version of the primary color adjusted based on values in the secondary
        color.
        
        :param java.awt.Color primary: the primary color to be tweaked
        :param java.awt.Color secondary: the color to used to determine the amount to tweak the red,green,blue values
        :return: a new color that is a combination of the two colors
        :rtype: java.awt.Color
        """

    @staticmethod
    def average(color1: java.awt.Color, color2: java.awt.Color) -> java.awt.Color:
        """
        Creates a new color by averaging the red, green, blue, and alpha values from the given
        colors.
        
        :param java.awt.Color color1: the first color to average
        :param java.awt.Color color2: the second color to average
        :return: a new color that is the average of the two given colors
        :rtype: java.awt.Color
        """

    @staticmethod
    def blend(c1: java.awt.Color, c2: java.awt.Color, ratio: typing.Union[jpype.JDouble, float]) -> java.awt.Color:
        """
        Takes the first color, blending into it the second color, using the given ratio. A lower
        ratio (say .1f) signals to use very little of the first color; a larger ratio signals to use
        more of the first color.
        
        :param java.awt.Color c1: the first color
        :param java.awt.Color c2: the second color
        :param jpype.JDouble or float ratio: the amount of the first color to include in the final output
        :return: the new color
        :rtype: java.awt.Color
        """

    @staticmethod
    def contrastForegroundColor(color: java.awt.Color) -> java.awt.Color:
        """
        A method to produce a color (either black or white) that contrasts with the given color. This
        is useful for finding a readable foreground color for a given background.
        
        :param java.awt.Color color: the color for which to find a contrast.
        :return: the contrasting color.
        :rtype: java.awt.Color
        """

    @staticmethod
    @typing.overload
    def deriveBackground(src: java.awt.Color, hue: typing.Union[jpype.JFloat, float], sfact: typing.Union[jpype.JFloat, float], bfact: typing.Union[jpype.JFloat, float]) -> java.awt.Color:
        ...

    @staticmethod
    @typing.overload
    def deriveBackground(background: java.awt.Color, hue: typing.Union[jpype.JFloat, float]) -> java.awt.Color:
        ...

    @staticmethod
    @typing.overload
    def deriveForeground(bg: java.awt.Color, hue: typing.Union[jpype.JFloat, float], brt: typing.Union[jpype.JFloat, float]) -> java.awt.Color:
        ...

    @staticmethod
    @typing.overload
    def deriveForeground(bg: java.awt.Color, hue: typing.Union[jpype.JFloat, float]) -> java.awt.Color:
        ...

    @staticmethod
    @typing.overload
    def getColor(rgba: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Return the color object given a rgba value that includes the desired alpha value.
        
        :param jpype.JInt or int rgba: value where bits 24-31 are alpha, 16-23 are red, 8-15 are green, 0-7 are
        blue
        :return: the color object given a rgba value that includes the desired alpha value
        :rtype: java.awt.Color
        """

    @staticmethod
    @typing.overload
    def getColor(red: typing.Union[jpype.JInt, int], green: typing.Union[jpype.JInt, int], blue: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Return an opaque color object given for the given red, green, and blue values.
        
        :param jpype.JInt or int red: the red value (0 - 255)
        :param jpype.JInt or int green: the green value (0 - 255)
        :param jpype.JInt or int blue: the blue value (0 - 255)
        :return: the color object for the given values
        :rtype: java.awt.Color
        """

    @staticmethod
    @typing.overload
    def getColor(red: typing.Union[jpype.JInt, int], green: typing.Union[jpype.JInt, int], blue: typing.Union[jpype.JInt, int], alpha: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Return the color object given for the given red, green, blue, and alpha values.
        
        :param jpype.JInt or int red: the red value (0 - 255)
        :param jpype.JInt or int green: the green value (0 - 255)
        :param jpype.JInt or int blue: the blue value (0 - 255)
        :param jpype.JInt or int alpha: the alpha (transparency) value (0 - 255) with 0 being fully transparent and 255 
        being fully opaque opaque
        :return: the color object for the given values
        :rtype: java.awt.Color
        """

    @staticmethod
    def getOpaqueColor(rgb: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Returns an opaque color with the given rgb value. The resulting color will have an alpha
        value of 0xff.
        
        :param jpype.JInt or int rgb: the value where bits 16-23 are red, 8-15 are green, 0-7 are blue. Bits 24-31 will
        be set to 0xff.
        :return: an opaque color with the given rgb value
        :rtype: java.awt.Color
        """

    @staticmethod
    def withAlpha(c: java.awt.Color, alpha: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Returns a new color that is comprised of the given color's rgb value and the given alpha
        value.
        
        :param java.awt.Color c: the color
        :param jpype.JInt or int alpha: the alpha
        :return: the new color
        :rtype: java.awt.Color
        """


class HelpLocation(java.lang.Object):
    """
    Class to identify where help can be located for some object. Help can be
    set on actions or dialogs.
    """

    class_: typing.ClassVar[java.lang.Class]
    HELP_TOPICS: typing.Final = "help/topics/"
    """
    A special prefix used in the 'src' attribute if links and images to signal to the framework
    to locate the given resource.  Using this allows cross-module help references to be relative,
    starting with this prefix.
    """

    HELP_SHARED: typing.Final = "help/shared/"
    """
    A special prefix used in the 'src' attribute if links and images to signal to the framework
    to locate the given resource.  This is meant to be used with shared help resources, such
    as images.
    """


    @typing.overload
    def __init__(self, topic: typing.Union[java.lang.String, str], anchor: typing.Union[java.lang.String, str]):
        """
        Construct a Help location using the specified topic and anchor names.
        An html file contained within the specified help topic directory must have an Anchor
        defined using the specified anchor name.
         
        
        **Note:**  You can specify a ``null`` anchor value.  In that case, the given topic
        will be searched for a file with the same name as the topic.  If such a file exists, 
        then that file will be used as the file for this location.  If no such file exists, then 
        the help file to use **cannot be resolved**.  Therefore, it is best to always specify
        a value for the help location.
        
        :param java.lang.String or str topic: topic directory name
        :param java.lang.String or str anchor: anchor name or null
        """

    @typing.overload
    def __init__(self, topic: typing.Union[java.lang.String, str], anchor: typing.Union[java.lang.String, str], inceptionInformation: typing.Union[java.lang.String, str]):
        """
        Construct a Help location using the specified topic and anchor names.
        An html file contained within the specified help topic directory must have an Anchor
        defined using the specified anchor name.
         
        
        **Note:**  You can specify a ``null`` anchor value.  In that case, the given topic
        will be searched for a file with the same name as the topic.  If such a file exists, 
        then that file will be used as the file for this location.  If no such file exists, then 
        the help file to use **cannot be resolved**.  Therefore, it is best to always specify
        a value for the help location.
        
        :param java.lang.String or str topic: topic directory name
        :param java.lang.String or str anchor: anchor name or null
        :param java.lang.String or str inceptionInformation: the description of from whence the item 
                described by this location has come; can be null
        """

    def getAnchor(self) -> str:
        """
        Returns the topic anchor name if known, otherwise null.
        
        :return: the topic anchor name if known, otherwise null.
        :rtype: str
        """

    def getHelpId(self) -> str:
        """
        Get the help ID for this help location.
        
        :return: null if there is a Help URL instead of a help ID
        :rtype: str
        """

    def getHelpURL(self) -> java.net.URL:
        """
        Get the help URL for this help location. A URL is created when the
        constructor ``HelpLocation(Class, String, String)`` is
        used by a plugin that has help relative to its class.
        
        :return: the URL or null if a help ID is used
        :rtype: java.net.URL
        """

    def getInceptionInformation(self) -> str:
        """
        Returns information describing how/where this help location was created.  This value may
        be null.
        
        :return: information describing how/where this help location was created.
        :rtype: str
        """

    def getTopic(self) -> str:
        """
        Returns the topic name/path if known, otherwise null.
        
        :return: the topic name/path if known, otherwise null.
        :rtype: str
        """

    @property
    def inceptionInformation(self) -> java.lang.String:
        ...

    @property
    def helpId(self) -> java.lang.String:
        ...

    @property
    def anchor(self) -> java.lang.String:
        ...

    @property
    def topic(self) -> java.lang.String:
        ...

    @property
    def helpURL(self) -> java.net.URL:
        ...


class TaskUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def addTrackedTask(task: ghidra.util.task.Task, monitor: ghidra.util.task.TaskMonitor):
        """
        Adds a Task to the list of tasks that have not yet finished running.  
         
        
        Note: it is safe to add the same task more than once, as it will not be repeatedly 
        tracked.
        
        :param ghidra.util.task.Task task: The task to watch
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for the given task
        """

    @staticmethod
    def addTrackedTaskListener(listener: TrackedTaskListener):
        """
        Adds a listener that will be notified when tasks are tracked (when they are added and
        removed from tracking).
        
        :param TrackedTaskListener listener: The listener to add.
        """

    @staticmethod
    def isExecutingTasks() -> bool:
        """
        Returns true if there are tasks that are running or need to be run.
        
        :return: true if there are tasks that are running or need to be run.
        :rtype: bool
        """

    @staticmethod
    def isTaskRunning(title: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the task with the indicated title is running.
        
        :param java.lang.String or str title: the title of the desired task
        :return: true if the task with the indicated title is running.
        :rtype: bool
        """

    @staticmethod
    def removeTrackedTask(task: ghidra.util.task.Task):
        """
        Removes the Task to the list of tasks that have not yet finished running.
        
        :param ghidra.util.task.Task task: The task to stop watching.
        """

    @staticmethod
    def removeTrackedTaskListener(listener: TrackedTaskListener):
        """
        Removes the given listener added via :meth:`addTrackedTask(Task,TaskMonitor) <.addTrackedTask>`.
        
        :param TrackedTaskListener listener: The listener that needs to be removed.
        """


class JavaSourceFile(java.lang.Object):

    @typing.type_check_only
    class TokenMatcher(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TokenPairMatcher(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filename: typing.Union[java.lang.String, str]):
        ...

    def getImportSectionStartLineNumber(self) -> int:
        ...

    def getJavaStatementStartingAtLine(self, firstUseLineNumber: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getLine(self, oneBasedLineNumber: typing.Union[jpype.JInt, int]) -> JavaSourceLine:
        ...

    def getLineContaintingStatementStart(self, lineNumber: typing.Union[jpype.JInt, int]) -> JavaSourceLine:
        ...

    def getLineNumberAfterStatementAtLine(self, lineNumber: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getOriginalSourceFileCopy(self) -> JavaSourceFile:
        ...

    def hasChanges(self) -> bool:
        ...

    def removeJavaStatement(self, lineNumber: typing.Union[jpype.JInt, int]):
        ...

    def save(self):
        ...

    @property
    def lineNumberAfterStatementAtLine(self) -> jpype.JInt:
        ...

    @property
    def lineContaintingStatementStart(self) -> JavaSourceLine:
        ...

    @property
    def line(self) -> JavaSourceLine:
        ...

    @property
    def importSectionStartLineNumber(self) -> jpype.JInt:
        ...

    @property
    def originalSourceFileCopy(self) -> JavaSourceFile:
        ...

    @property
    def javaStatementStartingAtLine(self) -> java.lang.String:
        ...


class Conv(java.lang.Object):
    """
    Helper methods for converting between
    number data types without negative
    promotion.
     
    
    Consider using java built-in methods for conversion instead of methods from this
    class.
    """

    class_: typing.ClassVar[java.lang.Class]
    BYTE_MASK: typing.Final = 255
    """
    A byte mask.
    
    
    .. deprecated::
    
    :meth:`Byte.toUnsignedInt(byte) <Byte.toUnsignedInt>` will handle most use cases of this constant
    """

    SHORT_MASK: typing.Final = 65535
    """
    A short mask.
    
    
    .. deprecated::
    
    :meth:`Short.toUnsignedInt(short) <Short.toUnsignedInt>` will handle most use cases of this constant
    """

    INT_MASK: typing.Final = 4294967295
    """
    An integer mask.
    
    
    .. deprecated::
    
    :meth:`Integer.toUnsignedLong(int) <Integer.toUnsignedLong>` will handle most use cases of this constant
    """


    @staticmethod
    @deprecated("Use Byte.toUnsignedInt(byte) instead")
    def byteToInt(b: typing.Union[jpype.JByte, int]) -> int:
        """
        Converts a byte to an integer.
        
        :param jpype.JByte or int b: the byte
        :return: the integer equivalent of the byte
        :rtype: int
        
        .. deprecated::
        
        Use :meth:`Byte.toUnsignedInt(byte) <Byte.toUnsignedInt>` instead
        """

    @staticmethod
    @deprecated("Use Byte.toUnsignedLong(byte) instead")
    def byteToLong(b: typing.Union[jpype.JByte, int]) -> int:
        """
        Converts a byte to a long.
        
        :param jpype.JByte or int b: the byte
        :return: the long equivalent of the byte
        :rtype: int
        
        .. deprecated::
        
        Use :meth:`Byte.toUnsignedLong(byte) <Byte.toUnsignedLong>` instead
        """

    @staticmethod
    @deprecated("Use other built-ins like Byte.toUnsignedInt(byte)")
    def byteToShort(b: typing.Union[jpype.JByte, int]) -> int:
        """
        
        
        :param jpype.JByte or int b: the byte
        :return: the short equivalent of the byte
        :rtype: int
        
        .. deprecated::
        
        Use other built-ins like :meth:`Byte.toUnsignedInt(byte) <Byte.toUnsignedInt>`
        """

    @staticmethod
    @deprecated("Use Integer.toUnsignedLong(int) instead")
    def intToLong(i: typing.Union[jpype.JInt, int]) -> int:
        """
        Converts an integer to a long.
        
        :param jpype.JInt or int i: the integer
        :return: the long equivalent of the long
        :rtype: int
        
        .. deprecated::
        
        Use :meth:`Integer.toUnsignedLong(int) <Integer.toUnsignedLong>` instead
        """

    @staticmethod
    @deprecated("Use Short.toUnsignedInt(short) instead")
    def shortToInt(s: typing.Union[jpype.JShort, int]) -> int:
        """
        Converts a short to an integer.
        
        :param jpype.JShort or int s: the short
        :return: the integer equivalent of the short
        :rtype: int
        
        .. deprecated::
        
        Use :meth:`Short.toUnsignedInt(short) <Short.toUnsignedInt>` instead
        """

    @staticmethod
    @deprecated("Use Short.toUnsignedLong(short) instead")
    def shortToLong(s: typing.Union[jpype.JShort, int]) -> int:
        """
        Converts a short to a long.
        
        :param jpype.JShort or int s: the short
        :return: the long eqivalent of the short
        :rtype: int
        
        .. deprecated::
        
        Use :meth:`Short.toUnsignedLong(short) <Short.toUnsignedLong>` instead
        """

    @staticmethod
    @typing.overload
    def toHexString(b: typing.Union[jpype.JByte, int]) -> str:
        """
        Consider using :meth:`String.format("%02x", b) <String.format>` instead.
         
        
        Converts a byte into a padded hex string.
        
        :param jpype.JByte or int b: the byte
        :return: the padded hex string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toHexString(s: typing.Union[jpype.JShort, int]) -> str:
        """
        Consider using :meth:`String.format("%04x", s) <String.format>` instead.
         
        
        Converts a short into a padded hex string.
        
        :param jpype.JShort or int s: the short
        :return: the padded hex string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toHexString(i: typing.Union[jpype.JInt, int]) -> str:
        """
        Consider using :meth:`String.format("%08x", i) <String.format>` instead.
         
        
        Converts an integer into a padded hex string.
        
        :param jpype.JInt or int i: the integer
        :return: the padded hex string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toHexString(l: typing.Union[jpype.JLong, int]) -> str:
        """
        Consider using :meth:`String.format("%016x", l) <String.format>` instead.
         
        
        Converts a long into a padded hex string.
        
        :param jpype.JLong or int l: the long
        :return: the padded hex string
        :rtype: str
        """

    @staticmethod
    @deprecated("Use new String(bytes, StandardCharSets.US_ASCII)\n instead")
    def toString(array: jpype.JArray[jpype.JByte]) -> str:
        """
        
        
        Old and **incorrect** way to convert bytes to a String by casting their
        values to chars.  Do not use.  Does not seem to be used in current codebase.
        
        :param jpype.JArray[jpype.JByte] array: 
        :return: 
        :rtype: str
        
        .. deprecated::
        
        Use :meth:`new String(bytes, StandardCharSets.US_ASCII) <String.String>`
        instead
        """

    @staticmethod
    def zeropad(s: typing.Union[java.lang.String, str], len: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns a string that is extended to length len with zeroes.
        
        :param java.lang.String or str s: The string to pad
        :param jpype.JInt or int len: The length of the return string
        :return: A string that has been left-padded with zeros to be of length len
        :rtype: str
        """


class FilterTransformer(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def transform(self, t: T) -> java.util.List[java.lang.String]:
        ...


class TestUniversalIdGenerator(UniversalIdGenerator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def checkpoint(self):
        ...

    def restore(self):
        ...


class CountLatch(java.lang.Object):
    """
    Latch that has a count that can be incremented and decremented.  Threads that call await() will
    block until the count is 0.
    """

    @typing.type_check_only
    class Sync(java.util.concurrent.locks.AbstractQueuedSynchronizer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def await_(self):
        """
        Causes the current thread to wait until the latch count is
        zero, unless the thread is :obj:`interrupted <Thread.interrupt>`.
        
         
        If the current count is zero then this method returns immediately.
        
         
        If the current count is greater than zero then the current
        thread becomes disabled for thread scheduling purposes and lies
        dormant until one of two things happen:
         
        * The count reaches zero due to invocations of the
        :obj:`.decrement` method; or
        * Some other thread :obj:`interrupts <Thread.interrupt>`
        the current thread.
        
        
         
        If the current thread:
         
        * has its interrupted status set on entry to this method; or
        * is :obj:`interrupted <Thread.interrupt>` while waiting,
        
        then :obj:`InterruptedException` is thrown and the current thread's
        interrupted status is cleared.
        
        :raises java.lang.InterruptedException: if the current thread is interrupted
                while waiting
        """

    @typing.overload
    def await_(self, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit) -> bool:
        """
        Causes the current thread to wait until the latch count is
        zero, unless the thread is :obj:`interrupted <Thread.interrupt>`,
        or the specified waiting time elapses.
        
         
        If the current count is zero then this method returns immediately
        with the value ``true``.
        
         
        If the current count is greater than zero then the current
        thread becomes disabled for thread scheduling purposes and lies
        dormant until one of three things happen:
         
        * The count reaches zero due to invocations of the
        :obj:`.decrement` method; or
        * Some other thread :obj:`interrupts <Thread.interrupt>`
        the current thread; or
        * The specified waiting time elapses.
        
        
         
        If the count reaches zero then the method returns with the
        value ``true``.
        
         
        If the current thread:
         
        * has its interrupted status set on entry to this method; or
        * is :obj:`interrupted <Thread.interrupt>` while waiting,
        
        then :obj:`InterruptedException` is thrown and the current thread's
        interrupted status is cleared.
        
         
        If the specified waiting time elapses then the value ``false``
        is returned.  If the time is less than or equal to zero, the method
        will not wait at all.
        
        :param jpype.JLong or int timeout: the maximum time to wait
        :param java.util.concurrent.TimeUnit unit: the time unit of the ``timeout`` argument
        :return: ``true`` if the count reached zero and ``false``
                if the waiting time elapsed before the count reached zero
        :rtype: bool
        :raises java.lang.InterruptedException: if the current thread is interrupted
                while waiting
        """

    def decrement(self):
        """
        Decrements the latch count and releases any waiting threads when the count reaches 0.
        """

    def getCount(self) -> int:
        ...

    def increment(self):
        """
        Increments the latch count.
        """

    @property
    def count(self) -> jpype.JInt:
        ...


class JavaSourceLine(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, line: typing.Union[java.lang.String, str], lineNumber: typing.Union[jpype.JInt, int]):
        ...

    def append(self, text: typing.Union[java.lang.String, str]):
        ...

    def delete(self):
        ...

    def getLeadingWhitespace(self) -> str:
        ...

    def getLineNumber(self) -> int:
        ...

    def getOriginalText(self) -> str:
        ...

    def getText(self) -> str:
        ...

    def hasChanges(self) -> bool:
        ...

    def isDeleted(self) -> bool:
        ...

    def prepend(self, text: typing.Union[java.lang.String, str]):
        ...

    def setText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def originalText(self) -> java.lang.String:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def leadingWhitespace(self) -> java.lang.String:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...


class StringFormat(java.lang.Object):
    """
    Class with static methods formatting values in hex.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def hexByteString(b: typing.Union[jpype.JByte, int]) -> str:
        """
        Gets a hexadecimal representation of a byte value.
        
        :param jpype.JByte or int b: the byte value
        :return: the byte as a hexadecimal string.
        :rtype: str
        """

    @staticmethod
    def hexWordString(s: typing.Union[jpype.JShort, int]) -> str:
        """
        Gets a hexadecimal representation of a short value.
        
        :param jpype.JShort or int s: the short value
        :return: the short as a hexadecimal string.
        :rtype: str
        """

    @staticmethod
    def padIt(str: typing.Union[java.lang.String, str], padlen: typing.Union[jpype.JInt, int], endchar: typing.Union[jpype.JChar, int, str], padded: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Creates a string prepended with zeros, if padding is indicated, and adds 
        the indicated endchar as the suffix.
        
        :param java.lang.String or str str: the original string
        :param jpype.JInt or int padlen: length of the padded string without the suffix character.
        :param jpype.JChar or int or str endchar: the suffix character
        :param jpype.JBoolean or bool padded: if true then prepend with zeros
        :return: return the possibly padded string containing the suffix.
        :rtype: str
        """


class UniversalID(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JLong, int]):
        ...

    def getValue(self) -> int:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class PrivateSaveable(Saveable):
    """
    A class that signals this saveable is not meant to broadcast its changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StringUtilities(java.lang.Object):
    """
    Class with static methods that deal with string manipulation.
    """

    class LineWrapper(java.lang.Object):
        """
        About the worst way to wrap lines ever
        """

        @typing.type_check_only
        class Mode(java.lang.Enum[StringUtilities.LineWrapper.Mode]):

            class_: typing.ClassVar[java.lang.Class]
            INIT: typing.Final[StringUtilities.LineWrapper.Mode]
            WORD: typing.Final[StringUtilities.LineWrapper.Mode]
            SPACE: typing.Final[StringUtilities.LineWrapper.Mode]

            @staticmethod
            def valueOf(name: typing.Union[java.lang.String, str]) -> StringUtilities.LineWrapper.Mode:
                ...

            @staticmethod
            def values() -> jpype.JArray[StringUtilities.LineWrapper.Mode]:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, width: typing.Union[jpype.JInt, int]):
            ...

        def append(self, cs: java.lang.CharSequence) -> StringUtilities.LineWrapper:
            ...

        def finish(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DOUBLE_QUOTED_STRING_PATTERN: typing.Final[java.util.regex.Pattern]
    LINE_SEPARATOR: typing.Final[java.lang.String]
    """
    The platform specific string that is the line separator.
    """

    UNICODE_REPLACEMENT: typing.Final = 65533
    UNICODE_BE_BYTE_ORDER_MARK: typing.Final = 65279
    """
    Unicode Byte Order Marks (BOM) characters are special characters in the Unicode character
    space that signal endian-ness of the text.
     
    
    The value for the BigEndian version (0xFEFF) works for both 16 and 32 bit character values.
     
    
    There are separate values for Little Endian Byte Order Marks for 16 and 32 bit characters
    because the 32 bit value is shifted left by 16 bits.
    """

    UNICODE_LE16_BYTE_ORDER_MARK: typing.Final = 65534
    UNICODE_LE32_BYTE_ORDER_MARK: typing.Final = -131072
    DEFAULT_TAB_SIZE: typing.Final = 8

    @staticmethod
    def characterToString(c: typing.Union[jpype.JChar, int, str]) -> str:
        """
        Converts the character into a string. If the character is special, it will actually render
        the character. For example, given '\n' the output would be "\\n".
        
        :param jpype.JChar or int or str c: the character to convert into a string
        :return: the converted character
        :rtype: str
        """

    @staticmethod
    def containsAll(toSearch: java.lang.CharSequence, *searches: java.lang.CharSequence) -> bool:
        """
        Returns true if all the given ``searches`` are contained in the given string.
        
        :param java.lang.CharSequence toSearch: the string to search
        :param jpype.JArray[java.lang.CharSequence] searches: the strings to find
        :return: true if all the given ``searches`` are contained in the given string.
        :rtype: bool
        """

    @staticmethod
    def containsAllIgnoreCase(toSearch: java.lang.CharSequence, *searches: java.lang.CharSequence) -> bool:
        """
        Returns true if all the given ``searches`` are contained in the given string,
        ignoring case.
        
        :param java.lang.CharSequence toSearch: the string to search
        :param jpype.JArray[java.lang.CharSequence] searches: the strings to find
        :return: true if all the given ``searches`` are contained in the given string.
        :rtype: bool
        """

    @staticmethod
    def containsAnyIgnoreCase(toSearch: java.lang.CharSequence, *searches: java.lang.CharSequence) -> bool:
        """
        Returns true if any of the given ``searches`` are contained in the given string,
        ignoring case.
        
        :param java.lang.CharSequence toSearch: the string to search
        :param jpype.JArray[java.lang.CharSequence] searches: the strings to find
        :return: true if any of the given ``searches`` are contained in the given string.
        :rtype: bool
        """

    @staticmethod
    def convertCodePointToEscapeSequence(codePoint: typing.Union[jpype.JInt, int]) -> str:
        """
        Maps known control characters to corresponding escape sequences. For example a line feed
        character would be converted to backslash '\\' character followed by an 'n' character. One
        use for this is to display strings in a manner to easily see the embedded control characters.
        
        :param jpype.JInt or int codePoint: The character to convert to escape sequence string
        :return: a new string with equivalent to escape sequence, or original character (as a string)
                if not in the control character mapping.
        :rtype: str
        """

    @staticmethod
    def convertControlCharsToEscapeSequences(str: typing.Union[java.lang.String, str]) -> str:
        """
        Replaces known control characters in a string to corresponding escape sequences. For example
        a string containing a line feed character would be converted to backslash character followed
        by an 'n' character. One use for this is to display strings in a manner to easily see the
        embedded control characters.
        
        The string that contains 'a','b','c',0x0a,'d', 0x01, 'e' would become 'a','b','c', '\', 'n',
        'd', 0x01, 'e'
        
        :param java.lang.String or str str: The string to convert control characters to escape sequences
        :return: a new string with all the control characters converted to escape sequences.
        :rtype: str
        """

    @staticmethod
    def convertEscapeSequences(str: typing.Union[java.lang.String, str]) -> str:
        """
        Replaces escaped characters in a string to corresponding control characters. For example a
        string containing a backslash character followed by a 'n' character would be replaced with a
        single line feed (0x0a) character. One use for this is to allow users to type strings in a
        text field and include control characters such as line feeds and tabs.
        
        The string that contains 'a','b','c', '\', 'n', 'd', '\', 'u', '0', '0', '0', '1', 'e' would
        become 'a','b','c',0x0a,'d', 0x01, e"
        
        :param java.lang.String or str str: The string to convert escape sequences to control characters.
        :return: a new string with escape sequences converted to control characters.
        :rtype: str
        
        .. seealso::
        
            | :obj:`.convertEscapeSequences(String string)`
        """

    @staticmethod
    @typing.overload
    def convertTabsToSpaces(str: typing.Union[java.lang.String, str]) -> str:
        """
        Convert tabs in the given string to spaces using a default tab width of 8 spaces.
        
        :param java.lang.String or str str: string containing tabs
        :return: string that has spaces for tabs
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def convertTabsToSpaces(str: typing.Union[java.lang.String, str], tabSize: typing.Union[jpype.JInt, int]) -> str:
        """
        Convert tabs in the given string to spaces.
        
        :param java.lang.String or str str: string containing tabs
        :param jpype.JInt or int tabSize: length of the tab
        :return: string that has spaces for tabs
        :rtype: str
        """

    @staticmethod
    def countOccurrences(string: typing.Union[java.lang.String, str], occur: typing.Union[jpype.JChar, int, str]) -> int:
        """
        Returns a count of how many times the 'occur' char appears in the strings.
        
        :param java.lang.String or str string: the string to look inside
        :param jpype.JChar or int or str occur: the character to look for/
        :return: a count of how many times the 'occur' char appears in the strings
        :rtype: int
        """

    @staticmethod
    def endsWithIgnoreCase(string: typing.Union[java.lang.String, str], postfix: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given string ends with ``postfix``, ignoring case.
         
        
        Note: This method is equivalent to calling:
         
         
        int startIndex = string.length() - postfix.length();
        string.regionMatches(true, startOffset, postfix, 0, postfix.length());
         
        
        :param java.lang.String or str string: the string which may end with ``postfix``
        :param java.lang.String or str postfix: the string for which to test existence
        :return: true if the given string ends with ``postfix``, ignoring case.
        :rtype: bool
        """

    @staticmethod
    def endsWithWhiteSpace(string: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def equals(s1: typing.Union[java.lang.String, str], s2: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    @staticmethod
    def extractFromDoubleQuotes(str: typing.Union[java.lang.String, str]) -> str:
        """
        If the given string is enclosed in double quotes, extract the inner text. Otherwise, return
        the given string unmodified.
        
        :param java.lang.String or str str: String to match and extract from
        :return: The inner text of a doubly-quoted string, or the original string if not
                double-quoted.
        :rtype: str
        """

    @staticmethod
    def findLastWordPosition(s: typing.Union[java.lang.String, str]) -> int:
        """
        Finds the starting position of the last word in the given string.
        
        :param java.lang.String or str s: the string to search
        :return: int the starting position of the last word, -1 if not found
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def findWord(s: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]) -> str:
        """
        Finds the word at the given index in the given string. For example, the string "The tree is
        green" and the index of 5, the result would be "tree".
        
        :param java.lang.String or str s: the string to search
        :param jpype.JInt or int index: the index into the string to "seed" the word.
        :return: String the word contained at the given index.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def findWord(s: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int], charsToAllow: jpype.JArray[jpype.JChar]) -> str:
        """
        Finds the word at the given index in the given string; if the word contains the given
        charToAllow, then allow it in the string. For example, the string "The tree* is green" and
        the index of 5, charToAllow is '*', then the result would be "tree*".
         
        
        If the search yields only whitespace, then the empty string will be returned.
        
        :param java.lang.String or str s: the string to search
        :param jpype.JInt or int index: the index into the string to "seed" the word.
        :param jpype.JArray[jpype.JChar] charsToAllow: chars that normally would be considered invalid, e.g., '*' so that the
                    word can be returned with the charToAllow
        :return: String the word contained at the given index.
        :rtype: str
        """

    @staticmethod
    def findWordLocation(s: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int], charsToAllow: jpype.JArray[jpype.JChar]) -> WordLocation:
        ...

    @staticmethod
    def fixMultipleAsterisks(value: typing.Union[java.lang.String, str]) -> str:
        """
        This method looks for all occurrences of successive asterisks (i.e., "**") and replace with a
        single asterisk, which is an equivalent usage in Ghidra. This is necessary due to some symbol
        names which cause the pattern matching process to become unusable. An example string that
        causes this problem is
        "s_CLSID\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\InprocServer3_01001400".
        
        :param java.lang.String or str value: The string to be checked.
        :return: The updated string.
        :rtype: str
        """

    @staticmethod
    def getLastWord(s: typing.Union[java.lang.String, str], separator: typing.Union[java.lang.String, str]) -> str:
        """
        Takes a path-like string and retrieves the last non-empty item. Examples:
         
        * StringUtilities.getLastWord("/This/is/my/last/word/", "/") returns word
        * StringUtilities.getLastWord("/This/is/my/last/word/", "/") returns word
        * StringUtilities.getLastWord("This.is.my.last.word", ".") returns word
        * StringUtilities.getLastWord("/This/is/my/last/word/MyFile.java", ".") returns java
        * StringUtilities.getLastWord("/This/is/my/last/word/MyFile.java", "/") returns
        MyFile.java
        
        
        :param java.lang.String or str s: the string from which to get the last word
        :param java.lang.String or str separator: the separator of words
        :return: the last word
        :rtype: str
        """

    @staticmethod
    def indentLines(s: typing.Union[java.lang.String, str], indent: typing.Union[java.lang.String, str]) -> str:
        """
        Splits the given string into lines using ``\n`` and then pads each string with the
        given pad string. Finally, the updated lines are formed into a single string.
         
        
        This is useful for constructing complicated ``toString()`` representations.
        
        :param java.lang.String or str s: the input string
        :param java.lang.String or str indent: the indent string; this will be appended as needed
        :return: the output string
        :rtype: str
        """

    @staticmethod
    def indexOfWord(text: typing.Union[java.lang.String, str], searchWord: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the index of the first whole word occurrence of the search word within the given
        text. A whole word is defined as the character before and after the occurrence must not be a
        JavaIdentifierPart.
        
        :param java.lang.String or str text: the text to be searched.
        :param java.lang.String or str searchWord: the word to search for.
        :return: the index of the first whole word occurrence of the search word within the given
                text, or -1 if not found.
        :rtype: int
        """

    @staticmethod
    def isAllBlank(*sequences: java.lang.CharSequence) -> bool:
        """
        Returns true if all the given sequences are either null or only whitespace
        
        :param jpype.JArray[java.lang.CharSequence] sequences: the sequences to check
        :return: true if all the given sequences are either null or only whitespace.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`StringUtils.isNoneBlank(CharSequence...)`
        
            | :obj:`StringUtils.isNoneEmpty(CharSequence...)`
        
            | :obj:`StringUtils.isAnyBlank(CharSequence...)`
        
            | :obj:`StringUtils.isAnyEmpty(CharSequence...)`
        """

    @staticmethod
    @typing.overload
    def isAsciiChar(c: typing.Union[jpype.JChar, int, str]) -> bool:
        """
        Returns true if the given character is within the ascii range.
        
        :param jpype.JChar or int or str c: the char to check
        :return: true if the given character is within the ascii range.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isAsciiChar(codePoint: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given code point is within the ascii range.
        
        :param jpype.JInt or int codePoint: the codePoint to check
        :return: true if the given character is within the ascii range.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isControlCharacterOrBackslash(c: typing.Union[jpype.JChar, int, str]) -> bool:
        """
        Returns true if the given character is a special character. For example a '\n' or '\\'. A
        value of 0 is not considered special for this purpose as it is handled separately because it
        has more varied use cases.
        
        :param jpype.JChar or int or str c: the character
        :return: true if the given character is a special character
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isControlCharacterOrBackslash(codePoint: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given codePoint (ie. full unicode 32bit character) is a special
        character. For example a '\n' or '\\'. A value of 0 is not considered special for this
        purpose as it is handled separately because it has more varied use cases.
        
        :param jpype.JInt or int codePoint: the codePoint (ie. character), see :meth:`String.codePointAt(int) <String.codePointAt>`
        :return: true if the given character is a special character
        :rtype: bool
        """

    @staticmethod
    def isDisplayable(c: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the character is in displayable character range
        
        :param jpype.JInt or int c: the character
        :return: true if the character is in displayable character range
        :rtype: bool
        """

    @staticmethod
    def isDoubleQuoted(str: typing.Union[java.lang.String, str]) -> bool:
        """
        Determines if a string is enclosed in double quotes (ASCII 34 (0x22))
        
        :param java.lang.String or str str: String to test for double-quote enclosure
        :return: True if the first and last characters are the double-quote character, false otherwise
        :rtype: bool
        """

    @staticmethod
    def isValidCLanguageChar(c: typing.Union[jpype.JChar, int, str]) -> bool:
        """
        Returns true if the character is OK to be contained inside C language string. That is, the
        string should not be tokenized on this char.
        
        :param jpype.JChar or int or str c: the char
        :return: boolean true if it is allows in a C string
        :rtype: bool
        """

    @staticmethod
    def isWholeWord(text: typing.Union[java.lang.String, str], startIndex: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the substring within the text string starting at startIndex and having the
        given length is a whole word. A whole word is defined as the character before and after the
        occurrence must not be a JavaIdentifierPart.
        
        :param java.lang.String or str text: the text containing the potential word.
        :param jpype.JInt or int startIndex: the start index of the potential word within the text.
        :param jpype.JInt or int length: the length of the potential word
        :return: true if the substring within the text string starting at startIndex and having the
                given length is a whole word.
        :rtype: bool
        """

    @staticmethod
    def isWordChar(c: typing.Union[jpype.JChar, int, str], charsToAllow: jpype.JArray[jpype.JChar]) -> bool:
        """
        Loosely defined as a character that we would expected to be an normal ascii content meant for
        consumption by a human. Also, provided allows chars will pass the test.
        
        :param jpype.JChar or int or str c: the char to check
        :param jpype.JArray[jpype.JChar] charsToAllow: characters that will cause this method to return true
        :return: true if it is a 'word char'
        :rtype: bool
        """

    @staticmethod
    def mergeStrings(string1: typing.Union[java.lang.String, str], string2: typing.Union[java.lang.String, str]) -> str:
        """
        Merge two strings into one. If one string contains the other, then the largest is returned.
        If both strings are null then null is returned. If both strings are empty, the empty string
        is returned. If the original two strings differ, this adds the second string to the first
        separated by a newline.
        
        :param java.lang.String or str string1: the first string
        :param java.lang.String or str string2: the second string
        :return: the merged string
        :rtype: str
        """

    @staticmethod
    def pad(source: typing.Union[java.lang.String, str], filler: typing.Union[jpype.JChar, int, str], length: typing.Union[jpype.JInt, int]) -> str:
        """
        Pads the source string to the specified length, using the filler string as the pad. If length
        is negative, left justifies the string, appending the filler; if length is positive, right
        justifies the source string.
        
        :param java.lang.String or str source: the original string to pad.
        :param jpype.JChar or int or str filler: the type of characters with which to pad
        :param jpype.JInt or int length: the length of padding to add (0 results in no changes)
        :return: the padded string
        :rtype: str
        """

    @staticmethod
    def startsWithIgnoreCase(string: typing.Union[java.lang.String, str], prefix: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given string starts with ``prefix`` ignoring case.
         
        
        Note: This method is equivalent to calling:
         
         
        string.regionMatches(true, 0, prefix, 0, prefix.length());
         
        
        :param java.lang.String or str string: the string which may contain the prefix
        :param java.lang.String or str prefix: the prefix to test against
        :return: true if the given string starts with ``prefix`` ignoring case.
        :rtype: bool
        """

    @staticmethod
    def toFixedSize(s: typing.Union[java.lang.String, str], pad: typing.Union[jpype.JChar, int, str], size: typing.Union[jpype.JInt, int]) -> str:
        """
        Enforces the given length upon the given string by trimming and then padding as necessary.
        
        :param java.lang.String or str s: the String to fix
        :param jpype.JChar or int or str pad: the pad character to use if padding is required
        :param jpype.JInt or int size: the desired size of the string
        :return: the fixed string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toLines(str: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Parses a string containing multiple lines into an array where each element in the array
        contains only a single line. The "\n" character is used as the delimiter for lines.
         
        
        This methods creates an empty string entry in the result array for initial and trailing
        separator chars, as well as for consecutive separators.
        
        :param java.lang.String or str str: the string to parse
        :return: an array of lines; an empty array if the given value is null or empty
        :rtype: jpype.JArray[java.lang.String]
        
        .. seealso::
        
            | :obj:`StringUtils.splitPreserveAllTokens(String, char)`
        """

    @staticmethod
    @typing.overload
    def toLines(s: typing.Union[java.lang.String, str], preserveTokens: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[java.lang.String]:
        """
        Parses a string containing multiple lines into an array where each element in the array
        contains only a single line. The "\n" character is used as the delimiter for lines.
        
        :param java.lang.String or str s: the string to parse
        :param jpype.JBoolean or bool preserveTokens: true signals to treat consecutive newlines as multiple lines; false
                    signals to treat consecutive newlines as a single line break
        :return: an array of lines; an empty array if the given value is null or empty
        :rtype: jpype.JArray[java.lang.String]
        """

    @staticmethod
    @typing.overload
    def toQuotedString(bytes: jpype.JArray[jpype.JByte]) -> str:
        """
        Generate a quoted string from US-ASCII character bytes assuming 1-byte chars.
         
        
        Special characters and non-printable characters will be escaped using C character escape
        conventions (e.g., \t, \n, \\uHHHH, etc.). If a character size other than 1-byte is required
        the alternate form of this method should be used.
         
        
        The result string will be single quoted (ie. "'") if the input byte array is 1 byte long,
        otherwise the result will be double-quoted ('"').
        
        :param jpype.JArray[jpype.JByte] bytes: character string bytes
        :return: escaped string for display use
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toQuotedString(bytes: jpype.JArray[jpype.JByte], charSize: typing.Union[jpype.JInt, int]) -> str:
        """
        Generate a quoted string from US-ASCII characters, where each character is charSize bytes.
         
        
        Special characters and non-printable characters will be escaped using C character escape
        conventions (e.g., \t, \n, \\uHHHH, etc.).
         
        
        The result string will be single quoted (ie. "'") if the input byte array is 1 character long
        (ie. charSize), otherwise the result will be double-quoted ('"').
        
        :param jpype.JArray[jpype.JByte] bytes: array of bytes
        :param jpype.JInt or int charSize: number of bytes per character (1, 2, 4).
        :return: escaped string for display use
        :rtype: str
        """

    @staticmethod
    def toStingJson(o: java.lang.Object) -> str:
        """
        Creates a JSON string for the given object using all of its fields. To control the fields
        that are in the result string, see :obj:`Json`.
         
         
        
        This is here as a marker to point users to the real :obj:`Json` String utility.
        
        :param java.lang.Object o: the object for which to create a string
        :return: the string
        :rtype: str
        """

    @staticmethod
    def toString(value: typing.Union[jpype.JInt, int]) -> str:
        """
        Converts an integer into a string. For example, given an integer 0x41424344, the returned
        string would be "ABCD".
        
        :param jpype.JInt or int value: the integer value
        :return: the converted string
        :rtype: str
        """

    @staticmethod
    def toStringWithIndent(o: java.lang.Object) -> str:
        ...

    @staticmethod
    def trim(original: typing.Union[java.lang.String, str], max: typing.Union[jpype.JInt, int]) -> str:
        """
        Limits the given string to the given ``max`` number of characters. If the string is
        larger than the given length, then it will be trimmed to fit that length **after adding
        ellipses**
        
         
        
        The given ``max`` value must be at least 4. This is to ensure that, at a minimum, we
        can display the ... plus one character.
        
        :param java.lang.String or str original: The string to be limited
        :param jpype.JInt or int max: The maximum number of characters to display (including ellipses, if trimmed).
        :return: the trimmed string
        :rtype: str
        :raises IllegalArgumentException: If the given ``max`` value is less than 5.
        """

    @staticmethod
    def trimMiddle(s: typing.Union[java.lang.String, str], max: typing.Union[jpype.JInt, int]) -> str:
        """
        Trims the given string the ``max`` number of characters. Ellipses will be added to
        signal that content was removed. Thus, the actual number of removed characters will be
        ``(s.length() - max) + ...`` length.
        
         
        
        If the string fits within the max, then the string will be returned.
        
         
        
        The given ``max`` value must be at least 5. This is to ensure that, at a minimum, we
        can display the ... plus one character from the front and back of the string.
        
        :param java.lang.String or str s: the string to trim
        :param jpype.JInt or int max: the max number of characters to allow.
        :return: the trimmed string
        :rtype: str
        """

    @staticmethod
    def trimTrailingNulls(s: typing.Union[java.lang.String, str]) -> str:
        ...

    @staticmethod
    def whitespaceToUnderscores(s: typing.Union[java.lang.String, str]) -> str:
        """
        Removes any whitespace from start or end of string, then replaces any non-printable
        character (< 32) or spaces (32) with an underscore.
        
        :param java.lang.String or str s: the string to adjust
        :return: a new trimmed string with underscores replacing any non-printable characters.
        :rtype: str
        """

    @staticmethod
    def wrapToWidth(str: typing.Union[java.lang.String, str], width: typing.Union[jpype.JInt, int]) -> str:
        """
        Wrap the given string at whitespace to best fit within the given line width
         
        
        If it is not possible to fit a word in the given width, it will be put on a line by itself,
        and that line will be allowed to exceed the given width.
        
        :param java.lang.String or str str: the string to wrap
        :param jpype.JInt or int width: the max width of each line, unless a single word exceeds it
        :return: The wrapped string
        :rtype: str
        """


class LongIterator(java.lang.Object):
    """
    Iterator over a set of Java-type long values.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[LongIterator]
    """
    A default implementation of LongIterator that has no values.
    """


    def hasNext(self) -> bool:
        """
        Return true if there is a next long in this iterator.
        """

    def hasPrevious(self) -> bool:
        """
        Return true if there a previous long in this iterator.
        """

    def next(self) -> int:
        """
        Get the next long value in this iterator.
        """

    def previous(self) -> int:
        """
        Get the previous long value in this iterator.
        """


class WordLocation(java.lang.Object):
    """
    A simple object that represents a word as defined by 
    :meth:`StringUtilities.findWord(String, int) <StringUtilities.findWord>`.  This class contains the position of the word
    within the original context from whence it came.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: typing.Union[java.lang.String, str], word: typing.Union[java.lang.String, str], start: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def empty(context: typing.Union[java.lang.String, str]) -> WordLocation:
        ...

    def getContext(self) -> str:
        ...

    def getStart(self) -> int:
        ...

    def getWord(self) -> str:
        ...

    def isEmpty(self) -> bool:
        ...

    @property
    def start(self) -> jpype.JInt:
        ...

    @property
    def context(self) -> java.lang.String:
        ...

    @property
    def word(self) -> java.lang.String:
        ...


class TriConsumer(java.lang.Object, typing.Generic[T, U, V]):
    """
    Patterned after :obj:`BiConsumer`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def accept(self, t: T, u: U, v: V):
        """
        Performs this operation on the given arguments.
        
        :param T t: the first input argument
        :param U u: the second input argument
        :param V v: the third input argument
        """


class Disposable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Dispose this object
        """


class InvalidNameException(ghidra.util.exception.UsrException):
    """
    Exception thrown if a name has invalid characters.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, s: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str s: detailed message explaining exception
        """


class DateUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MS_PER_SEC: typing.Final = 1000
    MS_PER_MIN: typing.Final = 60000
    MS_PER_HOUR: typing.Final = 3600000
    MS_PER_DAY: typing.Final = 86400000

    def __init__(self):
        ...

    @staticmethod
    def formatCompactDate(date: java.util.Date) -> str:
        """
        Formats the given date into a compact date string (mm/dd/yy).
        
        :param java.util.Date date: the date to format
        :return: the date string
        :rtype: str
        """

    @staticmethod
    def formatCurrentTime() -> str:
        """
        Returns the current local time zone time-of-day as simple time string.
        See h:mm.
        
        :return: current time-of-day as a string
        :rtype: str
        """

    @staticmethod
    def formatDate(date: java.util.Date) -> str:
        """
        Formats the given date into a string.   This is in contrast to
        :meth:`formatDateTimestamp(Date) <.formatDateTimestamp>`, which will also return the time portion of the date.
        
        :param java.util.Date date: the date to format
        :return: the date string
        :rtype: str
        """

    @staticmethod
    def formatDateTimestamp(date: java.util.Date) -> str:
        """
        Formats the given date into a string that contains the date and time.  This is in
        contrast to :meth:`formatDate(Date) <.formatDate>`, which only returns a date string.
        
        :param java.util.Date date: the date to format
        :return: the date and time string
        :rtype: str
        """

    @staticmethod
    def formatDuration(millis: typing.Union[jpype.JLong, int]) -> str:
        """
        Formats a millisecond duration as a English string expressing the number of
        hours, minutes and seconds in the duration
        
        :param jpype.JLong or int millis: Count of milliseconds of an elapsed duration.
        :return: String such as "5 hours, 3 mins, 22 secs".
        :rtype: str
        """

    @staticmethod
    def getBusinessDaysBetween(date1: java.util.Date, date2: java.util.Date) -> int:
        """
        Returns the **business days** between the two dates.  Returns 0 if the same date is
        passed for both parameters.  The order of the dates does not matter.
        
        :param java.util.Date date1: the first date
        :param java.util.Date date2: the second date
        :return: the number of days
        :rtype: int
        """

    @staticmethod
    def getDate(year: typing.Union[jpype.JInt, int], month: typing.Union[jpype.JInt, int], day: typing.Union[jpype.JInt, int]) -> java.util.Date:
        """
        Returns a date for the given numeric values
        
        :param jpype.JInt or int year: the year
        :param jpype.JInt or int month: the month; 0-based
        :param jpype.JInt or int day: the day of month; 1-based
        :return: the date
        :rtype: java.util.Date
        """

    @staticmethod
    def getDaysBetween(date1: java.util.Date, date2: java.util.Date) -> int:
        """
        Returns all days between the two dates.  Returns 0 if the same date is passed for both
        parameters.  The order of the dates does not matter.
        
        :param java.util.Date date1: the first date
        :param java.util.Date date2: the second date
        :return: the number of days
        :rtype: int
        """

    @staticmethod
    def getHolidays(year: typing.Union[jpype.JInt, int]) -> java.util.List[java.util.Date]:
        ...

    @staticmethod
    def getNormalizedToday() -> java.util.Date:
        ...

    @staticmethod
    @typing.overload
    def isHoliday(date: java.util.Date) -> bool:
        ...

    @staticmethod
    @typing.overload
    def isHoliday(cal: java.util.Calendar) -> bool:
        ...

    @staticmethod
    def isWeekend(cal: java.util.Calendar) -> bool:
        ...

    @staticmethod
    def normalizeDate(date: java.util.Date) -> java.util.Date:
        ...

    @staticmethod
    def toDate(ld: java.time.LocalDate) -> java.util.Date:
        """
        Converts the given LocalDate to a date
        
        :param java.time.LocalDate ld: the local date
        :return: the date
        :rtype: java.util.Date
        """

    @staticmethod
    def toLocalDate(d: java.util.Date) -> java.time.LocalDateTime:
        """
        Converts the given Data to a LocalDate
        
        :param java.util.Date d: the date
        :return: the local date
        :rtype: java.time.LocalDateTime
        """


class SignednessFormatMode(java.lang.Enum[SignednessFormatMode]):
    """
    Defines how the sign of integer-type numbers is to be interpreted for rendering.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[SignednessFormatMode]
    """
    Values to be rendered in binary, octal, or hexadecimal bases are rendered
    as unsigned; numbers rendered in decimal are rendered as signed.
    """

    UNSIGNED: typing.Final[SignednessFormatMode]
    """
    All values are rendered in their *unsigned* form
    """

    SIGNED: typing.Final[SignednessFormatMode]
    """
    All values are rendered in their *signed* form
    """


    @staticmethod
    def parse(value: typing.Union[jpype.JInt, int]) -> SignednessFormatMode:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SignednessFormatMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[SignednessFormatMode]:
        ...


@typing.type_check_only
class DropTargetDragEventWrapper(java.awt.dnd.DropTargetDragEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ev: java.awt.dnd.DropTargetDragEvent):
        ...


class CascadedDropTarget(java.awt.dnd.DropTarget):
    """
    Combines two drop targets and sends events to them in priority order.  If the first drop target
    accepts the event, then the second drop target is not accessed. 
     
    
    Either of the given drop targets can be an instance of CascadedDropTarget, effectively creating 
    a tree structure of drop targets.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comp: java.awt.Component, firstDropTarget: java.awt.dnd.DropTarget, secondDropTarget: java.awt.dnd.DropTarget):
        ...

    def getPrimaryDropTarget(self) -> java.awt.dnd.DropTarget:
        ...

    def getSecondaryDropTarget(self) -> java.awt.dnd.DropTarget:
        ...

    def removeDropTarget(self, dropTarget: java.awt.dnd.DropTarget) -> java.awt.dnd.DropTarget:
        """
        Removes the given drop target from anywhere within the tree of CascadedDropTargets.  
         
        If the given ``dropTarget`` is an immediate child of this CascadedDropTarget (CDT), then 
        the other child is returned.  Otherwise, a reference to this CDT will be returned with the 
        given ``dropTarget`` having been removed from one of this CDT's children.  This method 
        effectively removes the given ``dropTarget`` from the hierarchy and collapses the tree 
        structure as needed.
        
        :param java.awt.dnd.DropTarget dropTarget: The target to remove
        :return: the new drop target reference
        :rtype: java.awt.dnd.DropTarget
        """

    @property
    def secondaryDropTarget(self) -> java.awt.dnd.DropTarget:
        ...

    @property
    def primaryDropTarget(self) -> java.awt.dnd.DropTarget:
        ...


class TestSuiteUtilities(java.lang.Object):
    """
    A set of static utilities to facilitate JUnit testing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def createTestSuites(baseDir: jpype.protocol.SupportsPath, className: typing.Union[java.lang.String, str], pkgName: typing.Union[java.lang.String, str]):
        """
        Create the Java source file a JUnit TestSuite which 
        includes all TestCases within a package directory.
        
        :param jpype.protocol.SupportsPath baseDir: the base package directory
        :param java.lang.String or str className: the class name
        :param java.lang.String or str pkgName: the java package name
        :raises IOException:
        """

    @staticmethod
    @typing.overload
    def createTestSuites(baseDir: jpype.protocol.SupportsPath, className: typing.Union[java.lang.String, str], pkgName: typing.Union[java.lang.String, str], recurse: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Create the Java source file a JUnit TestSuite which 
        includes all TestCases within a package directory.
        
        :param jpype.protocol.SupportsPath baseDir: 
        :param java.lang.String or str className: 
        :param java.lang.String or str pkgName: 
        :param jpype.JBoolean or bool recurse:
        """

    @staticmethod
    def getClassNames(pkgName: typing.Union[java.lang.String, str], searchClass: java.lang.Class[typing.Any]) -> java.util.Iterator[java.lang.String]:
        """
        Get all class names within the named package which extend or implement the 
        specified search class.
        
        :param java.lang.String or str pkgName: package name
        :param java.lang.Class[typing.Any] searchClass: base or interface class to search for.
        """

    @staticmethod
    def getPkgTestSuite(pkgName: typing.Union[java.lang.String, str]) -> junit.framework.TestSuite:
        """
        Build JUnit test suite for the specified package only.
        
        :param java.lang.String or str pkgName: the java package name
        :return: test suite
        :rtype: junit.framework.TestSuite
        """

    @staticmethod
    def getSubPkgNames(pkgName: typing.Union[java.lang.String, str]) -> java.util.Iterator[java.lang.String]:
        """
        Get all potential package names within the named package.
        
        :param java.lang.String or str pkgName: package name
        """

    @staticmethod
    def getTestSuite(pkgName: typing.Union[java.lang.String, str]) -> junit.framework.TestSuite:
        """
        Build JUnit test suite for the specified package.
        TestSuite includes sub-TestSuites for each sub-package.
        
        :param java.lang.String or str pkgName: the java package name
        :return: test suite
        :rtype: junit.framework.TestSuite
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Command-line utilities.
         
        
        Parameter usage:
            createAllTests <baseDirPath> <className> <topPackage>
        
        :param jpype.JArray[java.lang.String] args:
        """


class BigEndianDataConverter(DataConverter):
    """
    Helper class to convert a byte array to Java primitives and primitives to a
    byte array in Big endian.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[BigEndianDataConverter]

    def __init__(self):
        """
        Don't use this constructor to create new instances of this class.  Use the static :obj:`.INSTANCE` instead.
        """


class UniversalIdGenerator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def initialize():
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @staticmethod
    def nextID() -> UniversalID:
        ...


class MonitoredInputStream(java.io.InputStream):
    """
    An InputStream which utilizes a TaskMonitor to indicate input progress and
    allows the operation to be cancelled via the TaskMonitor.  If monitor is
    cancelled any susequent read will generate a :obj:`IOCancelledException`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, in_: java.io.InputStream, monitor: ghidra.util.task.TaskMonitor):
        ...

    def available(self) -> int:
        """
        Returns the number of bytes that can be read from this input 
        stream without blocking. 
         
        
        This method
        simply performs ``in.available()`` and
        returns the result.
        
        :return: the number of bytes that can be read from the input stream
                    without blocking.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    def cleanupOnCancel(self) -> bool:
        """
        Determine if artifact cleanup is recommended when possible following cancellation
        of this input stream (i.e., :obj:`IOCancelledException` has been caught).
        
        :return: true if cleanup recommended, false if no cleanup required.
        :rtype: bool
        """

    def close(self):
        """
        Closes this input stream and releases any system resources 
        associated with the stream. 
        This
        method simply performs ``in.close()``.
        
        :raises IOException: if an I/O error occurs.
        """

    def getTaskMonitor(self) -> ghidra.util.task.TaskMonitor:
        """
        Get task monitor associated within this input stream.
        
        :return: task monitor
        :rtype: ghidra.util.task.TaskMonitor
        """

    def mark(self, readlimit: typing.Union[jpype.JInt, int]):
        """
        Marks the current position in this input stream. A subsequent 
        call to the ``reset`` method repositions this stream at 
        the last marked position so that subsequent reads re-read the same bytes.
         
        
        The ``readlimit`` argument tells this input stream to 
        allow that many bytes to be read before the mark position gets 
        invalidated. 
         
        
        This method simply performs ``in.mark(readlimit)``.
        
        :param jpype.JInt or int readlimit: the maximum limit of bytes that can be read before
                            the mark position becomes invalid.
        
        .. seealso::
        
            | :obj:`java.io.FilterInputStream.reset`
        """

    def markSupported(self) -> bool:
        """
        Tests if this input stream supports the ``mark`` 
        and ``reset`` methods. 
        This method
        simply performs ``in.markSupported()``.
        
        :return: ``true`` if this stream type supports the
                ``mark`` and ``reset`` method;
                ``false`` otherwise.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`java.io.InputStream.mark(int)`
        
            | :obj:`java.io.InputStream.reset()`
        """

    @typing.overload
    def read(self) -> int:
        """
        Reads the next byte of data from this input stream. The value 
        byte is returned as an ``int`` in the range 
        ``0`` to ``255``. If no byte is available 
        because the end of the stream has been reached, the value 
        ``-1`` is returned. This method blocks until input data 
        is available, the end of the stream is detected, or an exception 
        is thrown. 
         
        
        This method
        simply performs ``in.read()`` and returns the result.
        
        :return: the next byte of data, or ``-1`` if the end of the
                    stream is reached.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Reads up to ``byte.length`` bytes of data from this 
        input stream into an array of bytes. This method blocks until some 
        input is available. 
         
        
        This method simply performs the call
        ``read(b, 0, b.length)`` and returns
        the  result. It is important that it does
        *not* do ``in.read(b)`` instead;
        certain subclasses of  ``FilterInputStream``
        depend on the implementation strategy actually
        used.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which the data is read.
        :return: the total number of bytes read into the buffer, or
                    ``-1`` if there is no more data because the end of
                    the stream has been reached.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        
        .. seealso::
        
            | :obj:`java.io.FilterInputStream.read(byte[], int, int)`
        """

    @typing.overload
    def read(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]) -> int:
        """
        Reads up to ``len`` bytes of data from this input stream 
        into an array of bytes. This method blocks until some input is 
        available. 
         
        
        This method simply performs ``in.read(b, off, len)`` 
        and returns the result.
        
        :param jpype.JArray[jpype.JByte] b: the buffer into which the data is read.
        :param jpype.JInt or int off: the start offset of the data.
        :param jpype.JInt or int len: the maximum number of bytes read.
        :return: the total number of bytes read into the buffer, or
                    ``-1`` if there is no more data because the end of
                    the stream has been reached.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    def reset(self):
        """
        Repositions this stream to the position at the time the 
        ``mark`` method was last called on this input stream. 
         
        
        This method
        simply performs ``in.reset()``.
         
        
        Stream marks are intended to be used in
        situations where you need to read ahead a little to see what's in
        the stream. Often this is most easily done by invoking some
        general parser. If the stream is of the type handled by the
        parse, it just chugs along happily. If the stream is not of
        that type, the parser should toss an exception when it fails.
        If this happens within readlimit bytes, it allows the outer
        code to reset the stream and try another parser.
        
        :raises IOException: if the stream has not been marked or if the
                    mark has been invalidated.
        
        .. seealso::
        
            | :obj:`java.io.FilterInputStream.mark(int)`
        """

    def setCleanupOnCancel(self, enable: typing.Union[jpype.JBoolean, bool]) -> MonitoredInputStream:
        """
        Convey to byte stream consumer if cleanup of any artifacts produced is recommended, when 
        applicable, if :obj:`IOCancelledException` is thrown by this input stream.
        
        :param jpype.JBoolean or bool enable: true if cleanup recommended, false if no cleanup neccessary (default).
        :return: this instance
        :rtype: MonitoredInputStream
        """

    def setProgress(self, progress: typing.Union[jpype.JLong, int]):
        """
        Reset the current progress count to the specified value.
        
        :param jpype.JLong or int progress: current progress
        """

    def skip(self, n: typing.Union[jpype.JLong, int]) -> int:
        """
        Skips over and discards ``n`` bytes of data from the 
        input stream. The ``skip`` method may, for a variety of 
        reasons, end up skipping over some smaller number of bytes, 
        possibly ``0``. The actual number of bytes skipped is 
        returned. 
         
        
        This method
        simply performs ``in.skip(n)``.
        
        :param jpype.JLong or int n: the number of bytes to be skipped.
        :return: the actual number of bytes skipped.
        :rtype: int
        :raises IOException: if an I/O error occurs.
        """

    @property
    def taskMonitor(self) -> ghidra.util.task.TaskMonitor:
        ...


class ObjectStorage(java.lang.Object):
    """
    Methods for saving and restoring Strings and Java primitives or arrays of
    Strings and primitives. The order in which the puts are done must the
    same order in which the gets are done.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBoolean(self) -> bool:
        """
        Gets the boolean value.
        """

    def getByte(self) -> int:
        """
        Gets the byte value.
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Gets the byte array.
        """

    def getDouble(self) -> float:
        """
        Gets the double value.
        """

    def getDoubles(self) -> jpype.JArray[jpype.JDouble]:
        """
        Gets the double array.
        """

    def getFloat(self) -> float:
        """
        Gets the float value.
        """

    def getFloats(self) -> jpype.JArray[jpype.JFloat]:
        """
        Gets the float array.
        """

    def getInt(self) -> int:
        """
        Gets the int value.
        """

    def getInts(self) -> jpype.JArray[jpype.JInt]:
        """
        Gets the int array.
        """

    def getLong(self) -> int:
        """
        Gets the long value.
        """

    def getLongs(self) -> jpype.JArray[jpype.JLong]:
        """
        Gets the long array.
        """

    def getShort(self) -> int:
        """
        Gets the short value.
        """

    def getShorts(self) -> jpype.JArray[jpype.JShort]:
        """
        Gets the short array.
        """

    def getString(self) -> str:
        """
        Gets the String value.
        """

    def getStrings(self) -> jpype.JArray[java.lang.String]:
        """
        Gets the array of Strings
        """

    def putBoolean(self, value: typing.Union[jpype.JBoolean, bool]):
        """
        Store a boolean value.
        
        :param jpype.JBoolean or bool value: The value in the name,value pair.
        """

    def putByte(self, value: typing.Union[jpype.JByte, int]):
        """
        Store a byte value.
        
        :param jpype.JByte or int value: The value in the name,value pair.
        """

    def putBytes(self, value: jpype.JArray[jpype.JByte]):
        """
        Store a byte array.
        """

    def putDouble(self, value: typing.Union[jpype.JDouble, float]):
        """
        Store a double value.
        
        :param jpype.JDouble or float value: The value in the name,value pair.
        """

    def putDoubles(self, value: jpype.JArray[jpype.JDouble]):
        """
        Store a double array value.
        """

    def putFloat(self, value: typing.Union[jpype.JFloat, float]):
        """
        Store a float value.
        
        :param jpype.JFloat or float value: The value in the name,value pair.
        """

    def putFloats(self, value: jpype.JArray[jpype.JFloat]):
        """
        Store a float array.
        """

    def putInt(self, value: typing.Union[jpype.JInt, int]):
        """
        Store an integer value.
        
        :param jpype.JInt or int value: The value in the name,value pair.
        """

    def putInts(self, value: jpype.JArray[jpype.JInt]):
        """
        Store an integer array.
        """

    def putLong(self, value: typing.Union[jpype.JLong, int]):
        """
        Store a long value.
        
        :param jpype.JLong or int value: The value in the name,value pair.
        """

    def putLongs(self, value: jpype.JArray[jpype.JLong]):
        """
        Store a long array.
        """

    def putShort(self, value: typing.Union[jpype.JShort, int]):
        """
        Store a short value.
        
        :param jpype.JShort or int value: The value in the name,value pair.
        """

    def putShorts(self, value: jpype.JArray[jpype.JShort]):
        """
        Store a short array.
        """

    def putString(self, value: typing.Union[java.lang.String, str]):
        """
        Store a String value.
        
        :param java.lang.String or str value: The value in the name,value pair.
        """

    def putStrings(self, value: jpype.JArray[java.lang.String]):
        """
        Store a String[] value.
        """

    @property
    def floats(self) -> jpype.JArray[jpype.JFloat]:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def double(self) -> jpype.JDouble:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def float(self) -> jpype.JFloat:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...

    @property
    def longs(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def boolean(self) -> jpype.JBoolean:
        ...

    @property
    def strings(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def ints(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def doubles(self) -> jpype.JArray[jpype.JDouble]:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def shorts(self) -> jpype.JArray[jpype.JShort]:
        ...


class SaveablePoint(PrivateSaveable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, point: java.awt.Point):
        ...

    def getPoint(self) -> java.awt.Point:
        ...

    @property
    def point(self) -> java.awt.Point:
        ...


class ObjectStorageStreamAdapter(ObjectStorage):
    """
    Implementation for ObjectStorage to save and restore Strings and
    Java primitives using an ObjectOutputStream and ObjectInputStream,
    respectively.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, out: java.io.ObjectOutputStream):
        """
        Constructor for ObjectStorageStreamAdapter.
        
        :param java.io.ObjectOutputStream out: output stream to write to
        """

    @typing.overload
    def __init__(self, in_: java.io.ObjectInputStream):
        """
        Constructor for new ObjectStorageStreamAdapter
        
        :param java.io.ObjectInputStream in: input stream to read from
        """


class SaveableColor(PrivateSaveable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, color: java.awt.Color):
        ...

    @typing.overload
    def __init__(self):
        ...

    def getColor(self) -> java.awt.Color:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...


class NumericUtilities(java.lang.Object):

    @typing.type_check_only
    class IntegerRadixRenderer(java.lang.Object):
        """
        Provides the protocol for rendering integer-type numbers in different signed-ness modes.
        """

        class_: typing.ClassVar[java.lang.Class]

        def toString(self, number: typing.Union[jpype.JLong, int], radix: typing.Union[jpype.JInt, int]) -> str:
            """
            Format the given number in the provided radix base.
            
            :param jpype.JLong or int number: the number to render
            :param jpype.JInt or int radix: the base in which to render
            :return: a string representing the provided number in the given base
            :rtype: str
            """


    @typing.type_check_only
    class SignedIntegerRadixRenderer(NumericUtilities.IntegerRadixRenderer):
        """
        Renders provided numbers as signed values
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UnsignedIntegerRadixRenderer(NumericUtilities.IntegerRadixRenderer):
        """
        Renders provided numbers as unsigned values
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultIntegerRadixRenderer(NumericUtilities.IntegerRadixRenderer):
        """
        Renders provided numbers in a more human-friendly manner
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MAX_UNSIGNED_LONG: typing.Final[java.math.BigInteger]
    MAX_SIGNED_LONG: typing.Final[java.math.BigInteger]
    MAX_UNSIGNED_INT: typing.Final[java.math.BigInteger]
    MAX_UNSIGNED_INT32_AS_LONG: typing.Final = 4294967295

    @staticmethod
    def bigIntegerToUnsignedLong(value: java.math.BigInteger) -> int:
        ...

    @staticmethod
    @typing.overload
    def convertBytesToString(bytes: jpype.JArray[jpype.JByte]) -> str:
        """
        Convert a byte array into a hexadecimal string.
        
        :param jpype.JArray[jpype.JByte] bytes: byte array
        :return: hex string representation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def convertBytesToString(bytes: jpype.JArray[jpype.JByte], delimeter: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a byte array into a hexadecimal string.
        
        :param jpype.JArray[jpype.JByte] bytes: byte array
        :param java.lang.String or str delimeter: the text between byte strings
        :return: hex string representation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def convertBytesToString(bytes: jpype.JArray[jpype.JByte], start: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int], delimeter: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a byte array into a hexadecimal string.
        
        :param jpype.JArray[jpype.JByte] bytes: byte array
        :param jpype.JInt or int start: start index
        :param jpype.JInt or int len: number of bytes to convert
        :param java.lang.String or str delimeter: the text between byte strings
        :return: hex string representation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def convertBytesToString(bytes: java.util.Iterator[java.lang.Byte], delimiter: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a bytes into a hexadecimal string.
        
        :param java.util.Iterator[java.lang.Byte] bytes: an iterator of bytes
        :param java.lang.String or str delimiter: the text between byte strings; null is allowed
        :return: hex string representation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def convertBytesToString(bytes: collections.abc.Sequence, delimiter: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a bytes into a hexadecimal string.
        
        :param collections.abc.Sequence bytes: an iterable of bytes
        :param java.lang.String or str delimiter: the text between byte strings; null is allowed
        :return: hex string representation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def convertBytesToString(bytes: java.util.stream.Stream[java.lang.Byte], delimiter: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a bytes into a hexadecimal string.
        
        :param java.util.stream.Stream[java.lang.Byte] bytes: an stream of bytes
        :param java.lang.String or str delimiter: the text between byte strings; null is allowed
        :return: hex string representation
        :rtype: str
        """

    @staticmethod
    def convertHexStringToMaskedValue(msk: java.util.concurrent.atomic.AtomicLong, val: java.util.concurrent.atomic.AtomicLong, hex: typing.Union[java.lang.String, str], n: typing.Union[jpype.JInt, int], spaceevery: typing.Union[jpype.JInt, int], spacer: typing.Union[java.lang.String, str]):
        """
        The reverse of :meth:`convertMaskedValueToHexString(long, long, int, boolean, int, String) <.convertMaskedValueToHexString>`
        
        :param java.util.concurrent.atomic.AtomicLong msk: an object to receive the resulting mask
        :param java.util.concurrent.atomic.AtomicLong val: an object to receive the resulting value
        :param java.lang.String or str hex: the input string to parse
        :param jpype.JInt or int n: the number of nibbles to parse (they are stored right aligned in the result)
        :param jpype.JInt or int spaceevery: how many nibbles are expected between spacers
        :param java.lang.String or str spacer: the spacer
        
        .. seealso::
        
            | :obj:`.convertMaskedValueToHexString(long, long, int, boolean, int, String)`
        
            | :obj:`.convertMaskToHexString(long, int, boolean, int, String)`
        """

    @staticmethod
    def convertMaskToHexString(msk: typing.Union[jpype.JLong, int], n: typing.Union[jpype.JInt, int], truncate: typing.Union[jpype.JBoolean, bool], spaceevery: typing.Union[jpype.JInt, int], spacer: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a mask to a hexadecimal-ish string.
        
        Converts the mask in a similar way to
        :meth:`convertMaskedValueToHexString(long, long, int, boolean, int, String) <.convertMaskedValueToHexString>`.
        Philosophically, it is hexadecimal, but the only valid digits are 0 and F. Any
        partially-included nibble will be broken down into bracketed bits. Displaying masks in this
        way is convenient when shown proximal to related masked values.
        
        :param jpype.JLong or int msk: the mask
        :param jpype.JInt or int n: the number of nibbles, starting at the right
        :param jpype.JBoolean or bool truncate: true if leading Xs may be truncated
        :param jpype.JInt or int spaceevery: how many nibbles in spaced groups, 0 for no spaces
        :param java.lang.String or str spacer: the group separator, if applicable
        :return: the string representation
        :rtype: str
        
        .. seealso::
        
            | :obj:`.convertMaskedValueToHexString(long, long, int, boolean, int, String)`
        
            | :obj:`.convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)`
        """

    @staticmethod
    def convertMaskedValueToHexString(msk: typing.Union[jpype.JLong, int], val: typing.Union[jpype.JLong, int], n: typing.Union[jpype.JInt, int], truncate: typing.Union[jpype.JBoolean, bool], spaceevery: typing.Union[jpype.JInt, int], spacer: typing.Union[java.lang.String, str]) -> str:
        """
        Convert a masked value into a hexadecimal-ish string.
        
        Converts the data to hexadecimal, placing an X where a nibble is unknown. Where a nibble is
        partially defined, it is displayed as four bits in brackets []. Bits are displayed as x, or
        the defined value.
        
        For example, consider the mask 00001111:01011100, and the value 00001001:00011000. This will
        display as ``X8:[x0x1][10xx]``. To see the correlation, consider the table:
         
        +---------+----------+----------+-------+------------+------------+
        | Display |  ``X``   |  ``8``   | ``:`` | ``[x0x1]`` | ``[10xx]`` |
        +=========+==========+==========+=======+============+============+
        |Mask     |``0000``  |``1111``  |``:``  |``0101``    |``1100``    |
        +---------+----------+----------+-------+------------+------------+
        |Value    |``0000``  |``1000``  |``:``  |``0001``    |``1000``    |
        +---------+----------+----------+-------+------------+------------+
        
        
        :param jpype.JLong or int msk: the mask
        :param jpype.JLong or int val: the value
        :param jpype.JInt or int n: the number of nibbles, starting at the right. The example uses 4.
        :param jpype.JBoolean or bool truncate: true if leading Xs may be truncated. The example uses ``false``.
        :param jpype.JInt or int spaceevery: how many nibbles in spaced groups, 0 for no spaces. The example uses 2.
        :param java.lang.String or str spacer: the group separator, if applicable. The example uses ``':'``.
        :return: the string representation
        :rtype: str
        
        .. seealso::
        
            | :obj:`.convertMaskToHexString(long, int, boolean, int, String)`
        
            | :obj:`.convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)`
        """

    @staticmethod
    def convertStringToBytes(hexString: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Parse hexadecimal digits into a byte array.
        
        :param java.lang.String or str hexString: hexadecimal digits
        :return: numeric value as a byte array, or null if string contains invalid hex characters.
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def decodeBigInteger(s: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        """
        Decode a big integer in hex, binary, octal, or decimal, based on the prefix 0x, 0b, or 0.
         
         
        
        This checks for the presence of a case-insensitive prefix. 0x denotes hex, 0b denotes binary,
        0 denotes octal. If no prefix is given, decimal is assumed. A sign +/- may immediately
        precede the prefix. If no sign is given, a positive value is assumed.
        
        :param java.lang.String or str s: the string to parse
        :return: the decoded value
        :rtype: java.math.BigInteger
        """

    @staticmethod
    @typing.overload
    def formatNumber(number: typing.Union[jpype.JLong, int], radix: typing.Union[jpype.JInt, int]) -> str:
        """
        Render ``number`` in different bases using the default signedness mode.
         
        
        This invokes :meth:`formatNumber(long, int, SignednessFormatMode) <.formatNumber>` with a
        ``mode`` parameter of ``:obj:`SignednessFormatMode.DEFAULT```.
        
        :param jpype.JLong or int number: The number to represent
        :param jpype.JInt or int radix: the base in which ``number`` is represented
        :return: formatted string of the number parameter in provided radix base
        :rtype: str
        
        .. seealso::
        
            | :obj:`.formatNumber(long, int, SignednessFormatMode)`
        """

    @staticmethod
    @typing.overload
    def formatNumber(number: typing.Union[jpype.JLong, int], radix: typing.Union[jpype.JInt, int], mode: SignednessFormatMode) -> str:
        """
        Provide renderings of ``number`` in different bases:
         
        * 0 - renders number as an escaped character sequence
        * 2 - renders number as a base-2 integer
        * 8 - renders number as a base-8 integer
        * 10 - renders number as a base-10 integer
        * 16 (default) - renders number as a base-16
        integer
        
         
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        | Number | Radix | DEFAULT Mode Alias |                       *UNSIGNED* Mode Value                       | *SIGNED* Mode Value |
        +========+=======+====================+===================================================================+=====================+
        |        |       |                    |                                                                   |                     |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |100     |2      |*UNSIGNED*          |1100100b                                                           |1100100b             |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |100     |8      |*UNSIGNED*          |144o                                                               |144o                 |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |100     |10     |*SIGNED*            |100                                                                |100                  |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |100     |16     |*UNSIGNED*          |64h                                                                |64h                  |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |        |       |                    |                                                                   |                     |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-1      |2      |*UNSIGNED*          |1111111111111111111111111111111111111111111111111111111111111111b  |-1b                  |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-1      |8      |*UNSIGNED*          |1777777777777777777777o                                            |-1o                  |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-1      |10     |*SIGNED*            |18446744073709551615                                               |-1                   |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-1      |16     |*UNSIGNED*          |ffffffffffffffffh                                                  |-1h                  |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |        |       |                    |                                                                   |                     |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-100    |2      |*UNSIGNED*          |1111111111111111111111111111111111111111111111111111111110011100b  |-1100100b            |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-100    |8      |*UNSIGNED*          |1777777777777777777634o                                            |-144o                |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-100    |10     |*SIGNED*            |18446744073709551516                                               |-100                 |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        |-100    |16     |*UNSIGNED*          |ffffffffffffff9ch                                                  |-64h                 |
        +--------+-------+--------------------+-------------------------------------------------------------------+---------------------+
        
        
        :param jpype.JLong or int number: The number to represent
        :param jpype.JInt or int radix: The base in which ``number`` is represented
        :param SignednessFormatMode mode: Specifies how the number is formatted with respect to its signed-ness
        :return: number string in the given base
        :rtype: str
        """

    @staticmethod
    def getUnsignedAlignedValue(unsignedValue: typing.Union[jpype.JLong, int], alignment: typing.Union[jpype.JLong, int]) -> int:
        """
        Get an unsigned aligned value corresponding to the specified unsigned value which will be
        greater than or equal the specified value.
        
        :param jpype.JLong or int unsignedValue: value to be aligned
        :param jpype.JLong or int alignment: alignment
        :return: aligned value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def isFloatingPointType(number: java.lang.Number) -> bool:
        """
        Determine if the provided Number is a floating-point type -- Float or Double.
        
        :param java.lang.Number number: the object to check for for floating-point-type
        :return: true if the provided number is a floating-point-type, false otherwise
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isFloatingPointType(numClass: java.lang.Class[typing.Any]) -> bool:
        """
        Determine if the provided Number class is a floating-point type.
        
        :param java.lang.Class[typing.Any] numClass: Class of an object
        :return: true if the class parameter is a floating-point type, false otherwise
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isIntegerType(number: java.lang.Number) -> bool:
        """
        Determine if the provided Number is an integer type -- Byte, Short, Integer, or Long.
        
        :param java.lang.Number number: the object to check for for integer-type
        :return: true if the provided number is an integer-type, false otherwise
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isIntegerType(numClass: java.lang.Class[typing.Any]) -> bool:
        """
        Determine if the provided Number class is an integer type.
        
        :param java.lang.Class[typing.Any] numClass: Class of an object
        :return: true if the class parameter is a integer type, false otherwise
        :rtype: bool
        """

    @staticmethod
    @deprecated("use parseHexLong(String) instead")
    def parseHexBigInteger(s: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        """
        Parses the given hex string as a :obj:`BigInteger` value.
         
        
        Note: The string is treated as hex regardless of whether or not it contains the ``0x``
        prefix.
        
        :param java.lang.String or str s: the string to parse
        :return: the parsed :obj:`BigInteger` value
        :rtype: java.math.BigInteger
        :raises java.lang.NumberFormatException: if the string does not represent a valid value
        
        .. deprecated::
        
        use :meth:`parseHexLong(String) <.parseHexLong>` instead
        """

    @staticmethod
    def parseHexLong(s: typing.Union[java.lang.String, str]) -> int:
        """
        Parses the given hex string as a ``long`` value.
         
        
        Note: The string is treated as hex regardless of whether or not it contains the ``0x``
        prefix.
        
        :param java.lang.String or str s: the string to parse
        :return: the parsed ``long`` value
        :rtype: int
        :raises java.lang.NumberFormatException: if the string does not represent a valid value
        """

    @staticmethod
    @typing.overload
    def parseInt(s: typing.Union[java.lang.String, str]) -> int:
        """
        Parses the given decimal/hex string as an ``int`` value. This method allows values with
        the top bit set to be implicitly parsed as negative values.
        
        :param java.lang.String or str s: the string to parse
        :return: the parsed ``int`` value
        :rtype: int
        :raises java.lang.NumberFormatException: if the string does not represent a valid ``int`` value
        """

    @staticmethod
    @typing.overload
    def parseInt(s: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Parses the given decimal/hex string as an ``int`` value. This method allows values with
        the top bit set to be implicitly parsed as negative values.
        
        :param java.lang.String or str s: the string to parse
        :param jpype.JInt or int defaultValue: the default value to return if the string does not represent a valid
        ``int`` value
        :return: the parsed ``int`` value or the ``defaultValue`` if the string does not 
        represent a valid ``int`` value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def parseLong(s: typing.Union[java.lang.String, str]) -> int:
        """
        Parses the given decimal/hex string as an ``long`` value. This method allows values with
        the top bit set to be implicitly parsed as negative values.
        
        :param java.lang.String or str s: the string to parse
        :return: the parsed ``long`` value
        :rtype: int
        :raises java.lang.NumberFormatException: if the string does not represent a valid ``long`` value
        """

    @staticmethod
    @typing.overload
    def parseLong(s: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Parses the given decimal/hex string as an ``long`` value. This method allows values with
        the top bit set to be implicitly parsed as negative values.
        
        :param java.lang.String or str s: the string to parse
        :param jpype.JLong or int defaultValue: the default value to return if the string does not represent a valid
        ``long`` value
        :return: the parsed ``long`` value or the ``defaultValue`` if the string does not
        represent a valid ``long`` value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    @deprecated("use parseLong(String) instead")
    def parseNumber(numStr: typing.Union[java.lang.String, str]) -> int:
        """
        Parses the given string as a numeric value, detecting whether or not it begins with a hex
        prefix, and if not, parses as a long int value.
        
        :param java.lang.String or str numStr: the number string
        :return: the long value or 0
        :rtype: int
        
        .. deprecated::
        
        use :meth:`parseLong(String) <.parseLong>` instead
        """

    @staticmethod
    @typing.overload
    @deprecated("use parseLong(String, long) instead")
    def parseNumber(s: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.Long, int]) -> int:
        """
        Parses the given string as a numeric value, detecting whether or not it begins with a hex
        prefix, and if not, parses as a long int value.
        
        :param java.lang.String or str s: the string to parse
        :param java.lang.Long or int defaultValue: the default value to use if the string cannot be parsed
        :return: the long value
        :rtype: int
        
        .. deprecated::
        
        use :meth:`parseLong(String, long) <.parseLong>` instead
        """

    @staticmethod
    @typing.overload
    def toHexString(value: typing.Union[jpype.JLong, int]) -> str:
        """
        returns the value of the specified long as hexadecimal, prefixing with the 
        :obj:`.HEX_PREFIX_x` string.
        
        :param jpype.JLong or int value: the long value to convert
        :return: the string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toHexString(value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> str:
        """
        returns the value of the specified long as hexadecimal, prefixing with the 
        :obj:`.HEX_PREFIX_x` string.
        
        :param jpype.JLong or int value: the long value to convert
        :param jpype.JInt or int size: number of bytes to be represented
        :return: the string
        :rtype: str
        """

    @staticmethod
    def toSignedHexString(value: typing.Union[jpype.JLong, int]) -> str:
        """
        returns the value of the specified long as signed hexadecimal, prefixing with the
        :obj:`.HEX_PREFIX_x`  string.
        
        :param jpype.JLong or int value: the long value to convert
        :return: the string
        :rtype: str
        """

    @staticmethod
    def toString(b: typing.Union[jpype.JByte, int]) -> str:
        """
        Convert the given byte into a two character String, padding with a leading 0 if needed.
        
        :param jpype.JByte or int b: the byte
        :return: the byte string
        :rtype: str
        """

    @staticmethod
    def unsignedLongToBigInteger(value: typing.Union[jpype.JLong, int]) -> java.math.BigInteger:
        """
        Converts a **unsigned** long value, which is currently stored in a java
        **signed** long, into a :obj:`BigInteger`.
         
        
        In other words, the full 64 bits of the primitive java **signed** long is being
        used to store an **unsigned** value. This method converts this into a positive
        BigInteger value.
        
        :param jpype.JLong or int value: java **unsigned** long value stuffed into a java
                    **signed** long
        :return: new :obj:`BigInteger` with the positive value of the unsigned long value
        :rtype: java.math.BigInteger
        """

    @staticmethod
    def unsignedLongToDouble(val: typing.Union[jpype.JLong, int]) -> float:
        """
        Convert a long, treated as unsigned, to a double
        
        :param jpype.JLong or int val: the long to treat as unsigned and convert
        :return: the double
        :rtype: float
        """


class ReversedListIterator(java.util.ListIterator[E], typing.Generic[E]):
    """
    Wraps a :obj:`ListIterator` so that the operations are reversed.
     
    NOTE: you must obtain an iterator that is already at its end. E.g., if you wish to traverse a
    list in reverse, you would use
    ``new ReversedListIterator<>(list.listIterator(list.size()))``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it: java.util.ListIterator[E]):
        ...


class LittleEndianDataConverter(DataConverter):
    """
    Helper class to convert a byte array to a Java primitive in Little endian
    order, and to convert a primitive to a byte array.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[LittleEndianDataConverter]

    def __init__(self):
        """
        Don't use this constructor to create new instances of this class.  Use the static :obj:`.INSTANCE` instead
        or :meth:`DataConverter.getInstance(boolean) <DataConverter.getInstance>`
        """


class DataConverter(java.io.Serializable):
    """
    Stateless helper classes with static singleton instances that contain methods to convert
    Java numeric types to and from their raw form in a byte array.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getBigInteger(self, b: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Get the value from the given byte array using the specified size.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int size: number of bytes to use from array at offset 0
        :param jpype.JBoolean or bool signed: boolean flag indicating the value is signed
        :return: :obj:`BigInteger` with value
        :rtype: java.math.BigInteger
        :raises IndexOutOfBoundsException: if byte array size is
        less than size
        """

    @typing.overload
    def getBigInteger(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Get the value from the given byte array using the specified size.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int size: number of bytes to use from array
        :param jpype.JInt or int offset: offset into byte array for getting the long
        :param jpype.JBoolean or bool signed: boolean flag indicating the value is signed
        :return: :obj:`BigInteger` with value
        :rtype: java.math.BigInteger
        :raises IndexOutOfBoundsException: if byte array size is
        less than offset+size
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JShort, int]) -> jpype.JArray[jpype.JByte]:
        """
        Converts the short value to an array of bytes.
        
        :param jpype.JShort or int value: short value to be converted
        :return: array of bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Converts the int value to an array of bytes.
        
        :param jpype.JInt or int value: int value to be converted
        :return: array of bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JByte]:
        """
        Converts the long value to an array of bytes.
        
        :param jpype.JLong or int value: long value to be converted
        :return: array of bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def getBytes(self, value: java.math.BigInteger, size: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Converts the value to an array of bytes.
        
        :param java.math.BigInteger value: value to be converted
        :param jpype.JInt or int size: value size in bytes
        :return: array of bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JShort, int], b: jpype.JArray[jpype.JByte]):
        """
        Converts the given value to bytes.
        See :meth:`putShort(byte[], short) <.putShort>`
        
        :param jpype.JShort or int value: value to convert to bytes
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :raises IndexOutOfBoundsException: if b.length is not at least
        2.
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JShort, int], b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Converts the given value to bytes.
         
        
        See :meth:`putShort(byte[], int, short) <.putShort>`
        
        :param jpype.JShort or int value: value to convert to bytes
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :param jpype.JInt or int offset: offset into byte array to put the bytes
        :raises IndexOutOfBoundsException: if (offset+2)>b.length
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JInt, int], b: jpype.JArray[jpype.JByte]):
        """
        Converts the given value to bytes.
         
        
        See :meth:`putInt(byte[], int) <.putInt>`
        
        :param jpype.JInt or int value: value to convert to bytes
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :raises IndexOutOfBoundsException: if b.length is not at least
        4.
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JInt, int], b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Converts the given value to bytes.
         
        
        See :meth:`putInt(byte[], int) <.putInt>`
        
        :param jpype.JInt or int value: value to convert to bytes
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :param jpype.JInt or int offset: offset into byte array to put the bytes
        :raises IndexOutOfBoundsException: if (offset+4)>b.length
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte]):
        """
        Converts the given value to bytes.
         
        
        See :meth:`putLong(byte[], long) <.putLong>`
        
        :param jpype.JLong or int value: value to convert to bytes
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :raises IndexOutOfBoundsException: if b.length is not at least
        8.
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JLong, int], b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Converts the given value to bytes.
         
        
        See :meth:`putLong(byte[], long) <.putLong>`
        
        :param jpype.JLong or int value: value to convert to bytes
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :param jpype.JInt or int offset: offset into byte array to put the bytes
        :raises IndexOutOfBoundsException: if (offset+8)>b.length
        """

    @typing.overload
    def getBytes(self, value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Converts the given value to bytes using the number of least significant bytes
        specified by size.
         
        
        See :meth:`putValue(long, int, byte[], int) <.putValue>`
        
        :param jpype.JLong or int value: value to convert to bytes
        :param jpype.JInt or int size: number of least significant bytes of value to be written to the byte array
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :param jpype.JInt or int offset: offset into byte array to put the bytes
        :raises IndexOutOfBoundsException: if (offset+size)>b.length
        """

    @typing.overload
    def getBytes(self, value: java.math.BigInteger, size: typing.Union[jpype.JInt, int], b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Converts the given value to bytes using the number of least significant bytes
        specified by size.
         
        
        See :meth:`putBigInteger(byte[], int, BigInteger) <.putBigInteger>`
        
        :param java.math.BigInteger value: value to convert to bytes
        :param jpype.JInt or int size: number of least significant bytes of value to be written to the byte array
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :param jpype.JInt or int offset: offset into byte array to put the bytes
        :raises IndexOutOfBoundsException: if (offset+size)>b.length.
        """

    @staticmethod
    def getInstance(isBigEndian: typing.Union[jpype.JBoolean, bool]) -> DataConverter:
        """
        Returns the correct DataConverter static instance for the requested endian-ness.
        
        :param jpype.JBoolean or bool isBigEndian: boolean flag, true means big endian
        :return: static DataConverter instance
        :rtype: DataConverter
        """

    @typing.overload
    def getInt(self, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Get the int value from the given byte array.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :return: signed int value from the beginning of the specified array
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than 4
        """

    @typing.overload
    def getInt(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the int value from the given byte array.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int offset: offset into byte array for getting the int
        :return: signed int value
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than offset+4
        """

    @typing.overload
    def getLong(self, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Get the long value from the given byte array.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :return: signed long value from the beginning of the specified array
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than 8
        """

    @typing.overload
    def getLong(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the long value from the given byte array.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int offset: offset into byte array for getting the long
        :return: signed long value
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than offset+8
        """

    @typing.overload
    def getShort(self, b: jpype.JArray[jpype.JByte]) -> int:
        """
        Get the short value from the given byte array.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :return: signed short value from the beginning of the specified array
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than 2.
        """

    @typing.overload
    def getShort(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the short value from the given byte array.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int offset: offset into byte array for getting the short
        :return: signed short value
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than offset+2
        """

    @typing.overload
    def getSignedValue(self, b: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the **signed** value from the given byte array using the specified 
        integer size, returned as a long.
         
        
        Values with a size less than sizeof(long) will have their sign bit
        extended.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int size: number of bytes (1 - 8) to use from array at offset 0
        :return: signed value from the beginning of the specified array
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than specified size
        """

    @typing.overload
    def getSignedValue(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the **signed** value from the given byte array using the specified 
        integer size, returned as a long.
         
        
        Values with a size less than sizeof(long) will have their sign bit
        extended.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int size: number of bytes (1 - 8) to use from array
        :param jpype.JInt or int offset: offset into byte array for getting the long
        :return: signed value
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is
        less than offset+size or size is greater than 8 (sizeof long)
        """

    @typing.overload
    def getValue(self, b: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the **unsigned** value from the given byte array using the specified 
        integer size, returned as a long.
         
        
        Values with a size less than sizeof(long) will **not** have their sign bit
        extended and therefore will appear as an 'unsigned' value.
         
        
        Casting the 'unsigned' long value to the correctly sized smaller 
        java primitive will cause the value to appear as a signed value.
         
         
        Values of size 8 (ie. longs) will be signed.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int size: number of bytes (1 - 8) to use from array at offset 0
        :return: unsigned value from the beginning of the specified array
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is less than specified size
        """

    @typing.overload
    def getValue(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the **unsigned** value from the given byte array using the specified 
        integer size, returned as a long.
         
        
        Values with a size less than sizeof(long) will **not** have their sign bit
        extended and therefore will appear as an 'unsigned' value.
         
        
        Casting the 'unsigned' long value to the correctly sized smaller 
        java primitive will cause the value to appear as a signed value. 
         
        
        Values of size 8 (ie. longs) will be signed.
        
        :param jpype.JArray[jpype.JByte] b: array containing bytes
        :param jpype.JInt or int size: number of bytes (1 - 8) to use from array
        :param jpype.JInt or int offset: offset into byte array for getting the long
        :return: unsigned value
        :rtype: int
        :raises IndexOutOfBoundsException: if byte array size is
        less than offset+size or size is greater than 8 (sizeof long)
        """

    def isBigEndian(self) -> bool:
        """
        Returns the endianness of this DataConverter instance.
        
        :return: boolean flag, true means big-endian
        :rtype: bool
        """

    @typing.overload
    def putBigInteger(self, b: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], value: java.math.BigInteger):
        """
        Writes a value of specified size into the byte array at the given offset.
         
        
        See :meth:`getBytes(BigInteger, int, byte[], int) <.getBytes>`
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes at offset 0
        :param jpype.JInt or int size: number of bytes to be written
        :param java.math.BigInteger value: BigInteger value to convert
        :raises IndexOutOfBoundsException: if byte array is less than specified size
        """

    @typing.overload
    def putBigInteger(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], value: java.math.BigInteger):
        """
        Writes a value of specified size into the byte array at the given offset
         
        
        See :meth:`getBytes(BigInteger, int, byte[], int) <.getBytes>`
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JInt or int offset: the offset into the byte array to store the value
        :param jpype.JInt or int size: number of bytes to be written
        :param java.math.BigInteger value: BigInteger value to convert
        :raises IndexOutOfBoundsException: if (offset+size)>b.length
        """

    @typing.overload
    def putInt(self, b: jpype.JArray[jpype.JByte], value: typing.Union[jpype.JInt, int]):
        """
        Writes a int value into a byte array.
         
        
        See :meth:`getBytes(int, byte[]) <.getBytes>`
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JInt or int value: the int value
        :raises IndexOutOfBoundsException: if byte array is too small to hold the value
        """

    @typing.overload
    def putInt(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Writes a int value into the byte array at the given offset.
         
        
        See :meth:`getBytes(int, byte[], int) <.getBytes>`
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JInt or int offset: the offset into the byte array to store the value
        :param jpype.JInt or int value: the int value
        :raises IndexOutOfBoundsException: if offset is too large or byte array
        is too small to hold the value
        """

    @typing.overload
    def putLong(self, b: jpype.JArray[jpype.JByte], value: typing.Union[jpype.JLong, int]):
        """
        Writes a long value into a byte array.
         
        
        See :meth:`getBytes(long, byte[]) <.getBytes>`
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JLong or int value: the long value
        :raises IndexOutOfBoundsException: if byte array is too small to hold the value
        """

    @typing.overload
    def putLong(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Writes a long value into the byte array at the given offset
         
        
        See :meth:`getBytes(long, byte[], int) <.getBytes>`
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JInt or int offset: the offset into the byte array to store the value
        :param jpype.JLong or int value: the long value
        :raises IndexOutOfBoundsException: if offset is too large or byte array
        is too small to hold the value
        """

    @typing.overload
    def putShort(self, b: jpype.JArray[jpype.JByte], value: typing.Union[jpype.JShort, int]):
        """
        Writes a short value into a byte array.
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JShort or int value: the short value
        :raises IndexOutOfBoundsException: if byte array is too small to hold the value
        """

    @typing.overload
    def putShort(self, b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JShort, int]):
        """
        Writes a short value into the byte array at the given offset
        
        :param jpype.JArray[jpype.JByte] b: array to contain the bytes
        :param jpype.JInt or int offset: the offset into the byte array to store the value
        :param jpype.JShort or int value: the short value
        :raises IndexOutOfBoundsException: if offset is too large or byte array
        is too small to hold the value
        """

    def putValue(self, value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], b: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        """
        Converts the given value to bytes using the number of least significant bytes
        specified by size.
        
        :param jpype.JLong or int value: value to convert to bytes
        :param jpype.JInt or int size: number of least significant bytes of value to be written to the byte array
        :param jpype.JArray[jpype.JByte] b: byte array to store bytes
        :param jpype.JInt or int offset: offset into byte array to put the bytes
        :raises IndexOutOfBoundsException: if (offset+size)>b.length
        """

    @staticmethod
    def swapBytes(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Swap the least-significant bytes (based upon size)
        
        :param jpype.JLong or int val: value whose bytes are to be swapped
        :param jpype.JInt or int size: number of least significant bytes to be swapped
        :return: value with bytes swapped (any high-order bytes beyond size will be 0)
        :rtype: int
        """

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...


class StatusListener(java.lang.Object):
    """
    ``StatusListener`` is a general purpose status listener
    responsible for displaying and/or recording status messages
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearStatusText(self):
        """
        Clear the current status - same as setStatusText("")
        without being recorded
        """

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str]):
        """
        Set the current status as type INFO
        
        :param java.lang.String or str text: status text
        """

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str], type: MessageType):
        """
        Set the current status as the specified type
        
        :param java.lang.String or str text: status text
        :param MessageType type: status type
        """

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str], type: MessageType, alert: typing.Union[jpype.JBoolean, bool]):
        """
        Set the current status as the specified type
        
        :param java.lang.String or str text: status text
        :param MessageType type: status type
        :param jpype.JBoolean or bool alert: true to grab the user's attention
        """


class ReadOnlyException(java.io.IOException):
    """
    Exception thrown if a method attemps to change an object that is marked as read-only.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: detailed message
        """


class Saveable(java.lang.Object):
    """
    Save and restore elements that are compatible with ObjectStorage objects.
     
    
     
    **Important**: Any class implementing this interface that
    may have its class path saved to the data base (i.e. user defined properties)
    should create a map in the ``ClassTranslator`` when it is moved 
    or renamed between versions of Ghidra. It should also implement ``ExtensionPoint``.
     
    
    For example, any class that implements the ``Saveable`` interface 
    can potentially be saved as a property in the program. If used as a program 
    property the class name gets saved to a database field in the property manager. 
    If the class gets moved or renamed, the property manager won't be able to 
    instantiate it. The ``ClassTranslator`` allows the saveable class 
    to indicate its old path name (that was stored in the database) and its
    current path name (the actual location of the class it needs to instantiate 
    for the property). 
     
    The saveable class should call 
     
    ``    ClassTranslator.put(oldClassPath, newClassPath);``
     
    in its static initializer.
     
    The property manager would then call 
     
    ``    String newPathName = ClassTranslator.get(oldPathName);`` 
     
    when it can't find the class for the old path name. 
    If the new path name isn't null the property manager can use it to get the class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getObjectStorageFields(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        """
        Returns the field classes, in Java types, in the same order as used :obj:`.save` and
        :obj:`.restore`. 
         
        
        For example, if the save method calls ``objStorage.putInt()`` and then
        ``objStorage.putFloat()``, then this method must return 
        ``Class[]{ Integer.class, Float.class }``.
        
        :return: 
        :rtype: jpype.JArray[java.lang.Class[typing.Any]]
        """

    def getSchemaVersion(self) -> int:
        """
        Get the storage schema version.  Any time there is a software release
        in which the implementing class has changed the data structure used 
        for the save and restore methods, the schema version must be incremented.
        NOTE: While this could be a static method, the Saveable interface is unable to 
        define such methods.
        
        :return: storage schema version.
        :rtype: int
        """

    def isPrivate(self) -> bool:
        """
        Returns true if this saveable should not have it's changes broadcast.
        
        :return: true if this saveable should not have it's changes broadcast.
        :rtype: bool
        """

    def isUpgradeable(self, oldSchemaVersion: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determine if the implementation supports an storage upgrade of the specified
        oldSchemaVersion to the current schema version.
        
        :param jpype.JInt or int oldSchemaVersion: 
        :return: true if upgrading is supported for the older schema version.
        :rtype: bool
        """

    def restore(self, objStorage: ObjectStorage):
        """
        Restore from the given ObjectStorage.
        
        :param ObjectStorage objStorage: Object that can handle Java primitives, Strings, and
        arrays of primitives and Strings
        TODO: document how errors should be handled (i.e, exception, null return)
        """

    def save(self, objStorage: ObjectStorage):
        """
        Save to the given ObjectStorage.
        
        :param ObjectStorage objStorage: Object that can handle Java primitives, Strings, and
        arrays of primitives and Strings
        """

    def upgrade(self, oldObjStorage: ObjectStorage, oldSchemaVersion: typing.Union[jpype.JInt, int], currentObjStorage: ObjectStorage) -> bool:
        """
        Upgrade an older stored object to the current storage schema.
        
        :param ObjectStorage oldObjStorage: the old stored object
        :param jpype.JInt or int oldSchemaVersion: storage schema version number for the old object
        :param ObjectStorage currentObjStorage: new object for storage in the current schema
        :return: true if data was upgraded to the currentObjStorage successfully.
        :rtype: bool
        """

    @property
    def private(self) -> jpype.JBoolean:
        ...

    @property
    def schemaVersion(self) -> jpype.JInt:
        ...

    @property
    def upgradeable(self) -> jpype.JBoolean:
        ...

    @property
    def objectStorageFields(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        ...


class MathUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def clamp(value: typing.Union[jpype.JInt, int], min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]) -> int:
        """
        Ensures that the given value is within the given range.
        
        :param jpype.JInt or int value: the value to check
        :param jpype.JInt or int min: the minimum value allowed
        :param jpype.JInt or int max: the maximum value allowed
        :return: the clamped value
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def cmax(a: C, b: C, comp: java.util.Comparator[C]) -> C:
        ...

    @staticmethod
    @typing.overload
    def cmax(a: C, b: C) -> C:
        ...

    @staticmethod
    @typing.overload
    def cmin(a: C, b: C, comp: java.util.Comparator[C]) -> C:
        ...

    @staticmethod
    @typing.overload
    def cmin(a: C, b: C) -> C:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @staticmethod
    def unsignedDivide(numerator: typing.Union[jpype.JLong, int], denominator: typing.Union[jpype.JLong, int]) -> int:
        """
        Perform unsigned division. Provides proper handling of all 64-bit unsigned values.
        
        :param jpype.JLong or int numerator: unsigned numerator
        :param jpype.JLong or int denominator: positive divisor
        :return: result of unsigned division
        :rtype: int
        :raises IllegalArgumentException: if negative denominator is specified
        """

    @staticmethod
    @typing.overload
    def unsignedMax(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        """
        Compute the maximum, treating the inputs as unsigned
        
        :param jpype.JLong or int a: the first value to consider
        :param jpype.JLong or int b: the second value to consider
        :return: the maximum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMax(a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int]) -> int:
        """
        Compute the maximum, treating the inputs as unsigned
        
        :param jpype.JInt or int a: the first value to consider
        :param jpype.JInt or int b: the second value to consider
        :return: the maximum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMax(a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JLong, int]) -> int:
        """
        Compute the maximum, treating the inputs as unsigned
         
         
        
        This method is overloaded to prevent accidental signed-extension on one of the inputs. This
        method will correctly zero-extend the ``int`` parameter before performing any comparison.
        
        :param jpype.JInt or int a: the first value to consider
        :param jpype.JLong or int b: the second value to consider
        :return: the maximum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMax(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JInt, int]) -> int:
        """
        Compute the maximum, treating the inputs as unsigned
         
         
        
        This method is overloaded to prevent accidental signed-extension on one of the inputs. This
        method will correctly zero-extend the ``int`` parameter before performing any comparison.
        
        :param jpype.JLong or int a: the first value to consider
        :param jpype.JInt or int b: the second value to consider
        :return: the maximum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMin(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        """
        Compute the minimum, treating the inputs as unsigned
        
        :param jpype.JLong or int a: the first value to consider
        :param jpype.JLong or int b: the second value to consider
        :return: the minimum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMin(a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JInt, int]) -> int:
        """
        Compute the minimum, treating the inputs as unsigned
        
        :param jpype.JInt or int a: the first value to consider
        :param jpype.JInt or int b: the second value to consider
        :return: the minimum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMin(a: typing.Union[jpype.JInt, int], b: typing.Union[jpype.JLong, int]) -> int:
        """
        Compute the minimum, treating the inputs as unsigned
         
         
        
        This method is overloaded to prevent accidental signed-extension on one of the inputs. This
        method will correctly zero-extend the ``int`` parameter before performing any comparison.
        Also note the return type is ``int``, since b would never be selected if it overflows an
        ``int``.
        
        :param jpype.JInt or int a: the first value to consider
        :param jpype.JLong or int b: the second value to consider
        :return: the minimum
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def unsignedMin(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JInt, int]) -> int:
        """
        Compute the minimum, treating the inputs as unsigned
         
         
        
        This method is overloaded to prevent accidental signed-extension on one of the inputs. This
        method will correctly zero-extend the ``int`` parameter before performing any comparison.
        Also note the return type is ``int``, since b would never be selected if it overflows an
        ``int``.
        
        :param jpype.JLong or int a: the first value to consider
        :param jpype.JInt or int b: the second value to consider
        :return: the minimum
        :rtype: int
        """

    @staticmethod
    def unsignedModulo(numerator: typing.Union[jpype.JLong, int], denominator: typing.Union[jpype.JLong, int]) -> int:
        """
        Perform unsigned modulo. Provides proper handling of all 64-bit unsigned values.
        
        :param jpype.JLong or int numerator: unsigned numerator
        :param jpype.JLong or int denominator: positive divisor
        :return: result of unsigned modulo (i.e., remainder)
        :rtype: int
        :raises IllegalArgumentException: if negative denominator is specified
        """


class UserSearchUtils(java.lang.Object):
    """
    This class converts user inputted strings and creates :obj:`Pattern`s from them
    that can be used to create :obj:`Matcher` objects.  Some methods create patterns that
    are meant to be used with :meth:`Matcher.matches() <Matcher.matches>`, while others create patterns
    meant to be used with :meth:`Matcher.find() <Matcher.find>`.  Please see each method javadoc for clarification.
     
    
    Note: methods in the class will escape regex characters, which means that normal regex
    queries will not work, but will be instead interpreted as literal string searches.
    """

    class_: typing.ClassVar[java.lang.Class]
    STAR: typing.Final = "*"
    """
    Wildcard string for matching 0 or more characters.
    """

    NON_GLOB_BACKSLASH_PATTERN: typing.Final[java.util.regex.Pattern]
    """
    A pattern that will find all '\' chars that are not followed by '*', '?' or another '\'
    """


    def __init__(self):
        ...

    @staticmethod
    def convertUserInputToRegex(input: typing.Union[java.lang.String, str], allowGlobbing: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Convert user entered text into a regular expression, escaping regex characters, 
        optionally turning globbing characters into valid regex syntax.
        
        :param java.lang.String or str input: the user entered text to be converted to a regular expression.
        :param jpype.JBoolean or bool allowGlobbing: if true, '*' and '?' will be converted to equivalent regular expression
        syntax for wildcard matching, otherwise they will be treated as literal characters to be 
        part of the search text.
        :return: a converted text string suitable for use in a regular expression.
        :rtype: str
        """

    @staticmethod
    def createContainsPattern(input: typing.Union[java.lang.String, str], allowGlobbing: typing.Union[jpype.JBoolean, bool], options: typing.Union[jpype.JInt, int]) -> java.util.regex.Pattern:
        """
        Creates a regular expression Pattern that will **match**
        all strings that **contain** the given input string.
         
        
        This method should only be used with :meth:`Matcher.matches() <Matcher.matches>`.
        
        :param java.lang.String or str input: the string that you want to your matched strings to contain.
        :param jpype.JBoolean or bool allowGlobbing: if true, globing characters (* and ?) will converted to regex wildcard patterns;
                otherwise, they will be escaped and searched as literals.
        :param jpype.JInt or int options: any :obj:`Pattern` options desired.  For example, you can pass
                    :obj:`Pattern.CASE_INSENSITIVE` to get case insensitivity.
        :return: a regular expression Pattern that will **match**
        all strings that contain the given input string.
        :rtype: java.util.regex.Pattern
        """

    @staticmethod
    def createEndsWithPattern(input: typing.Union[java.lang.String, str], allowGlobbing: typing.Union[jpype.JBoolean, bool], options: typing.Union[jpype.JInt, int]) -> java.util.regex.Pattern:
        """
        Creates a regular expression Pattern that will **match**
        all strings that **end with** the given input string.
         
        
        This method should only be used with :meth:`Matcher.matches() <Matcher.matches>`.
         
        
        The returned regular expression Pattern should be used
        with the "matches" method on a Matcher.  (As opposed to "find").
        
        :param java.lang.String or str input: the string that you want to your matched strings to end with.
        :param jpype.JBoolean or bool allowGlobbing: if true, globing characters (* and ?) will converted to regex wildcard patterns;
                otherwise, they will be escaped and searched as literals.
        :param jpype.JInt or int options: any :obj:`Pattern` options desired.  For example, you can pass
                    :obj:`Pattern.CASE_INSENSITIVE` to get case insensitivity.
        :return: a regular expression Pattern that will **match**
                        all strings that end with the given input string.
        :rtype: java.util.regex.Pattern
        """

    @staticmethod
    def createLiteralSearchPattern(text: typing.Union[java.lang.String, str]) -> java.util.regex.Pattern:
        """
        Generate a compiled representation of a regular expression, ignoring regex special
        characters  . The resulting pattern will match the literal text string.
         
        
        This method can be used with :meth:`Matcher.matches() <Matcher.matches>` or :meth:`Matcher.find() <Matcher.find>`.
         
        
        This method will **not** turn globbing characters into regex characters.
        If you need that, then see the other methods of this class.
        
        :param java.lang.String or str text: search string
        :return: Pattern the compiled regular expression
        :rtype: java.util.regex.Pattern
        :raises java.util.regex.PatternSyntaxException: if the input could be compiled
        """

    @staticmethod
    def createPattern(input: typing.Union[java.lang.String, str], allowGlobbing: typing.Union[jpype.JBoolean, bool], options: typing.Union[jpype.JInt, int]) -> java.util.regex.Pattern:
        """
        Creates a regular expression Pattern that will match all strings that
        **match exactly** the given input string.
         
        
        This method can be used with :meth:`Matcher.matches() <Matcher.matches>` or :meth:`Matcher.find() <Matcher.find>`.
        
        :param java.lang.String or str input: the string that you want to your matched strings to exactly match.
        :param jpype.JBoolean or bool allowGlobbing: if true, globing characters (* and ?) will converted to regex wildcard patterns;
                otherwise, they will be escaped and searched as literals.
        :param jpype.JInt or int options: any :obj:`Pattern` options desired.  For example, you can pass
                    :obj:`Pattern.CASE_INSENSITIVE` to get case insensitivity.
        :return: a regular expression Pattern that will **match**
                    all strings that exactly match with the given input string.
        :rtype: java.util.regex.Pattern
        """

    @staticmethod
    def createPatternString(input: typing.Union[java.lang.String, str], allowGlobbing: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Creates a regular expression that can be used to create a Pattern that will **match**
        all strings that match the given input string.
         
        
        This method can be used with :meth:`Matcher.matches() <Matcher.matches>` or :meth:`Matcher.find() <Matcher.find>`.
        
        :param java.lang.String or str input: the string that you want to your matched strings to exactly match.
        :param jpype.JBoolean or bool allowGlobbing: if true, globing characters (* and ?) will converted to regex wildcard patterns;
                otherwise, they will be escaped and searched as literals.
        :return: a regular expression Pattern String that will **match**
                    all strings that exactly match with the given input string.
        :rtype: str
        """

    @staticmethod
    def createSearchPattern(input: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> java.util.regex.Pattern:
        """
        **
        Note: this is the default model of how to let users search for things in Ghidra.  This
        is NOT a tool to allow regex searching, but instead allows users to perform searches while
        using familiar globbing characters such as '*' and '?'.
        **
         
        
        This method can be used with :meth:`Matcher.matches() <Matcher.matches>` or :meth:`Matcher.find() <Matcher.find>`.
         
        
        Create a regular expression from the given input. **Note:** the regular expression
        created by this method is not a pure regular expression.  More specifically, many
        regular expression characters passed to this method will be escaped
        (see :meth:`escapeAllRegexCharacters(String) <.escapeAllRegexCharacters>`.
         
        
        Also, globbing characters
        **will** be changed from a regular expression meaning to a
        command-line style glob meaning.
        
         
        
        **Note: **This method **will** escape regular expression
        characters, such as:
         
        * ?
        * .
        * $
        * ...and many others
        
        Thus, this method is not meant to **accept** regular expressions, but
        rather **generates** regular expressions.
        
        :param java.lang.String or str input: string to create a regular expression from
        :param jpype.JBoolean or bool caseSensitive: true if the regular expression is case sensitive
        :return: Pattern the compiled regular expression
        :rtype: java.util.regex.Pattern
        :raises java.util.regex.PatternSyntaxException: if the input could be compiled
        """

    @staticmethod
    def createStartsWithPattern(input: typing.Union[java.lang.String, str], allowGlobbing: typing.Union[jpype.JBoolean, bool], options: typing.Union[jpype.JInt, int]) -> java.util.regex.Pattern:
        """
        Creates a regular expression Pattern that will **match**
        all strings that **start with** the given input string.
         
        
        This method should only be used with :meth:`Matcher.matches() <Matcher.matches>`.
         
        
        The returned regular expression Pattern should be used
        with the "matches" method on a Matcher.  (As opposed to "find").
        
        :param java.lang.String or str input: the string that you want to your matched strings to start with.
        :param jpype.JBoolean or bool allowGlobbing: if true, globing characters (* and ?) will converted to regex wildcard patterns;
                otherwise, they will be escaped and searched as literals.
        :param jpype.JInt or int options: any :obj:`Pattern` options desired.  For example, you can pass
                    :obj:`Pattern.CASE_INSENSITIVE` to get case insensitivity.
        :return: a regular expression Pattern that will **match**
                        all strings that start with the given input string.
        :rtype: java.util.regex.Pattern
        """

    @staticmethod
    def escapeNonGlobbingRegexCharacters(input: typing.Union[java.lang.String, str]) -> str:
        """
        Escapes all special regex characters except globbing chars (*?)
        
        :param java.lang.String or str input: the string to sanitize
        :return: a new string with all non-globing regex characters escaped.
        :rtype: str
        """


class DefaultErrorLogger(ErrorLogger):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Location(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        """
        Returns a description for the location.  This should probably describe the significance of the
        location.  For example, if this location is from an Issue, then what is its relationship to the
        issue.
        
        :return: a descrition for the location.
        :rtype: str
        """

    def getStringRepresentation(self) -> str:
        """
        Returns a displayable representation of this location.
        
        :return: a displayable representation of this location.
        :rtype: str
        """

    def go(self, provider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        """
        Will attempt to navigate to the location as appropriate.  For example, it may use the goto service
        to navigate the code browser to a progam and an address.  Or it could launch a browser and
        display a web page.
        
        :param ghidra.framework.plugintool.ServiceProvider provider: a service provider that this location can use to find a service to help with
        navigation.
        :return: true if the navigation was successful, false otherwise.
        :rtype: bool
        """

    @property
    def stringRepresentation(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class SystemUtilities(java.lang.Object):
    """
    General purpose class to provide convenience methods for doing "System" type
    stuff, e.g., find resources, date/time, etc. All methods in this class are
    static.
    """

    class_: typing.ClassVar[java.lang.Class]
    FONT_SIZE_OVERRIDE_PROPERTY_NAME: typing.Final = "font.size.override"
    """
    System property that signals to override the font settings for Java and
    Ghidra components.
    """

    TESTING_PROPERTY: typing.Final = "SystemUtilities.isTesting"
    """
    The system property that can be checked during testing to determine if
    the system is running in test mode.
    """

    TESTING_BATCH_PROPERTY: typing.Final = "ghidra.test.property.batch.mode"
    """
    The system property that can be checked during testing to determine if
    the system is running in batch, automated test mode.
    """

    HEADLESS_PROPERTY: typing.Final = "SystemUtilities.isHeadless"
    """
    The system property that can be checked during runtime to determine if we
    are running with a GUI or headless.
    """

    SINGLE_JAR_MODE_PROPERTY: typing.Final = "SystemUtilities.isSingleJarMode"
    """
    The system property that can be checked during runtime to determine if we
    are running in single-jar mode.
    """


    def __init__(self):
        ...

    @staticmethod
    @deprecated("Use the theming system for fonts")
    def adjustForFontSizeOverride(font: java.awt.Font) -> java.awt.Font:
        """
        No longer supported.  Use the theming system for fonts
        
        :param java.awt.Font font: the font
        :return: the same font passed in
        :rtype: java.awt.Font
        
        .. deprecated::
        
        Use the theming system for fonts
        """

    @staticmethod
    def assertThisIsTheSwingThread(errorMessage: typing.Union[java.lang.String, str]):
        """
        A development/testing time method to make sure the current thread is the swing thread.
        
        :param java.lang.String or str errorMessage: The message to display when the assert fails
        """

    @staticmethod
    def assertTrue(booleanValue: typing.Union[jpype.JBoolean, bool], string: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def compareTo(c1: T, c2: T) -> int:
        ...

    @staticmethod
    def getBooleanProperty(name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Gets the boolean value of the system property by the given name.  If the property is
        not set, the defaultValue is returned.   If the value is set, then it will be passed
        into :meth:`Boolean.parseBoolean(String) <Boolean.parseBoolean>`.
        
        :param java.lang.String or str name: the property name to check
        :param jpype.JBoolean or bool defaultValue: the default value
        :return: true if the property is set and has a value of 'true', ignoring case
        :rtype: bool
        """

    @staticmethod
    def getCleanUserName(name: typing.Union[java.lang.String, str]) -> str:
        """
        Clean the specified user name to eliminate any spaces or leading domain name
        which may be present (e.g., "MyDomain\John Doe" becomes "JohnDoe").
        
        :param java.lang.String or str name: user name string to be cleaned-up
        :return: the clean user name
        :rtype: str
        """

    @staticmethod
    def getDefaultThreadPoolSize() -> int:
        """
        Returns the default size (in number of threads) for a **CPU processing bound**
        thread pool.
        
        :return: the default pool size.
        :rtype: int
        """

    @staticmethod
    def getFontSizeOverrideValue() -> int:
        """
        Returns a non-null value if the system property is set that triggers the
        font override setting, which makes all Java and Ghidra component fonts
        the same size.
        
        :return: a non-null value if the system property is set that triggers the
                font override setting, which makes all Java and Ghidra component
                fonts the same size.
        :rtype: int
        
        .. seealso::
        
            | :obj:`.FONT_SIZE_OVERRIDE_PROPERTY_NAME`
        """

    @staticmethod
    def getSourceLocationForClass(classObject: java.lang.Class[typing.Any]) -> java.io.File:
        """
        Returns a file that contains the given class. If the class is in a jar file, then
        the jar file will be returned. If the file is in a .class file, then the directory
        containing the package root will be returned (i.e. the "bin" directory).
        
        :param java.lang.Class[typing.Any] classObject: the class for which to get the location
        :return: the containing location
        :rtype: java.io.File
        """

    @staticmethod
    def getUserName() -> str:
        """
        Get the user that is running the application.  This name may be modified to
        eliminate any spaces or leading domain name which may be present in Java's
        ``user.name`` system property (see :meth:`getCleanUserName(String) <.getCleanUserName>`).
        
        :return: the user name
        :rtype: str
        """

    @staticmethod
    def isArrayEqual(array1: jpype.JArray[java.lang.Object], array2: jpype.JArray[java.lang.Object]) -> bool:
        ...

    @staticmethod
    def isEqual(o1: java.lang.Object, o2: java.lang.Object) -> bool:
        """
        Returns whether or not the two indicated objects are equal. It allows
        either or both of the specified objects to be null.
        
        :param java.lang.Object o1: the first object or null
        :param java.lang.Object o2: the second object or null
        :return: true if the objects are equal.
        :rtype: bool
        """

    @staticmethod
    def isEventDispatchThread() -> bool:
        """
        Returns true if this is the event dispatch thread. Note that this method returns true in
        headless mode because any thread in headless mode can dispatch its own events. In swing
        environments, the swing thread is usually used to dispatch events.
        
        :return: true if this is the event dispatch thread -OR- is in headless mode.
        :rtype: bool
        """

    @staticmethod
    def isInDevelopmentMode() -> bool:
        """
        Returns true if we are running in development mode. The assumption is
        that if this class is in a jar file, then we are in production mode.
        
        :return: true if we are running in development mode
        :rtype: bool
        """

    @staticmethod
    def isInHeadlessMode() -> bool:
        """
        Returns true if the system is running without a GUI.
        
        :return: true if the system is running without a GUI.
        :rtype: bool
        """

    @staticmethod
    def isInReleaseMode() -> bool:
        """
        Returns true if the application is a release and not in development or testing
        
        :return: true if the application is a release and not in development or testing
        :rtype: bool
        """

    @staticmethod
    def isInTestingBatchMode() -> bool:
        """
        Returns true if the system is running during a batch, automated test.
        
        :return: true if the system is running during a batch, automated test.
        :rtype: bool
        """

    @staticmethod
    def isInTestingMode() -> bool:
        """
        Returns true if the system is running during a test.
        
        :return: true if the system is running during a test.
        :rtype: bool
        """

    @staticmethod
    def printString(string: typing.Union[java.lang.String, str], printStream: java.io.PrintStream) -> bool:
        """
        A debugging utility that allows you to create a conditional breakpoint in Eclipse that
        will print items for you while it is performing its tests.  This method always returns
        false.  This means to use it you will have to OR (||) your conditional breakpoint
        expressions if you want them to pass.  Otherwise, you can make this method be the
        only breakpoint expression and it will never stop on the breakpoint, but will still
        print your debug.
         
        
        This method is useful to print values of code that you cannot edit while debugging.
         
        
        Example, inside of your conditional breakpoint for a method on a Sun Java file you
        can put something like: ``printString("Value of first arg: " + arg0, System.err)``
         
        
        Note: Don't remove this method simply because no code is referencing it, as it is used
        by conditional breakpoints.
        
        :param java.lang.String or str string: The string to print
        :param java.io.PrintStream printStream: The stream to print to (System.our or err)
        :return: The string passed in so that you can use this method in an evaluation
        :rtype: bool
        """

    @staticmethod
    def runIfSwingOrPostSwingLater(r: java.lang.Runnable):
        ...

    @staticmethod
    def runSwingLater(r: java.lang.Runnable):
        """
        Calls the given runnable on the Swing thread in the future by putting the request on
        the back of the event queue.
        
        :param java.lang.Runnable r: the runnable
        """

    @staticmethod
    @typing.overload
    def runSwingNow(s: java.util.function.Supplier[T]) -> T:
        """
        Calls the given suppler on the Swing thread, blocking with a
        :meth:`SwingUtilities.invokeAndWait(Runnable) <SwingUtilities.invokeAndWait>`.  Use this method when you need to get
        a value while being on the Swing thread.
        
                String value = runSwingNow(() -> label.getText());
        
        :param java.util.function.Supplier[T] s: the supplier that will be called on the Swing thread
        :return: the result of the supplier
        :rtype: T
        
        .. seealso::
        
            | :obj:`.runSwingNow(Runnable)`
        """

    @staticmethod
    @typing.overload
    def runSwingNow(r: java.lang.Runnable):
        """
        Calls the given runnable on the Swing thread.
        
        :param java.lang.Runnable r: the runnable
        
        .. seealso::
        
            | :obj:`.runSwingNow(Supplier)`if you need to return a value from the Swing thread.
        """


class ErrorDisplay(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def displayErrorMessage(self, errorLogger: ErrorLogger, originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object, throwable: java.lang.Throwable):
        ...

    def displayInfoMessage(self, errorLogger: ErrorLogger, originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object):
        ...

    def displayWarningMessage(self, errorLogger: ErrorLogger, originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object, throwable: java.lang.Throwable):
        ...


class BoundedInputStream(java.io.InputStream):
    """
    :obj:`InputStream` wrapper that limits itself to a portion of the wrapped stream.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, wrappedInputStream: java.io.InputStream, size: typing.Union[jpype.JLong, int]):
        """
        Creates a new instance.
        
        :param java.io.InputStream wrappedInputStream: :obj:`InputStream` to wrap, already positioned to the desired
        starting position.
        :param jpype.JLong or int size: number of bytes to allow this wrapper to read.
        """


class NullOutputStream(java.io.OutputStream):
    """
    A :obj:`OutputStream` that discards all bytes written to it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def close(self):
        ...

    def flush(self):
        ...

    @typing.overload
    def write(self, b: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        ...


class Fixup(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def canFixup(self) -> bool:
        """
        Return true if this Fixup object can automatically perform some action to address the issue. false 
        if the fixup() method does nothing.
        
        :return: 
        :rtype: bool
        """

    def fixup(self, provider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        """
        Attempts to perform some action or task to "fix" the related issue.
        
        :param ghidra.framework.plugintool.ServiceProvider provider: a service provider that can provide various services.
        :return: true if the fixup performed its intended action.
        :rtype: bool
        """

    def getDescription(self) -> str:
        """
        Returns a description of what this Fixup.  Typically, it will either be a simple suggestion
        for something the user could do, or it might be a description of whate the fixup() method will
        attempt to do to address some issue.
        
        :return: a description for this Fixup
        :rtype: str
        """

    @property
    def description(self) -> java.lang.String:
        ...


class Msg(java.lang.Object):
    """
    Class with static methods to report errors as either a short message or a
    more detailed message (e.g., stacktrace).
     
     
    The 'message' parameter for these calls is typically a String.  However, it can also 
    be a log4j ``Message`` object as well.   (See log4j2 for details.)
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def debug(originator: java.lang.Object, message: java.lang.Object):
        """
        Used to record a debug message to the log file.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def debug(originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        """
        Used to record a debug message to the log file.  This may be used to document an exception
        without elevating that exception to error or warning status
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        :param java.lang.Throwable throwable: the Throwable that describes the cause of the error
        """

    @staticmethod
    @typing.overload
    def error(originator: java.lang.Object, message: java.lang.Object):
        """
        Used to display an error message with no available Throwable to the user
        via the console (no GUI). Also records the message to the logging system.
        If you have a Throwable, please use the other error(...) method.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def error(originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        """
        Used to display an error message with a Throwable (for stack trace) to
        the user via the console (no GUI). Also records the message to the
        logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        :param java.lang.Throwable throwable: the Throwable that describes the cause of the error
        """

    @staticmethod
    @typing.overload
    def info(originator: java.lang.Object, message: java.lang.Object):
        """
        Used to display an informational message to the user via the console (no
        GUI). Also records the message to the logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def info(originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        """
        Used to display an informational message to the user via the console (no
        GUI). Also records the message to the logging system.  This may be used to 
        document an exception without elevating that exception to error or warning status.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        :param java.lang.Throwable throwable: the Throwable that describes the cause of the error
        """

    @staticmethod
    def out(message: java.lang.Object):
        """
        Useful for printing temporary messages without any logging markup.  This is meant to be
        a replacement for System.out.
        
        :param java.lang.Object message: the message to print
        """

    @staticmethod
    def setErrorDisplay(errDisplay: ErrorDisplay):
        """
        Sets the error display (by default it's console)
        
        :param ErrorDisplay errDisplay: the error display
        """

    @staticmethod
    def setErrorLogger(errLogger: ErrorLogger):
        """
        Sets the error logger (by default it's a DefaultErrorLogger).
        
        :param ErrorLogger errLogger: the error logger
        """

    @staticmethod
    @typing.overload
    def showError(originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object):
        """
        Used to display an error message with no available Throwable to the user
        with a pop-up GUI dialog. Also records the message to the logging system.
        If you have a Throwable, please use the other error(...) method.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.awt.Component parent: a parent component used to center the dialog (or null if you
                    don't have one)
        :param java.lang.String or str title: the title of the pop-up dialog (main subject of message)
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def showError(originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object, throwable: java.lang.Throwable):
        """
        Used to display an error message with a Throwable (for stack trace) to
        the user with a pop-up GUI dialog. Also records the message to the
        logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.awt.Component parent: a parent component used to center the dialog (or null if you
                    don't have one)
        :param java.lang.String or str title: the title of the pop-up dialog (main subject of message)
        :param java.lang.Object message: the details of the message
        :param java.lang.Throwable throwable: the Throwable that describes the cause of the error
        """

    @staticmethod
    def showInfo(originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object):
        """
        Used to display an informational message to the user
        with a pop-up GUI dialog. Also records the message to the logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.awt.Component parent: a parent component used to center the dialog (or null if you
                    don't have one)
        :param java.lang.String or str title: the title of the pop-up dialog (main subject of message)
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    def showWarn(originator: java.lang.Object, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: java.lang.Object):
        """
        Used to display a warning message to the user with a pop-up GUI dialog.
        Also records the message to the logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.awt.Component parent: a parent component used to center the dialog (or null if you
                    don't have one)
        :param java.lang.String or str title: the title of the pop-up dialog (main subject of message)
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def trace(originator: java.lang.Object, message: java.lang.Object):
        """
        Used to record a trace message to the log file. All calls to this method
        outside of main methods and JUnit tests will be removed before a
        production release.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def trace(originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        """
        Used to record a trace message to the log file. All calls to this method
        outside of main methods and JUnit tests will be removed before a
        production release. This may be used to document an exception
        without elevating that exception to error or warning status.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        :param java.lang.Throwable throwable: the Throwable that describes the cause of the error
        """

    @staticmethod
    @typing.overload
    def warn(originator: java.lang.Object, message: java.lang.Object):
        """
        Used to display a warning message to the user via the console (no GUI).
        Also records the message to the logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        """

    @staticmethod
    @typing.overload
    def warn(originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        """
        Used to display a warning message to the user via the console (no GUI).
        Also records the message to the logging system.
        
        :param java.lang.Object originator: a Logger instance, "this", or YourClass.class
        :param java.lang.Object message: the details of the message
        :param java.lang.Throwable throwable: a Throwable for printing a stack trace
        """


class Issue(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getCategory(self) -> str:
        """
        Returns the category for this issue.  Categories may use '.' as separators to present 
        a hierarchical category structure.
        
        :return: the category for this issue.
        :rtype: str
        """

    def getDescription(self) -> str:
        """
        Returns a detailed description of the issue.
        
        :return: a detailed description of the issue.
        :rtype: str
        """

    def getPossibleFixups(self) -> java.util.List[Fixup]:
        """
        Returns a list of possible Fixup objects for this issue.
        
        :return: a list of possible Fixup objects for this issue. This list may be empty, but not null.
        :rtype: java.util.List[Fixup]
        """

    def getPrimaryLocation(self) -> Location:
        """
        Returns a Location object that describes where the issue occurred.
        
        :return: a Location object that describes where the issue occurred. May return null
        if the issue is not related to a specific location.
        :rtype: Location
        """

    def getSecondaryLocations(self) -> java.util.List[Location]:
        """
        Returns a list of locations related to the issue that are not the primary issue location.
        
        :return: a list of locations related to the issue that are not the primary issue location.  
        This list may be empty, but not null.
        :rtype: java.util.List[Location]
        """

    @property
    def secondaryLocations(self) -> java.util.List[Location]:
        ...

    @property
    def primaryLocation(self) -> Location:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def category(self) -> java.lang.String:
        ...

    @property
    def possibleFixups(self) -> java.util.List[Fixup]:
        ...


class HashingOutputStream(java.io.OutputStream):
    """
    A filtering :obj:`OutputStream` that calculates the hash of the bytes being
    written.
     
    
    Call :meth:`getDigest() <.getDigest>` to retrieve the hash value bytes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, out: java.io.OutputStream, hashAlgo: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.io.OutputStream out: - OutputStream to wrap
        :param java.lang.String or str hashAlgo: - see :meth:`MessageDigest.getInstance(String) <MessageDigest.getInstance>`, ie. "MD5".
        :raises NoSuchAlgorithmException:
        """

    def close(self):
        ...

    def flush(self):
        ...

    def getDigest(self) -> jpype.JArray[jpype.JByte]:
        ...

    @typing.overload
    def write(self, b: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        ...

    @property
    def digest(self) -> jpype.JArray[jpype.JByte]:
        ...


class MessageType(java.lang.Enum[MessageType]):

    class_: typing.ClassVar[java.lang.Class]
    INFO: typing.Final[MessageType]
    ALERT: typing.Final[MessageType]
    WARNING: typing.Final[MessageType]
    ERROR: typing.Final[MessageType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MessageType:
        ...

    @staticmethod
    def values() -> jpype.JArray[MessageType]:
        ...


class MonitoredOutputStream(java.io.OutputStream):
    """
    An OutputStream which utilizes a TaskMonitor to indicate output progress and
    allows the operation to be cancelled via the TaskMonitor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, out: java.io.OutputStream, monitor: ghidra.util.task.TaskMonitor):
        ...

    def close(self):
        """
        Closes this output stream and releases any system resources 
        associated with the stream. 
         
        
        The ``close`` method of ``FilterOutputStream`` 
        calls its ``flush`` method, and then calls the 
        ``close`` method of its underlying output stream.
        
        :raises IOException: if an I/O error occurs.
        
        .. seealso::
        
            | :obj:`java.io.FilterOutputStream.flush()`
        """

    def flush(self):
        """
        Flushes this output stream and forces any buffered output bytes 
        to be written out to the stream. 
         
        
        The ``flush`` method of ``FilterOutputStream`` 
        calls the ``flush`` method of its underlying output stream.
        
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: typing.Union[jpype.JInt, int]):
        """
        Writes the specified ``byte`` to this output stream. 
         
        
        The ``write`` method of ``FilterOutputStream`` 
        calls the ``write`` method of its underlying output stream, 
        that is, it performs ``out.write(b)``.
         
        
        Implements the abstract ``write`` method of ``OutputStream``.
        
        :param jpype.JInt or int b: the ``byte``.
        :raises IOException: if an I/O error occurs.
        """

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte]):
        """
        Writes ``b.length`` bytes to this output stream. 
         
        
        The ``write`` method of ``FilterOutputStream`` 
        calls its ``write`` method of three arguments with the 
        arguments ``b``, ``0``, and 
        ``b.length``. 
         
        
        Note that this method does not call the one-argument 
        ``write`` method of its underlying stream with the single 
        argument ``b``.
        
        :param jpype.JArray[jpype.JByte] b: the data to be written.
        :raises IOException: if an I/O error occurs.
        
        .. seealso::
        
            | :obj:`java.io.FilterOutputStream.write(byte[], int, int)`
        """

    @typing.overload
    def write(self, b: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        """
        Writes ``len`` bytes from the specified 
        ``byte`` array starting at offset ``off`` to 
        this output stream. 
         
        
        The ``write`` method of ``FilterOutputStream`` 
        calls the ``write`` method of one argument on each 
        ``byte`` to output. 
         
        
        Note that this method does not call the ``write`` method 
        of its underlying input stream with the same arguments. Subclasses 
        of ``FilterOutputStream`` should provide a more efficient 
        implementation of this method.
        
        :param jpype.JArray[jpype.JByte] b: the data.
        :param jpype.JInt or int off: the start offset in the data.
        :param jpype.JInt or int len: the number of bytes to write.
        :raises IOException: if an I/O error occurs.
        
        .. seealso::
        
            | :obj:`java.io.FilterOutputStream.write(int)`
        """


class ErrorLogger(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def debug(self, originator: java.lang.Object, message: java.lang.Object):
        ...

    @typing.overload
    def debug(self, originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        ...

    @typing.overload
    def error(self, originator: java.lang.Object, message: java.lang.Object):
        ...

    @typing.overload
    def error(self, originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        ...

    @typing.overload
    def info(self, originator: java.lang.Object, message: java.lang.Object):
        ...

    @typing.overload
    def info(self, originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        ...

    @typing.overload
    def trace(self, originator: java.lang.Object, message: java.lang.Object):
        ...

    @typing.overload
    def trace(self, originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        ...

    @typing.overload
    def warn(self, originator: java.lang.Object, message: java.lang.Object):
        ...

    @typing.overload
    def warn(self, originator: java.lang.Object, message: java.lang.Object, throwable: java.lang.Throwable):
        ...


class Swing(java.lang.Object):
    """
    A utility class to handle running code on the AWT Event Dispatch Thread
    """

    class_: typing.ClassVar[java.lang.Class]
    GSWING_THREAD_POOL_NAME: typing.Final = "GSwing Worker"

    @staticmethod
    def allowSwingToProcessEvents():
        """
        Wait until AWT event queue (Swing) has been flushed and no more (to a point) events
        are pending.
        """

    @staticmethod
    def assertSwingThread(errorMessage: typing.Union[java.lang.String, str]) -> bool:
        """
        Logs a stack trace if the current calling thread is not the Swing thread
        
        :param java.lang.String or str errorMessage: The message to display when not on the Swing thread
        :return: true if the calling thread is the Swing thread
        :rtype: bool
        """

    @staticmethod
    def isSwingThread() -> bool:
        """
        Returns true if this is the event dispatch thread. Note that this method returns true in
        headless mode because any thread in headless mode can dispatch its own events. In swing
        environments, the swing thread is usually used to dispatch events.
        
        :return: true if this is the event dispatch thread -OR- is in headless mode.
        :rtype: bool
        """

    @staticmethod
    def runIfSwingOrRunLater(r: java.lang.Runnable):
        """
        Runs the given runnable now if the caller is on the Swing thread.  Otherwise, the 
        runnable will be posted later.
        
        :param java.lang.Runnable r: the runnable
        """

    @staticmethod
    def runLater(r: java.lang.Runnable):
        """
        Calls the given runnable on the Swing thread in the future by putting the request on
        the back of the event queue.
        
        :param java.lang.Runnable r: the runnable
        """

    @staticmethod
    @typing.overload
    def runNow(s: java.util.function.Supplier[T]) -> T:
        """
        Calls the given suppler on the Swing thread, blocking with a
        :meth:`SwingUtilities.invokeAndWait(Runnable) <SwingUtilities.invokeAndWait>` if not on the Swing thread.  
         
         
        Use this method when you are not on the Swing thread and you need to get a value 
        that is managed/synchronized by the Swing thread.
        
                String value = runNow(() -> label.getText());
        
        :param java.util.function.Supplier[T] s: the supplier that will be called on the Swing thread
        :return: the result of the supplier
        :rtype: T
        
        .. seealso::
        
            | :obj:`.runNow(Runnable)`
        """

    @staticmethod
    @typing.overload
    def runNow(r: java.lang.Runnable):
        """
        Calls the given runnable on the Swing thread
        
        :param java.lang.Runnable r: the runnable
        
        .. seealso::
        
            | :obj:`.runNow(Supplier)`if you need to return a value from the Swing thread.
        """

    @staticmethod
    @typing.overload
    def runNow(r: java.lang.Runnable, timeout: typing.Union[jpype.JLong, int], unit: java.util.concurrent.TimeUnit):
        """
        Calls the given runnable on the Swing thread
         
         
        This method will throw an exception if the Swing thread is not available within the
        given timeout.  This method is useful for preventing deadlocks.
        
        :param java.lang.Runnable r: the runnable
        :param jpype.JLong or int timeout: the timeout value
        :param java.util.concurrent.TimeUnit unit: the time unit of the timeout value
        :raises UnableToSwingException: if the timeout was reach waiting for the Swing thread
        
        .. seealso::
        
            | :obj:`.runNow(Supplier)`if you need to return a value from the Swing thread.
        """


class ConsoleErrorDisplay(ErrorDisplay):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["BrowserLoader", "ManualViewerCommandWrappedOption", "StackFrameImpl", "GhidraJarBuilder", "MultiComparableArrayIterator", "UndefinedFunction", "ManualViewerCommandEditor", "LaunchErrorDialog", "SourceFileUtils", "GhidraBigEndianDataConverter", "GhidraLittleEndianDataConverter", "ManualEntry", "GhidraDataConverter", "XmlProgramUtilities", "Lock", "VersionExceptionHandler", "NotOwnerException", "PropertyFile", "MD5Utilities", "NamingUtilities", "HashUtilities", "HTMLUtilities", "TrackedTaskListener", "WebColors", "ColorUtils", "HelpLocation", "TaskUtilities", "JavaSourceFile", "Conv", "FilterTransformer", "TestUniversalIdGenerator", "CountLatch", "JavaSourceLine", "StringFormat", "UniversalID", "PrivateSaveable", "StringUtilities", "LongIterator", "WordLocation", "TriConsumer", "Disposable", "InvalidNameException", "DateUtils", "SignednessFormatMode", "DropTargetDragEventWrapper", "CascadedDropTarget", "TestSuiteUtilities", "BigEndianDataConverter", "UniversalIdGenerator", "MonitoredInputStream", "ObjectStorage", "SaveablePoint", "ObjectStorageStreamAdapter", "SaveableColor", "NumericUtilities", "ReversedListIterator", "LittleEndianDataConverter", "DataConverter", "StatusListener", "ReadOnlyException", "Saveable", "MathUtilities", "UserSearchUtils", "DefaultErrorLogger", "Location", "SystemUtilities", "ErrorDisplay", "BoundedInputStream", "NullOutputStream", "Fixup", "Msg", "Issue", "HashingOutputStream", "MessageType", "MonitoredOutputStream", "ErrorLogger", "Swing", "ConsoleErrorDisplay"]
