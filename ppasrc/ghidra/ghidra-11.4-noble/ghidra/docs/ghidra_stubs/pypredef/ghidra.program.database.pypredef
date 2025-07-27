from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import generic.stl
import ghidra.framework.data
import ghidra.framework.model
import ghidra.program.database.code
import ghidra.program.database.map
import ghidra.program.database.mem
import ghidra.program.database.module
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.lang.ref # type: ignore
import java.nio.charset # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import utility.function


E = typing.TypeVar("E")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class GhidraDataTypeArchiveMergeManagerFactory(DataTypeArchiveMergeManagerFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GhidraProgramMultiUserMergeManagerFactory(ProgramMultiUserMergeManagerFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramBuilder(java.lang.Object):

    class ExceptionalSupplier(java.lang.Object, typing.Generic[R, E]):

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> R:
            ...


    class_: typing.ClassVar[java.lang.Class]
    _ARM: typing.Final = "ARM:LE:32:v7"
    _AARCH64: typing.Final = "AARCH64:LE:64:v8A"
    _X86: typing.Final = "x86:LE:32:default"
    _X86_16_REAL_MODE: typing.Final = "x86:LE:16:Real Mode"
    _X64: typing.Final = "x86:LE:64:default"
    _8051: typing.Final = "8051:BE:16:default"
    _SPARC64: typing.Final = "sparc:BE:64:default"
    _MIPS: typing.Final = "MIPS:BE:32:default"
    _MIPS_6432: typing.Final = "MIPS:BE:64:64-32addr"
    _PPC_32: typing.Final = "PowerPC:BE:32:default"
    _PPC_6432: typing.Final = "PowerPC:BE:64:64-32addr"
    _PPC_64: typing.Final = "PowerPC:BE:64:default"
    _TOY_BE: typing.Final = "Toy:BE:32:default"
    _TOY_BE_POSITIVE: typing.Final = "Toy:BE:32:posStack"
    _TOY_LE: typing.Final = "Toy:LE:32:default"
    _TOY_WORDSIZE2_BE: typing.Final = "Toy:BE:32:wordSize2"
    _TOY_WORDSIZE2_LE: typing.Final = "Toy:LE:32:wordSize2"
    _TOY64_BE: typing.Final = "Toy:BE:64:default"
    _TOY64_LE: typing.Final = "Toy:LE:64:default"
    _TOY: typing.Final = "Toy:BE:32:default"

    @typing.overload
    def __init__(self):
        """
        Construct program builder using the big-endian Toy language and default compiler spec.
        This builder object will be the program consumer and must be disposed to properly
        release the program.
        
        :raises java.lang.Exception: if there is an exception creating the program
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], languageName: typing.Union[java.lang.String, str]):
        """
        Construct program builder using specified language and default compiler spec.
        This builder object will be the program consumer and must be disposed to properly
        release the program.
        
        :param java.lang.String or str name: program name
        :param java.lang.String or str languageName: supported language ID (includes all Toy language IDs)
        :raises java.lang.Exception: if there is an exception creating the program
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], languageName: typing.Union[java.lang.String, str], consumer: java.lang.Object):
        """
        Construct program builder using specified language and default compiler spec
        
        :param java.lang.String or str name: program name
        :param java.lang.String or str languageName: supported language ID (includes all Toy language IDs)
        :param java.lang.Object consumer: program consumer (if null this builder will be used as consumer and must be disposed to release program)
        :raises java.lang.Exception: if there is an exception creating the program
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], languageName: typing.Union[java.lang.String, str], compilerSpecID: typing.Union[java.lang.String, str], consumer: java.lang.Object):
        """
        Construct program builder using specified language
        
        :param java.lang.String or str name: program name
        :param java.lang.String or str languageName: supported language ID (includes all Toy language IDs)
        :param java.lang.String or str compilerSpecID: compiler specification ID (if null default spec will be used)
        :param java.lang.Object consumer: program consumer (if null this builder will be used as consumer and must be disposed to release program)
        :raises java.lang.Exception: if there is an exception creating the program
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language):
        """
        Construct program builder using a full language object rather than a language id string
        
        :param java.lang.String or str name: program name
        :param ghidra.program.model.lang.Language language: Language object
        :raises java.lang.Exception: if there is an exception creating the program
        """

    def addCategory(self, path: ghidra.program.model.data.CategoryPath):
        ...

    def addDataType(self, dt: ghidra.program.model.data.DataType):
        ...

    def addFunctionVariable(self, f: ghidra.program.model.listing.Function, v: ghidra.program.model.listing.Variable):
        ...

    @typing.overload
    def addr(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def addr(self, addressString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        ...

    def analyze(self):
        """
        Perform complete analysis on the built program.
        Limited analysis may already have been performed during disassembly - so it may not
        be necessary to do complete analysis
        """

    @typing.overload
    def applyDataType(self, addressString: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.DataType):
        ...

    @typing.overload
    def applyDataType(self, addressString: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.DataType, n: typing.Union[jpype.JInt, int]):
        """
        Creates a data instance at the specified address, repeated ``N`` times.
        Any conflicting Data will be overwritten.
        
        :param java.lang.String or str addressString: address.
        :param ghidra.program.model.data.DataType dt: :obj:`DataType` to place at address, :obj:`Dynamic` length datatype not supported.
        :param jpype.JInt or int n: repeat count.
        """

    def applyFixedLengthDataType(self, addressString: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]):
        ...

    def applyStringDataType(self, addressString: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.AbstractStringDataType, n: typing.Union[jpype.JInt, int]):
        """
        Creates a sting data type instance at the specified address, repeated ``N`` times.
        
        :param java.lang.String or str addressString: address.
        :param ghidra.program.model.data.AbstractStringDataType dt: :obj:`AbstractStringDataType` string type to place at address.
        :param jpype.JInt or int n: repeat count.
        """

    def bindExternalLibrary(self, libraryName: typing.Union[java.lang.String, str], pathname: typing.Union[java.lang.String, str]):
        ...

    def clearCodeUnits(self, startAddressString: typing.Union[java.lang.String, str], endAddressString: typing.Union[java.lang.String, str], clearContext: typing.Union[jpype.JBoolean, bool]):
        ...

    def createBookmark(self, address: typing.Union[java.lang.String, str], bookmarkType: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Bookmark:
        ...

    def createClassNamespace(self, name: typing.Union[java.lang.String, str], parentNamespace: typing.Union[java.lang.String, str], type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.GhidraClass:
        ...

    @typing.overload
    def createComment(self, address: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], commentType: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def createComment(self, address: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], commentType: ghidra.program.model.listing.CommentType):
        ...

    @typing.overload
    def createEmptyFunction(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], returnType: ghidra.program.model.data.DataType, *params: ghidra.program.model.listing.Parameter) -> ghidra.program.model.listing.Function:
        ...

    @typing.overload
    def createEmptyFunction(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], returnType: ghidra.program.model.data.DataType, varargs: typing.Union[jpype.JBoolean, bool], inline: typing.Union[jpype.JBoolean, bool], noReturn: typing.Union[jpype.JBoolean, bool], *params: ghidra.program.model.listing.Parameter) -> ghidra.program.model.listing.Function:
        ...

    @typing.overload
    def createEmptyFunction(self, name: typing.Union[java.lang.String, str], namespace: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], bodySize: typing.Union[jpype.JInt, int], returnType: ghidra.program.model.data.DataType, *params: ghidra.program.model.listing.Parameter) -> ghidra.program.model.listing.Function:
        ...

    @typing.overload
    def createEmptyFunction(self, name: typing.Union[java.lang.String, str], namespace: typing.Union[java.lang.String, str], callingConventionName: typing.Union[java.lang.String, str], customStorage: typing.Union[jpype.JBoolean, bool], address: typing.Union[java.lang.String, str], bodySize: typing.Union[jpype.JInt, int], returnType: ghidra.program.model.data.DataType, *params: ghidra.program.model.listing.Parameter) -> ghidra.program.model.listing.Function:
        ...

    @typing.overload
    def createEmptyFunction(self, name: typing.Union[java.lang.String, str], namespace: typing.Union[java.lang.String, str], callingConventionName: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], returnType: ghidra.program.model.data.DataType, *paramTypes: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Function:
        ...

    def createEncodedString(self, address: typing.Union[java.lang.String, str], string: typing.Union[java.lang.String, str], encoding: java.nio.charset.Charset, nullTerminate: typing.Union[jpype.JBoolean, bool]):
        ...

    def createEntryPoint(self, addressString: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        ...

    def createEquate(self, address: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int], opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Equate:
        ...

    @typing.overload
    def createExternalFunction(self, extAddress: typing.Union[java.lang.String, str], libName: typing.Union[java.lang.String, str], functionName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.ExternalLocation:
        ...

    @typing.overload
    def createExternalFunction(self, extAddress: typing.Union[java.lang.String, str], libName: typing.Union[java.lang.String, str], functionName: typing.Union[java.lang.String, str], originalName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.ExternalLocation:
        ...

    def createExternalLibraries(self, *libraryNames: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def createExternalReference(self, fromAddress: typing.Union[java.lang.String, str], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def createExternalReference(self, fromAddress: typing.Union[java.lang.String, str], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], extAddress: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def createExternalReference(self, fromAddress: typing.Union[java.lang.String, str], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], extAddress: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType):
        ...

    def createFileBytes(self, size: typing.Union[jpype.JInt, int]) -> ghidra.program.database.mem.FileBytes:
        ...

    def createFragment(self, treeName: typing.Union[java.lang.String, str], modulePath: typing.Union[java.lang.String, str], fragmentName: typing.Union[java.lang.String, str], startAddr: typing.Union[java.lang.String, str], endAddr: typing.Union[java.lang.String, str]):
        ...

    def createFunction(self, addressString: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Function:
        """
        Creates a function by examining the instructions to find the body.
        
        :param java.lang.String or str addressString: the address
        :return: the function
        :rtype: ghidra.program.model.listing.Function
        """

    def createFunctionComment(self, entryPointAddress: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def createLabel(self, addressString: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        ...

    @typing.overload
    def createLabel(self, addressString: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], namespace: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        ...

    @typing.overload
    def createLibrary(self, libraryName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Library:
        ...

    @typing.overload
    def createLibrary(self, libraryName: typing.Union[java.lang.String, str], type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Library:
        ...

    def createLocalVariable(self, function: ghidra.program.model.listing.Function, name: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def createMemory(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @typing.overload
    def createMemory(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @typing.overload
    def createMemory(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], fileBytes: ghidra.program.database.mem.FileBytes, size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @typing.overload
    def createMemory(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str], initialValue: typing.Union[jpype.JByte, int]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    def createMemoryCallReference(self, fromAddress: typing.Union[java.lang.String, str], toAddress: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Reference:
        ...

    def createMemoryJumpReference(self, fromAddress: typing.Union[java.lang.String, str], toAddress: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Reference:
        ...

    def createMemoryReadReference(self, fromAddress: typing.Union[java.lang.String, str], toAddress: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Reference:
        ...

    @typing.overload
    def createMemoryReference(self, fromAddress: typing.Union[java.lang.String, str], toAddress: typing.Union[java.lang.String, str], refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Reference:
        ...

    @typing.overload
    def createMemoryReference(self, fromAddress: typing.Union[java.lang.String, str], toAddress: typing.Union[java.lang.String, str], refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Reference:
        ...

    @typing.overload
    def createNamespace(self, namespace: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        ...

    @typing.overload
    def createNamespace(self, namespace: typing.Union[java.lang.String, str], type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace:
        ...

    @typing.overload
    def createNamespace(self, namespace: typing.Union[java.lang.String, str], parentNamespace: typing.Union[java.lang.String, str], type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace:
        ...

    def createOffsetMemReference(self, fromAddress: typing.Union[java.lang.String, str], toAddress: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Reference:
        ...

    def createOverlayMemory(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    def createProgramTree(self, treeName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def createRegisterReference(self, fromAddress: typing.Union[java.lang.String, str], registerName: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Reference:
        ...

    @typing.overload
    def createRegisterReference(self, fromAddress: typing.Union[java.lang.String, str], refType: ghidra.program.model.symbol.RefType, registerName: typing.Union[java.lang.String, str], sourceType: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Reference:
        ...

    def createStackReference(self, fromAddress: typing.Union[java.lang.String, str], refType: ghidra.program.model.symbol.RefType, stackOffset: typing.Union[jpype.JInt, int], sourceType: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Reference:
        ...

    @typing.overload
    def createString(self, address: typing.Union[java.lang.String, str], string: typing.Union[java.lang.String, str], charset: java.nio.charset.Charset, nullTerminate: typing.Union[jpype.JBoolean, bool], dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data:
        ...

    @typing.overload
    def createString(self, address: typing.Union[java.lang.String, str], stringBytes: jpype.JArray[jpype.JByte], charset: java.nio.charset.Charset, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data:
        ...

    def createUninitializedMemory(self, name: typing.Union[java.lang.String, str], address: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    def deleteFunction(self, address: typing.Union[java.lang.String, str]):
        ...

    def deleteReference(self, reference: ghidra.program.model.symbol.Reference):
        ...

    @typing.overload
    def disassemble(self, addressString: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def disassemble(self, addressString: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], followFlows: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def disassemble(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def disassemble(self, set: ghidra.program.model.address.AddressSetView, followFlows: typing.Union[jpype.JBoolean, bool]):
        ...

    def disassembleArm(self, addressString: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], thumb: typing.Union[jpype.JBoolean, bool]):
        ...

    def dispose(self):
        ...

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @typing.overload
    def getNamespace(self, namespace: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        ...

    @typing.overload
    def getNamespace(self, namespace: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Namespace:
        ...

    def getOrCreateModule(self, treeName: typing.Union[java.lang.String, str], modulePath: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramModule:
        ...

    def getProgram(self) -> ProgramDB:
        """
        Get the constructed program.  If this builder was not constructed with a consumer,
        the caller should dispose the builder after either the program is no longer
        in use, or a new consumer has been added to the program (e.g., program opened
        in a tool or another consumer explicitly added).
        
        :return: constructed program
        :rtype: ProgramDB
        """

    def getRegister(self, regName: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.Register:
        ...

    def setAnalysisEnabled(self, name: typing.Union[java.lang.String, str], enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setAnalyzed(self):
        """
        This prevents the 'ask to analyze' dialog from showing when called with ``true``
        """

    @typing.overload
    def setBytes(self, address: typing.Union[java.lang.String, str], byteString: typing.Union[java.lang.String, str]):
        """
        Sets the bytes starting at ``address`` to the values encoded in ``byteString``.
         
        
        See :meth:`setBytes(String, byte[], boolean) <.setBytes>`.
        
        :param java.lang.String or str address: String containing numeric value, preferably hex encoded: "0x1004000"
        :param java.lang.String or str byteString: String containing 2 digit hex values, separated by ' ' space chars
        or by comma ',' chars: "12 05 ff".  See :meth:`NumericUtilities.parseHexLong(String) <NumericUtilities.parseHexLong>`.
        :raises java.lang.Exception: if there is an exception applying the bytes
        """

    @typing.overload
    def setBytes(self, address: typing.Union[java.lang.String, str], byteString: typing.Union[java.lang.String, str], disassemble: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the bytes starting at ``address`` to the values encoded in ``byteString``
        and then optionally disassembling.
         
        
        See :meth:`setBytes(String, byte[], boolean) <.setBytes>`.
        
        :param java.lang.String or str address: String containing numeric value, preferably hex encoded: "0x1004000"
        :param java.lang.String or str byteString: String containing 2 digit hex values, separated by ' ' space chars
        or by comma ',' chars: "12 05 ff".  See :meth:`NumericUtilities.parseHexLong(String) <NumericUtilities.parseHexLong>`.
        :param jpype.JBoolean or bool disassemble: boolean flag.
        :raises java.lang.Exception: if there is an exception applying the bytes
        """

    @typing.overload
    def setBytes(self, stringAddress: typing.Union[java.lang.String, str], bytes: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def setBytes(self, stringAddress: typing.Union[java.lang.String, str], bytes: jpype.JArray[jpype.JByte], disassemble: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the bytes starting at ``stringAddress`` to the byte values in ``bytes``
        and then optionally disassembling.
        
        :param java.lang.String or str stringAddress: String containing numeric value, preferably hex encoded: "0x1004000"
        :param jpype.JArray[jpype.JByte] bytes: array of bytes to copy into the memory buffer at the addresss.
        :param jpype.JBoolean or bool disassemble: boolean flag.  See :meth:`disassemble(String, int) <.disassemble>`
        :raises java.lang.Exception: if there is an exception applying the bytes
        """

    def setChanged(self, changed: typing.Union[jpype.JBoolean, bool]):
        ...

    def setExecute(self, block: ghidra.program.model.mem.MemoryBlock, e: typing.Union[jpype.JBoolean, bool]):
        ...

    def setFallthrough(self, from_: typing.Union[java.lang.String, str], to: typing.Union[java.lang.String, str]):
        ...

    def setIntProperty(self, address: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setObjectProperty(self, address: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], value: ghidra.util.Saveable):
        ...

    def setProperty(self, name: typing.Union[java.lang.String, str], value: java.lang.Object):
        ...

    def setRead(self, block: ghidra.program.model.mem.MemoryBlock, r: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRecordChanges(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRegisterValue(self, registerName: typing.Union[java.lang.String, str], startAddress: typing.Union[java.lang.String, str], endAddress: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        ...

    def setStringProperty(self, address: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    def setWrite(self, block: ghidra.program.model.mem.MemoryBlock, w: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def tx(self, c: utility.function.ExceptionalCallback[E]):
        ...

    @typing.overload
    def tx(self, s: ProgramBuilder.ExceptionalSupplier[R, E]) -> R:
        ...

    def withTransaction(self, r: java.lang.Runnable):
        ...

    @property
    def namespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def program(self) -> ProgramDB:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...


class OverlayRegionSupplier(java.lang.Object):
    """
    :obj:`OverlayRegionSupplier` provides a callback mechanism which allows a
    :obj:`ProgramOverlayAddressSpace` to identify defined memory regions within its
    space so that it may properly implement the :meth:`OverlayAddressSpace.contains(long) <OverlayAddressSpace.contains>`
    method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOverlayAddressSet(self, overlaySpace: ghidra.program.model.address.OverlayAddressSpace) -> ghidra.program.model.address.AddressSetView:
        """
        Get the set of memory address defined within the specified overlay space.
        
        :param ghidra.program.model.address.OverlayAddressSpace overlaySpace: overlay address space
        :return: set of memory address defined within the specified overlay space or null
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @property
    def overlayAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...


class DBStringMapAdapter(java.lang.Object):
    """
    ``DBStringMapAdapter`` provides a simple string-to-string map backed by a named database table.
    This adapter's schema must never change.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, tableName: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]):
        ...

    def delete(self, key: typing.Union[java.lang.String, str]):
        ...

    def get(self, key: typing.Union[java.lang.String, str]) -> str:
        ...

    def getBoolean(self, key: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def getInt(self, key: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> int:
        ...

    def keySet(self) -> java.util.Set[java.lang.String]:
        ...

    def put(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class OverlaySpaceDBAdapter(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProgramDBChangeSet(ghidra.program.model.listing.ProgramChangeSet, ghidra.framework.data.DomainObjectDBChangeSet):
    """
    Holds changes made to a program.
    Currently changes are summarized by an address set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addrMap: ghidra.program.database.map.AddressMap, numUndos: typing.Union[jpype.JInt, int]):
        """
        Construct a new ProgramChangeSet.
        
        :param ghidra.program.database.map.AddressMap addrMap: the address map.
        :param jpype.JInt or int numUndos: the number of undo change sets to track.
        """


@typing.type_check_only
class ChangeDiff(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DataTypeArchiveDB(ghidra.framework.data.DomainObjectAdapterDB, ghidra.program.model.listing.DataTypeArchive):
    """
    Database implementation for Data Type Archive.
    """

    class_: typing.ClassVar[java.lang.Class]
    ARCHIVE_INFO: typing.Final = "Data Type Archive Information"
    """
    Name of data type archive information property list
    """

    ARCHIVE_SETTINGS: typing.Final = "Data Type Archive Settings"
    """
    Name of data type archive settings property list
    """

    DATE_CREATED: typing.Final = "Date Created"
    """
    Name of date created property
    """

    CREATED_WITH_GHIDRA_VERSION: typing.Final = "Created With Ghidra Version"
    """
    Name of Ghidra version property
    """

    JANUARY_1_1970: typing.Final[java.util.Date]
    """
    A date from January 1, 1970
    """


    @typing.overload
    def __init__(self, folder: ghidra.framework.model.DomainFolder, name: typing.Union[java.lang.String, str], consumer: java.lang.Object):
        """
        Constructs a new DataTypeArchiveDB within a project folder.
        
        :param ghidra.framework.model.DomainFolder folder: folder within which the project archive will be created
        :param java.lang.String or str name: the name of the data type archive
        :param java.lang.Object consumer: the object that is using this data type archive.
        :raises IOException: if there is an error accessing the database.
        :raises InvalidNameException: 
        :raises DuplicateNameException:
        """

    @typing.overload
    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, monitor: ghidra.util.task.TaskMonitor, consumer: java.lang.Object):
        """
        Constructs a new DataTypeArchiveDB
        
        :param db.DBHandle dbh: a handle to an open data type archive database.
        :param ghidra.framework.data.OpenMode openMode: one of:
                READ_ONLY: the original database will not be modified
                UPDATE: the database can be written to.
                UPGRADE: the database is upgraded to the latest schema as it is opened.
        :param ghidra.util.task.TaskMonitor monitor: TaskMonitor that allows the open to be canceled.
        :param java.lang.Object consumer: the object that keeping the program open.
        :raises IOException: if an error accessing the database occurs.
        :raises VersionException: if database version does not match implementation, UPGRADE may be possible.
        :raises CancelledException: if instantiation is canceled by monitor
        """

    def categoryAdded(self, categoryID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a category was added.
        
        :param jpype.JLong or int categoryID: the id of the data type that was added.
        :param ghidra.program.util.ProgramEvent eventType: the type of change (should always be CATEGORY_ADDED)
        :param java.lang.Object oldValue: always null
        :param java.lang.Object newValue: new value depends on the type.
        """

    def categoryChanged(self, categoryID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a category was changed.
        
        :param jpype.JLong or int categoryID: the id of the data type that was added.
        :param ghidra.program.util.ProgramEvent eventType: the type of change
        :param java.lang.Object oldValue: old value depends on the type.
        :param java.lang.Object newValue: new value depends on the type.
        """

    def dataTypeAdded(self, dataTypeID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a data type was added.
        
        :param jpype.JLong or int dataTypeID: the id if the data type that was added.
        :param ghidra.program.util.ProgramEvent eventType: should always be DATATYPE_ADDED
        :param java.lang.Object oldValue: always null
        :param java.lang.Object newValue: the data type added.
        """

    def dataTypeChanged(self, dataTypeID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, isAutoResponseChange: typing.Union[jpype.JBoolean, bool], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        notification the a data type has changed
        
        :param jpype.JLong or int dataTypeID: the id of the data type that changed.
        :param ghidra.program.util.ProgramEvent eventType: the type of the change (moved, renamed, etc.)
        :param jpype.JBoolean or bool isAutoResponseChange: true if change is an auto-response change caused by 
        another datatype's change (e.g., size, alignment), else false in which case this
        change will be added to archive change-set to aid merge conflict detection.
        :param java.lang.Object oldValue: the old data type.
        :param java.lang.Object newValue: the new data type.
        """

    def setChanged(self, eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Mark the state this Data Type Archive as having changed and generate
        the event.  Any or all parameters may be null.
        
        :param ghidra.program.util.ProgramEvent eventType: event type
        :param java.lang.Object oldValue: original value
        :param java.lang.Object newValue: new value
        """


@typing.type_check_only
class ProgramUserDataDB(ghidra.framework.data.DomainObjectAdapterDB, ghidra.program.model.listing.ProgramUserData):
    """
    ``ProgramUserDataDB`` stores user data associated with a specific program.
    A ContentHandler should not be created for this class since it must never be stored
    within a DomainFolder.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ProgramDB):
        """
        Create a new program user data store.
        
        :param ProgramDB program: related program
        :raises IOException: if an IO error occurs
        """

    @typing.overload
    def __init__(self, dbh: db.DBHandle, program: ProgramDB, monitor: ghidra.util.task.TaskMonitor):
        """
        Open existing program user data store.
        If a major language change is detected the instance will automatically attempt to upgrade
        its internal address map.
        
        :param db.DBHandle dbh: user data storage DB handle
        :param ProgramDB program: related program
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises IOException: if an IO error occurs
        :raises VersionException: if a DB version error occurs
        :raises LanguageNotFoundException: if language was not found
        :raises CancelledException: if instantiation was cancelled
        :raises java.lang.IllegalStateException: if data store is bad or incmopatible with program
        """


class ManagerDB(java.lang.Object):
    """
    Interface that all subsection managers of a program must implement.
    """

    class_: typing.ClassVar[java.lang.Class]

    def deleteAddressRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Delete all objects which have been applied to the address range startAddr to endAddr
        and update the database accordingly.
        The specified start and end addresses must form a valid range within
        a single :obj:`AddressSpace`.
        
        :param ghidra.program.model.address.Address startAddr: the first address in the range.
        :param ghidra.program.model.address.Address endAddr: the last address in the range.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use in any upgrade operations.
        :raises CancelledException: if the user cancelled the operation via the task monitor.
        """

    def dispose(self):
        """
        Callback from the program after being closed to signal this manager to release memory and resources.
        """

    def invalidateCache(self, all: typing.Union[jpype.JBoolean, bool]):
        """
        Clears all data caches.
        
        :param jpype.JBoolean or bool all: if false, some managers may not need to update their cache if they can
        tell that its not necessary.  If this flag is true, then all managers should clear
        their cache no matter what.
        :raises IOException: if a database io error occurs.
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move all objects within an address range to a new location.
        
        :param ghidra.program.model.address.Address fromAddr: the first address of the range to be moved.
        :param ghidra.program.model.address.Address toAddr: the address where to the range is to be moved.
        :param jpype.JLong or int length: the number of addresses to move.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use in any upgrade operations.
        :raises CancelledException: if the user cancelled the operation via the task monitor.
        :raises AddressOverflowException: if the length is such that a address wrap occurs
        """

    def programReady(self, openMode: ghidra.framework.data.OpenMode, currentRevision: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Callback from program made to each manager after the program has completed initialization.
        This method may be used by managers to perform additional upgrading which may have been deferred.
        
        :param ghidra.framework.data.OpenMode openMode: the mode that the program is being opened.
        :param jpype.JInt or int currentRevision: current program revision.  If openMode is UPGRADE, this value reflects 
        the pre-upgrade value.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use in any upgrade operations.
        :raises IOException: if a database io error occurs.
        :raises CancelledException: if the user cancelled the operation via the task monitor.
        """

    def setProgram(self, program: ProgramDB):
        """
        Callback from program used to indicate all manager have been created.
        When this method is invoked, all managers have been instantiated but may not be fully initialized.
        
        :param ProgramDB program: the program is set when all the initializations have been completed.
        """


class ProgramDB(ghidra.framework.data.DomainObjectAdapterDB, ghidra.program.model.listing.Program, ghidra.program.util.ChangeManager):
    """
    Database implementation for Program.
    """

    class_: typing.ClassVar[java.lang.Class]
    CONTENT_TYPE: typing.Final = "Program"
    ANALYSIS_OPTIONS_MOVED_VERSION: typing.Final = 9
    """
    Key version numbers which require special upgrade handling
    """

    ADDED_VARIABLE_STORAGE_MANAGER_VERSION: typing.Final = 10
    METADATA_ADDED_VERSION: typing.Final = 11
    EXTERNAL_FUNCTIONS_ADDED_VERSION: typing.Final = 17
    COMPOUND_VARIABLE_STORAGE_ADDED_VERSION: typing.Final = 18
    AUTO_PARAMETERS_ADDED_VERSION: typing.Final = 19
    RELOCATION_STATUS_ADDED_VERSION: typing.Final = 26

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object):
        """
        Constructs a new ProgramDB
        
        :param java.lang.String or str name: the name of the program
        :param ghidra.program.model.lang.Language language: the Language used by this program
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: compiler specification
        :param java.lang.Object consumer: the object that is using this program.
        :raises IOException: if there is an error accessing the database.
        """

    @typing.overload
    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, monitor: ghidra.util.task.TaskMonitor, consumer: java.lang.Object):
        """
        Constructs a new ProgramDB
        
        :param db.DBHandle dbh: a handle to an open program database.
        :param ghidra.framework.data.OpenMode openMode: one of:
                READ_ONLY: the original database will not be modified
                UPDATE: the database can be written to.
                UPGRADE: the database is upgraded to the latest schema as it is opened.
        :param ghidra.util.task.TaskMonitor monitor: TaskMonitor that allows the open to be canceled.
        :param java.lang.Object consumer: the object that keeping the program open.
        :raises IOException: if an error accessing the database occurs.
        :raises VersionException: if database version does not match implementation, UPGRADE may be possible.
        :raises CancelledException: if instantiation is canceled by monitor
        :raises LanguageNotFoundException: if a language cannot be found for this program
        """

    def categoryAdded(self, categoryID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a category was added.
        
        :param jpype.JLong or int categoryID: the id of the datatype that was added.
        :param ghidra.program.util.ProgramEvent eventType: the type of change (should always be CATEGORY_ADDED)
        :param java.lang.Object oldValue: always null
        :param java.lang.Object newValue: new value depends on the type.
        """

    def categoryChanged(self, categoryID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a category was changed.
        
        :param jpype.JLong or int categoryID: the id of the datatype that was added.
        :param ghidra.program.util.ProgramEvent eventType: the type of change.
        :param java.lang.Object oldValue: old value depends on the type.
        :param java.lang.Object newValue: new value depends on the type.
        """

    def dataTypeAdded(self, dataTypeID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a datatype was added.
        
        :param jpype.JLong or int dataTypeID: the id if the datatype that was added.
        :param ghidra.program.util.ProgramEvent eventType: should always be DATATYPE_ADDED
        :param java.lang.Object oldValue: always null
        :param java.lang.Object newValue: the datatype added.
        """

    def dataTypeChanged(self, dataTypeID: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, isAutoChange: typing.Union[jpype.JBoolean, bool], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        notification the a datatype has changed
        
        :param jpype.JLong or int dataTypeID: the id of the datatype that changed.
        :param ghidra.program.util.ProgramEvent eventType: the type of the change (moved, renamed, etc.)
        :param jpype.JBoolean or bool isAutoChange: true if change was an automatic change in response to 
        another datatype's change (e.g., size, alignment), else false in which case this
        change will be added to program change-set to aid merge conflict detection.
        :param java.lang.Object oldValue: the old datatype.
        :param java.lang.Object newValue: the new datatype.
        """

    def deleteAddressRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Deletes given range from the program.
        
        :param ghidra.program.model.address.Address startAddr: the first address in the range.
        :param ghidra.program.model.address.Address endAddr: the last address in the range.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use while deleting information in the given range.
        :raises RollbackException: if the user cancelled the operation via the task monitor.
        """

    def getAddressMap(self) -> ghidra.program.database.map.AddressMapDB:
        """
        Returns this programs address map.
        NOTE: This method should be dropped from the :obj:`Program` interface to help
        discourage the its use external to this implementation since bad assumptions 
        are frequently made about address keys which may not be ordered or sequential
        across an entire address space.
        """

    def getCodeManager(self) -> ghidra.program.database.code.CodeManager:
        ...

    def getNamespaceManager(self) -> ghidra.program.database.symbol.NamespaceManager:
        ...

    def getStoredVersion(self) -> int:
        ...

    def getTreeManager(self) -> ghidra.program.database.module.TreeManager:
        ...

    def isLanguageUpgradePending(self) -> bool:
        """
        Determine if program initialization requires a language upgrade
        
        :return: true if language upgrade is pending
        :rtype: bool
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Moves all information stored in the given range to the new location
        
        :param ghidra.program.model.address.Address fromAddr: the first address in the range to be moved
        :param ghidra.program.model.address.Address toAddr: the address to move to
        :param jpype.JLong or int length: the number of addresses to move
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use while deleting information in the given range
        :raises AddressOverflowException: if there is a problem moving address ranges
        :raises RollbackException: if the user cancelled the operation via the task monitor
        """

    def programTreeAdded(self, id: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a program tree was added.
        
        :param jpype.JLong or int id: the id of the program tree that was added.
        :param ghidra.program.util.ProgramEvent eventType: the type of change
        :param java.lang.Object oldValue: old value is null
        :param java.lang.Object newValue: new value depends the tree that was added.
        """

    def programTreeChanged(self, id: typing.Union[jpype.JLong, int], eventType: ghidra.program.util.ProgramEvent, affectedObj: java.lang.Object, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a program tree was changed.
        
        :param jpype.JLong or int id: the id of the program tree that was changed.
        :param ghidra.program.util.ProgramEvent eventType: the :obj:`EventType` for this event
        :param java.lang.Object affectedObj: the object that was changed
        :param java.lang.Object oldValue: old value depends on the type of the change
        :param java.lang.Object newValue: old value depends on the type of the change
        """

    def setChanged(self, changeRecord: ghidra.program.util.ProgramChangeRecord):
        ...

    def setEffectiveImageBase(self, imageBase: ghidra.program.model.address.Address):
        ...

    def sourceArchiveAdded(self, sourceArchiveID: ghidra.util.UniversalID, eventType: ghidra.program.util.ProgramEvent):
        ...

    def sourceArchiveChanged(self, sourceArchiveID: ghidra.util.UniversalID, eventType: ghidra.program.util.ProgramEvent):
        ...

    def symbolAdded(self, symbol: ghidra.program.model.symbol.Symbol, eventType: ghidra.program.util.ProgramEvent, addr: ghidra.program.model.address.Address, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a symbol was added.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol that was added.
        :param ghidra.program.util.ProgramEvent eventType: the type of change
        :param ghidra.program.model.address.Address addr: the address of the symbol that added
        :param java.lang.Object oldValue: old value depends on the type of the change
        :param java.lang.Object newValue: old value depends on the type of the change
        """

    def symbolChanged(self, symbol: ghidra.program.model.symbol.Symbol, eventType: ghidra.program.util.ProgramEvent, addr: ghidra.program.model.address.Address, affectedObj: java.lang.Object, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a symbol was changed.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol that was changed.
        :param ghidra.program.util.ProgramEvent eventType: the type of change
        :param ghidra.program.model.address.Address addr: the address of the symbol that changed
        :param java.lang.Object affectedObj: the object that was changed
        :param java.lang.Object oldValue: old value depends on the type of the change
        :param java.lang.Object newValue: old value depends on the type of the change
        """

    def tagChanged(self, tag: ghidra.program.model.listing.FunctionTag, eventType: ghidra.program.util.ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that a :obj:`FunctionTag` was changed. This can be either an
        edit or a delete.
        
        :param ghidra.program.model.listing.FunctionTag tag: the tag that was changed.
        :param ghidra.program.util.ProgramEvent eventType: the type of change
        :param java.lang.Object oldValue: old value
        :param java.lang.Object newValue: new value
        """

    def tagCreated(self, tag: ghidra.program.model.listing.FunctionTag, eventType: ghidra.program.util.ProgramEvent):
        """
        Notification that a new :obj:`FunctionTag` was created.
        
        :param ghidra.program.model.listing.FunctionTag tag: the tag that was created.
        :param ghidra.program.util.ProgramEvent eventType: the type of change
        """

    @property
    def treeManager(self) -> ghidra.program.database.module.TreeManager:
        ...

    @property
    def addressMap(self) -> ghidra.program.database.map.AddressMapDB:
        ...

    @property
    def languageUpgradePending(self) -> jpype.JBoolean:
        ...

    @property
    def codeManager(self) -> ghidra.program.database.code.CodeManager:
        ...

    @property
    def namespaceManager(self) -> ghidra.program.database.symbol.NamespaceManager:
        ...

    @property
    def storedVersion(self) -> jpype.JInt:
        ...


class ProjectDataTypeManager(ghidra.program.model.data.StandAloneDataTypeManager, ghidra.program.model.data.ProjectArchiveBasedDataTypeManager):
    """
    Class for managing data types in a project archive
    NOTE: default data organization is used.
    """

    class_: typing.ClassVar[java.lang.Class]

    def archiveReady(self, openMode: ghidra.framework.data.OpenMode, monitor: ghidra.util.task.TaskMonitor):
        ...


class ProgramMultiUserMergeManagerFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getMergeManager(resultsObj: ghidra.framework.model.DomainObject, sourceObj: ghidra.framework.model.DomainObject, originalObj: ghidra.framework.model.DomainObject, latestObj: ghidra.framework.model.DomainObject) -> ghidra.framework.data.DomainObjectMergeManager:
        ...


@typing.type_check_only
class DataTypeArchiveDBChangeSet(ghidra.program.model.listing.DataTypeArchiveChangeSet, ghidra.framework.data.DomainObjectDBChangeSet):
    """
    Holds changes made to a data type archive.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numUndos: typing.Union[jpype.JInt, int]):
        """
        Construct a new DataTypeArchiveChangeSet.
        
        :param addrMap: the address map.:param jpype.JInt or int numUndos: the number of undo change sets to track.
        """


class IntRangeMapDB(IntRangeMap):

    class_: typing.ClassVar[java.lang.Class]
    TABLE_PREFIX: typing.Final = "Range Map - IntMap - "

    @staticmethod
    def createPropertyMap(program: ProgramDB, mapName: typing.Union[java.lang.String, str], errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock) -> IntRangeMapDB:
        ...

    def delete(self):
        ...

    @staticmethod
    def getPropertyMap(program: ProgramDB, mapName: typing.Union[java.lang.String, str], errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock) -> IntRangeMapDB:
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move the address range to a new starting address.
        
        :param ghidra.program.model.address.Address fromAddr: move from address
        :param ghidra.program.model.address.Address toAddr: move to address
        :param jpype.JLong or int length: number of address to move
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """


class ProgramAddressFactory(ghidra.program.model.address.DefaultAddressFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, overlayRegionSupplier: OverlayRegionSupplier):
        """
        Construct a Program address factory which augments the :obj:`DefaultAddressFactory` 
        supplied by a :obj:`Language`.  The following additional address spaces are added:
         
        * :obj:`AddressSpace.OTHER_SPACE`
        * :obj:`AddressSpace.EXTERNAL_SPACE`
        * A stack space (see :obj:`AddressSpace.TYPE_STACK`)
        * :obj:`AddressSpace.HASH_SPACE`
        * A join space (see :obj:`AddressSpace.TYPE_JOIN`)
        
        In addition, support is provided for :obj:`ProgramOverlayAddressSpace`.
        
        :param ghidra.program.model.lang.Language language: language specification
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: compiler specification
        :param OverlayRegionSupplier overlayRegionSupplier: overlay space defined region supplier which will be invoked when 
        specific queries are performed on overlay address spaces.  If memory is not yet available 
        a null AddressSet may be returned by the supplier.
        """

    def checkValidOverlaySpaceName(self, name: typing.Union[java.lang.String, str]):
        ...

    def invalidateOverlayCache(self):
        ...


class DataTypeArchiveLinkContentHandler(ghidra.framework.data.LinkHandler[DataTypeArchiveDB]):

    class_: typing.ClassVar[java.lang.Class]
    ARCHIVE_LINK_CONTENT_TYPE: typing.Final = "ArchiveLink"

    def __init__(self):
        ...


@typing.type_check_only
class ListingDB(ghidra.program.model.listing.Listing):
    """
    Database implementation of Listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setProgram(self, program: ProgramDB):
        ...


class DBObjectCache(java.lang.Object, typing.Generic[T]):
    """
    Generic cache implementation for objects that extend DatabaseObject. This is a reference based
    cache such that objects are only ever automatically removed from the cache when there are no
    references to that object. It also maintains a small "hard" cache so that recently accessed objects
    are not prematurely removed from the cache if there are no references to them.
    """

    @typing.type_check_only
    class KeyedSoftReference(java.lang.ref.WeakReference[T], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hardCacheSize: typing.Union[jpype.JInt, int]):
        """
        Constructs a new DBObjectCache with a given hard cache size.  The hard cache size is
        the minimum number of objects to keep in the cache. Typically, the cache will contain
        more than this number, but the excess objects are subject to garbage collections
        
        :param jpype.JInt or int hardCacheSize: the minimum number of objects to keep in the cache.
        """

    @typing.overload
    def delete(self, keyRanges: java.util.List[ghidra.program.model.address.KeyRange]):
        """
        Delete all objects from HashMap whose key is contained
        within the specified keyRanges.
        
        :param java.util.List[ghidra.program.model.address.KeyRange] keyRanges: key ranges to delete
        """

    @typing.overload
    def delete(self, key: typing.Union[jpype.JLong, int]):
        """
        Removes the object with the given key from the cache.
        
        :param jpype.JLong or int key: the key of the object to remove.
        """

    @typing.overload
    def get(self, key: typing.Union[jpype.JLong, int]) -> T:
        """
        Retrieves the database object with the given key from the cache.
        
        :param jpype.JLong or int key: the key of the object to retrieve.
        :return: the cached object or null if the object with that key is not currently cached.
        :rtype: T
        """

    @typing.overload
    def get(self, objectRecord: db.DBRecord) -> T:
        """
        Retrieves the database object with the given record and associated key from the cache.
        This form should be used in conjunction with record iterators to avoid unnecessary
        record query during a possible object refresh.  To benefit from the record the cached
        object must implement the :meth:`DatabaseObject.refresh(DBRecord) <DatabaseObject.refresh>` method which by default
        ignores the record and simply calls :meth:`DatabaseObject.refresh() <DatabaseObject.refresh>`.
        
        :param db.DBRecord objectRecord: the valid record corresponding to the object to be retrieved and possibly
        used to refresh the associated object if found in cache
        :return: the cached object or null if the object with that key is not currently cached.
        :rtype: T
        """

    def getCachedObjects(self) -> java.util.List[T]:
        """
        Returns an List of all the cached objects.
        
        :return: an List of all the cached objects.
        :rtype: java.util.List[T]
        """

    def invalidate(self):
        """
        Marks all the cached objects as invalid.  Invalid objects will have to refresh themselves
        before they are allowed to be used. If an invalidated object cannot refresh itself, then
        the object is removed from the cache and discarded and the application can no longer use
        that instance of the object.
        """

    def keyChanged(self, oldKey: typing.Union[jpype.JLong, int], newKey: typing.Union[jpype.JLong, int]):
        ...

    def setHardCacheSize(self, size: typing.Union[jpype.JInt, int]):
        """
        Sets the number of objects to protect against garbage collection.
        
        :param jpype.JInt or int size: the minimum number of objects to keep in the cache.
        """

    def size(self) -> int:
        """
        Returns the number of objects currently in the cache.
        
        :return: the number of objects currently in the cache.
        :rtype: int
        """

    @property
    def cachedObjects(self) -> java.util.List[T]:
        ...


@typing.type_check_only
class MyChangeDiff(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OverlaySpaceDBAdapterV0(OverlaySpaceDBAdapter):

    @typing.type_check_only
    class V0ConvertedRecordIterator(db.ConvertedRecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class IntRangeMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def clearAll(self):
        ...

    @typing.overload
    def clearValue(self, addresses: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def clearValue(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def getAddressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @typing.overload
    def getAddressSet(self, value: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.AddressSet:
        ...

    def getValue(self, address: ghidra.program.model.address.Address) -> int:
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def setValue(self, addresses: ghidra.program.model.address.AddressSetView, value: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def setValue(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, value: typing.Union[jpype.JInt, int]):
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class ProgramLinkContentHandler(ghidra.framework.data.LinkHandler[ProgramDB]):

    class_: typing.ClassVar[java.lang.Class]
    PROGRAM_LINK_CONTENT_TYPE: typing.Final = "ProgramLink"

    def __init__(self):
        ...


class ProgramOverlayAddressSpace(ghidra.program.model.address.OverlayAddressSpace):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, key: typing.Union[jpype.JLong, int], overlayName: typing.Union[java.lang.String, str], baseSpace: ghidra.program.model.address.AddressSpace, unique: typing.Union[jpype.JInt, int], overlayRegionSupplier: OverlayRegionSupplier, factory: ProgramAddressFactory):
        """
        
        
        :param jpype.JLong or int key: DB record key
        :param java.lang.String or str overlayName: current overlay name
        :param ghidra.program.model.address.AddressSpace baseSpace: base address space (type should be restricted as neccessary by caller)
        :param jpype.JInt or int unique: assigned unique ID
        :param OverlayRegionSupplier overlayRegionSupplier: callback handler which supplies the defined address set 
        for a specified overlay address space.
        :param ProgramAddressFactory factory: used to determine a suitable ordered overlay ordered-key used for
        :meth:`equals(Object) <.equals>` and :meth:`compareTo(AddressSpace) <.compareTo>`.
        :raises DuplicateNameException: if specified name duplicates an existing address space name
        """

    def getKey(self) -> int:
        """
        Get the DB record key used to store this overlay specification.
        This is intended to be used internally to reconcile address spaces only.
        
        :return: DB record key
        :rtype: int
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Method to support renaming an overlay address space instance.  Intended for internal use only.
        
        :param java.lang.String or str name: new overlay space name
        """

    @property
    def key(self) -> jpype.JLong:
        ...


@typing.type_check_only
class OverlaySpaceDBAdapterV1(OverlaySpaceDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SpecExtension(java.lang.Object):
    """
    Utility class for installing/removing "specification extensions" to a Program.
    A specification extension is a program specific version of either a:
     
    * Prototype Model
    * Call Fixup or
    * Callother Fixup
    
    Normally these objects are provided by the language specific configuration files (.cspec or .pspec),
    but this class allows additional objects to be added that are specific to the program.
     
    
    Internally, each spec extension is stored as an XML document as a formal Program Option. Each type of
    extension is described by a specific XML tag and is parsed as it would be in a .cspec or .pspec file.
    The XML tags are:
     
    * ``<callfixup>`` - describing a Call Fixup
    * ``<callotherfixup>`` - describing a Callother Fixup
    * ``<prototype>`` - describing a typical Prototype Model
    * ``<resolveprototype>`` - describing a Prototype Model merged from other models
    
    Each type of object has a unique name or target, which must be specified as part of the XML tag,
    which is referred to in this class as the extension's "formal name".  In the 
    ``<callotherfixup>`` tag, the formal name is given by the "targetop" attribute; for all the 
    other tags, the formal name is given by the "name" attribute".
     
    
    The parent option for all extensions is given by the static field SPEC_EXTENSION. Under the parent
    option, each extension is stored as a string with an option name, constructed by
    concatenating the extension's formal name with a prefix corresponding to the extension's XML tag name.
     
    
    testExtensionDocument() is used independently to extensively test whether a document
    describes a valid extension.
     
    
    Extensions are installed on a program via ``addReplaceCompilerSpecExtension()``.
    Extensions are removed from a program via ``removeCompilerSpecExtension()``.
    """

    class Type(java.lang.Enum[SpecExtension.Type]):
        """
        The possible types of spec extensions.
        """

        class_: typing.ClassVar[java.lang.Class]
        PROTOTYPE_MODEL: typing.Final[SpecExtension.Type]
        MERGE_MODEL: typing.Final[SpecExtension.Type]
        CALL_FIXUP: typing.Final[SpecExtension.Type]
        CALLOTHER_FIXUP: typing.Final[SpecExtension.Type]

        def getOptionName(self, formalName: typing.Union[java.lang.String, str]) -> str:
            """
            For a given extension's formal name, generate the option name used to store the extension.
            The option name is the tag name concatenated with the formal name, separated by '_'
            
            :param java.lang.String or str formalName: is the formal name of the extension
            :return: the option name
            :rtype: str
            """

        def getTagName(self) -> str:
            """
            Get the XML tag name associated with the specific extension type.
            
            :return: the tag name
            :rtype: str
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SpecExtension.Type:
            ...

        @staticmethod
        def values() -> jpype.JArray[SpecExtension.Type]:
            ...

        @property
        def tagName(self) -> java.lang.String:
            ...

        @property
        def optionName(self) -> java.lang.String:
            ...


    class DocInfo(java.lang.Object):
        """
        Helper class for collecting information about an extension XML document
        and constructing its option name for storage
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, document: typing.Union[java.lang.String, str]):
            """
            Construct by directly pulling information from the XML document
            
            :param java.lang.String or str document: is the entire XML document as a String
            """

        def getFormalName(self) -> str:
            """
            
            
            :return: the formal name of the extension
            :rtype: str
            """

        def getOptionName(self) -> str:
            """
            
            
            :return: the option name associated with the extension
            :rtype: str
            """

        def getType(self) -> SpecExtension.Type:
            """
            
            
            :return: the Type of the extension
            :rtype: SpecExtension.Type
            """

        def isOverride(self) -> bool:
            """
            
            
            :return: true if the extension overrides a core object
            :rtype: bool
            """

        @property
        def formalName(self) -> java.lang.String:
            ...

        @property
        def override(self) -> jpype.JBoolean:
            ...

        @property
        def type(self) -> SpecExtension.Type:
            ...

        @property
        def optionName(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]
    SPEC_EXTENSION: typing.Final = "Specification Extensions"
    FORMAT_VERSION_OPTIONNAME: typing.Final = "FormatVersion"
    VERSION_COUNTER_OPTIONNAME: typing.Final = "VersionCounter"
    FORMAT_VERSION: typing.Final = 1

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct an extension manager attached to a specific program.
        Multiple add/remove/test actions can be performed.  Validator state is cached between calls.
        
        :param ghidra.program.model.listing.Program program: is the specific Program
        """

    def addReplaceCompilerSpecExtension(self, document: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Install or replace a spec extension to the program.  The extension is presented as
        an XML document, from which a name is extracted.  If an extension previously existed
        with the same name, it is overwritten.  Otherwise the document is treated as a new
        extension.  Testing is performed before installation:
            - Document is parsed as XML and is verified against spec grammars
            - Internal p-code tags from InjectPayloads are compiled
            - Name collisions are checked for
        
        :param java.lang.String or str document: is the XML document describing the extension
        :param ghidra.util.task.TaskMonitor monitor: is a task monitor
        :raises LockException: if the caller does not exclusive access to the program
        :raises XmlParseException: for a badly formed extension document
        :raises SAXException: for parse errors in the extension document
        :raises SleighException: for a document that fails verification
        """

    @staticmethod
    def checkFormatVersion(program: ghidra.program.model.listing.Program):
        """
        Check the format version for spec extensions for a given program.
        If the program reports a version that does not match the current
        number attached to the running tool (FORMAT_VERSION), a VersionException is thrown
        
        :param ghidra.program.model.listing.Program program: is the given Program
        :raises VersionException: the reported version does not match the tool
        """

    @staticmethod
    def getCompilerSpecExtension(program: ghidra.program.model.listing.Program, type: SpecExtension.Type, name: typing.Union[java.lang.String, str]) -> str:
        """
        Get the raw string making up an extension, given its type and name
        
        :param ghidra.program.model.listing.Program program: is the program to extract the extension from
        :param SpecExtension.Type type: is the type of extension
        :param java.lang.String or str name: is the formal name of the extension
        :return: the extension string or null
        :rtype: str
        """

    @staticmethod
    def getCompilerSpecExtensions(program: ghidra.program.model.listing.Program) -> java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]:
        """
        Get all compiler spec extensions for the program. The extensions are XML documents
        strings, with an associated "option name" string.
        Return a list of (optionname,document) pairs, which may be empty
        
        :param ghidra.program.model.listing.Program program: is the Program to get extensions for
        :return: the list of (optionname,document) pairs
        :rtype: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]
        """

    @staticmethod
    def getExtensionType(nm: typing.Union[java.lang.String, str], isXML: typing.Union[jpype.JBoolean, bool]) -> SpecExtension.Type:
        """
        Get the extension type either from the XML tag name or the option name
        
        :param java.lang.String or str nm: is the XML tag or option name
        :param jpype.JBoolean or bool isXML: is true for an XML tag, false for an option name
        :return: the extension type
        :rtype: SpecExtension.Type
        :raises SleighException: if no type matches the name
        """

    @staticmethod
    def getFormalName(optionName: typing.Union[java.lang.String, str]) -> str:
        """
        Get the formal name of an extension from its option name.
        
        :param java.lang.String or str optionName: is the option name
        :return: the formal name
        :rtype: str
        """

    @staticmethod
    def getVersionCounter(program: ghidra.program.model.listing.Program) -> int:
        """
        Get version of CompilerSpec extensions stored with the Program
        
        :param ghidra.program.model.listing.Program program: is the given Program
        :return: the version number
        :rtype: int
        """

    @staticmethod
    def isValidFormalName(formalName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the desired formal name is a valid identifier
        
        :param java.lang.String or str formalName: is the formal name to check
        :return: true if the name is valid
        :rtype: bool
        """

    @staticmethod
    def parseExtension(optionName: typing.Union[java.lang.String, str], extension: typing.Union[java.lang.String, str], cspec: ghidra.program.model.lang.CompilerSpec, provideDummy: typing.Union[jpype.JBoolean, bool]) -> java.lang.Object:
        """
        Parse an XML string and build the corresponding compiler spec extension object.
        Currently this can either be a
         
        * PrototypeModel
        * InjectPayload
        
         
        For InjectPayloadCallfixup or InjectPayloadCallother, the p-code ``<body>`` tag
        is also parsed, and the caller can control whether any parse errors
        cause an exception or whether a dummy payload is provided instead.
        
        :param java.lang.String or str optionName: is the option name the extension is attached to
        :param java.lang.String or str extension: is the XML document as a String
        :param ghidra.program.model.lang.CompilerSpec cspec: is the compiler spec the new extension is for
        :param jpype.JBoolean or bool provideDummy: if true, provide a dummy payload if necessary
        :return: the extension object
        :rtype: java.lang.Object
        :raises SAXException: is there are XML format errors
        :raises XmlParseException: if the XML document is badly formed
        :raises SleighException: if internal p-code does not parse
        """

    @staticmethod
    def registerOptions(program: ghidra.program.model.listing.Program):
        """
        Register the options system allowing spec extensions with the given Program
        
        :param ghidra.program.model.listing.Program program: is the given Program
        """

    def removeCompilerSpecExtension(self, optionName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Remove the indicated spec extension from the program.
        Depending on the type, references to the extension are removed or altered
        first, to facilitate final removal of the extension.
        All changes are made in a single transaction that can be cancelled.
        
        :param java.lang.String or str optionName: is the option name where the extension is stored
        :param ghidra.util.task.TaskMonitor monitor: is a provided monitor that can trigger cancellation
        :raises LockException: if the caller does not have exclusive access to the program
        :raises CancelledException: if the caller cancels the operation via the task monitor
        """

    def testExtensionDocument(self, document: typing.Union[java.lang.String, str]) -> SpecExtension.DocInfo:
        """
        Test if the given XML document describes a suitable spec extension.
        The document must fully parse and validate and must not conflict with the existing spec;
        otherwise an exception is thrown. If all tests pass, an object describing basic properties
        of the document is returned.
        
        :param java.lang.String or str document: is the given XML document
        :return: info about the document
        :rtype: SpecExtension.DocInfo
        :raises SleighException: if validity checks fail
        :raises XmlParseException: if the XML is badly formed
        :raises SAXException: if there are parse errors
        """


class ObsoleteProgramPropertiesService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getObsoleteProgramProperties() -> java.util.Map[java.lang.String, java.lang.String]:
        ...


class DataTypeArchiveMergeManagerFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getMergeManager(resultsObj: ghidra.framework.model.DomainObject, sourceObj: ghidra.framework.model.DomainObject, originalObj: ghidra.framework.model.DomainObject, latestObj: ghidra.framework.model.DomainObject) -> ghidra.framework.data.DomainObjectMergeManager:
        ...


class ProgramCompilerSpec(ghidra.program.model.lang.BasicCompilerSpec):
    """
    A Program-specific version of the :obj:`CompilerSpec`.
     
    Every :obj:`Program` owns a specific ``ProgramCompilerSpec``. It is based on a
    :obj:`CompilerSpec` returned by the :obj:`Language` assigned to the :obj:`Program`, but it may
    include extensions. Extensions are currently either a new form of:
     
     
    * :obj:`PrototypeModel` or
    * :obj:`InjectPayload`
    
     
    Extensions can be installed or removed from a :obj:`ProgramDB` via the :obj:`Options` mechanism
    (See :obj:`SpecExtension`) using
    :meth:`SpecExtension.addReplaceCompilerSpecExtension(String, TaskMonitor) <SpecExtension.addReplaceCompilerSpecExtension>` or
    :meth:`SpecExtension.removeCompilerSpecExtension(String, TaskMonitor) <SpecExtension.removeCompilerSpecExtension>`.
     
    ``ProgramCompilerSpec`` allows the static evaluation models, described by the underlying
    :obj:`BasicCompilerSpec` and returned by
    :meth:`getPrototypeEvaluationModel(EvaluationModelType) <.getPrototypeEvaluationModel>`, to be overridden by Program-specific
    options.
     
    :meth:`getDecompilerOutputLanguage() <.getDecompilerOutputLanguage>` queries the Program-specific language the decompiler
    should use as output.
     
    :meth:`installExtensions() <.installExtensions>` is the main entry point for integrating the Program Options with the
    Language's base CompilerSpec and producing a complete in-memory CompilerSpec for the Program.
    """

    class_: typing.ClassVar[java.lang.Class]
    DECOMPILER_PROPERTY_LIST_NAME: typing.Final = "Decompiler"
    DECOMPILER_OUTPUT_LANGUAGE: typing.Final = "Output Language"
    DECOMPILER_OUTPUT_DEF: typing.Final[ghidra.program.model.lang.DecompilerLanguage]
    DECOMPILER_OUTPUT_DESC: typing.Final = "Select the source language output by the decompiler."
    EVALUATION_MODEL_PROPERTY_NAME: typing.Final = "Prototype Evaluation"

    @staticmethod
    def enableJavaLanguageDecompilation(program: ghidra.program.model.listing.Program):
        """
        Adds and enables an option to have the decompiler display java.
        
        :param ghidra.program.model.listing.Program program: to be enabled
        """


class ProgramContentHandler(ghidra.framework.data.DBWithUserDataContentHandler[ProgramDB]):
    """
    ``ProgramContentHandler`` converts between Program instantiations
    and FolderItem storage.  This class also produces the appropriate Icon for 
    Program files.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROGRAM_CONTENT_TYPE: typing.Final = "Program"
    PROGRAM_ICON: typing.ClassVar[javax.swing.Icon]

    def __init__(self):
        ...


class DataTypeArchiveContentHandler(ghidra.framework.data.DBContentHandler[DataTypeArchiveDB]):
    """
    ``DataTypeArchiveContentHandler`` converts between DataTypeArchive instantiations
    and FolderItem storage.  This class also produces the appropriate Icon for 
    DataTypeArchive files.
    """

    class_: typing.ClassVar[java.lang.Class]
    DATA_TYPE_ARCHIVE_CONTENT_TYPE: typing.Final = "Archive"

    def __init__(self):
        ...


class DatabaseObject(java.lang.Object):
    """
    Base class for an cached object in the database. Database objects have keys. They are marked as
    invalid when a database cache is cleared and can be revived on a refresh as long as they haven't
    been deleted. Instantiating an object will cause it to be added immediately to the associated
    cache.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKey(self) -> int:
        """
        Get the database key for this object.
        """

    def isDeleted(self, lock: ghidra.util.Lock) -> bool:
        """
        Returns true if this object has been deleted. Note: once an object has been deleted, it will
        never be "refreshed". For example, if an object is ever deleted and is resurrected via an
        "undo", you will have get a fresh instance of the object.
        
        :param ghidra.util.Lock lock: object cache lock object
        :return: true if this object has been deleted.
        :rtype: bool
        """

    def setInvalid(self):
        """
        Invalidate this object. This does not necessarily mean that this object can never be used
        again. If the object can refresh itself, it may still be useable.
        """

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...



__all__ = ["GhidraDataTypeArchiveMergeManagerFactory", "GhidraProgramMultiUserMergeManagerFactory", "ProgramBuilder", "OverlayRegionSupplier", "DBStringMapAdapter", "OverlaySpaceDBAdapter", "ProgramDBChangeSet", "ChangeDiff", "DataTypeArchiveDB", "ProgramUserDataDB", "ManagerDB", "ProgramDB", "ProjectDataTypeManager", "ProgramMultiUserMergeManagerFactory", "DataTypeArchiveDBChangeSet", "IntRangeMapDB", "ProgramAddressFactory", "DataTypeArchiveLinkContentHandler", "ListingDB", "DBObjectCache", "MyChangeDiff", "OverlaySpaceDBAdapterV0", "IntRangeMap", "ProgramLinkContentHandler", "ProgramOverlayAddressSpace", "OverlaySpaceDBAdapterV1", "SpecExtension", "ObsoleteProgramPropertiesService", "DataTypeArchiveMergeManagerFactory", "ProgramCompilerSpec", "ProgramContentHandler", "DataTypeArchiveContentHandler", "DatabaseObject"]
