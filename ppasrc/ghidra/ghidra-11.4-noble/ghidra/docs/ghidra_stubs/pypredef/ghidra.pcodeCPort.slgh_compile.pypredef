from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra
import ghidra.pcodeCPort.opcodes
import ghidra.pcodeCPort.semantics
import ghidra.pcodeCPort.sleighbase
import ghidra.pcodeCPort.slghpatexpress
import ghidra.pcodeCPort.slghsymbol
import ghidra.pcodeCPort.space
import ghidra.pcodeCPort.translate
import ghidra.sleigh.grammar
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.apache.logging.log4j # type: ignore


class RtlPair(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    section: ghidra.pcodeCPort.semantics.ConstructTpl
    scope: ghidra.pcodeCPort.slghsymbol.SymbolScope

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, sec: ghidra.pcodeCPort.semantics.ConstructTpl, sc: ghidra.pcodeCPort.slghsymbol.SymbolScope):
        ...


@typing.type_check_only
class OptimizeRecord(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class StarQuality(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    def getId(self) -> ghidra.pcodeCPort.semantics.ConstTpl:
        ...

    def getSize(self) -> int:
        ...

    def setId(self, id: ghidra.pcodeCPort.semantics.ConstTpl):
        ...

    def setSize(self, size: typing.Union[jpype.JInt, int]):
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @size.setter
    def size(self, value: jpype.JInt):
        ...

    @property
    def id(self) -> ghidra.pcodeCPort.semantics.ConstTpl:
        ...

    @id.setter
    def id(self, value: ghidra.pcodeCPort.semantics.ConstTpl):
        ...


class PcodeCompile(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    log: typing.Final[org.apache.logging.log4j.Logger]
    noplist: generic.stl.VectorSTL[java.lang.String]

    def __init__(self):
        ...

    def addSymbol(self, sym: ghidra.pcodeCPort.slghsymbol.SleighSymbol):
        ...

    def addressOf(self, var: ghidra.pcodeCPort.semantics.VarnodeTpl, size: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def allocateTemp(self) -> int:
        ...

    def appendOp(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, res: ExprTree, constval: typing.Union[jpype.JLong, int], constsz: typing.Union[jpype.JInt, int]):
        ...

    def assignBitRange(self, location: ghidra.sleigh.grammar.Location, vn: ghidra.pcodeCPort.semantics.VarnodeTpl, bitoffset: typing.Union[jpype.JInt, int], numbits: typing.Union[jpype.JInt, int], rhs: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def buildTemporary(self, location: ghidra.sleigh.grammar.Location) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def buildTruncatedVarnode(self, loc: ghidra.sleigh.grammar.Location, basevn: ghidra.pcodeCPort.semantics.VarnodeTpl, bitoffset: typing.Union[jpype.JInt, int], numbits: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def createBitRange(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.SpecificSymbol, bitoffset: typing.Union[jpype.JInt, int], numbits: typing.Union[jpype.JInt, int]) -> ExprTree:
        ...

    def createCrossBuild(self, find: ghidra.sleigh.grammar.Location, v: ghidra.pcodeCPort.semantics.VarnodeTpl, second: ghidra.pcodeCPort.slghsymbol.SectionSymbol) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createLoad(self, location: ghidra.sleigh.grammar.Location, qual: StarQuality, ptr: ExprTree) -> ExprTree:
        ...

    def createMacroUse(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.MacroSymbol, param: generic.stl.VectorSTL[ExprTree]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        """
        Handle a sleigh 'macro' invocation, returning the resulting p-code op templates (OpTpl)
        
        :param ghidra.sleigh.grammar.Location location: is the file/line where the macro is invoked
        :param ghidra.pcodeCPort.slghsymbol.MacroSymbol sym: MacroSymbol is the macro symbol
        :param generic.stl.VectorSTL[ExprTree] param: is the parsed list of operand expressions
        :return: a list of p-code op templates
        :rtype: generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]
        """

    @typing.overload
    def createOp(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn: ExprTree) -> ExprTree:
        ...

    @typing.overload
    def createOp(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn1: ExprTree, vn2: ExprTree) -> ExprTree:
        ...

    def createOpConst(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, val: typing.Union[jpype.JLong, int]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def createOpNoOut(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def createOpNoOut(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn1: ExprTree, vn2: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createOpOut(self, location: ghidra.sleigh.grammar.Location, outvn: ghidra.pcodeCPort.semantics.VarnodeTpl, opc: ghidra.pcodeCPort.opcodes.OpCode, vn1: ExprTree, vn2: ExprTree) -> ExprTree:
        ...

    def createOpOutUnary(self, location: ghidra.sleigh.grammar.Location, outvn: ghidra.pcodeCPort.semantics.VarnodeTpl, opc: ghidra.pcodeCPort.opcodes.OpCode, vn: ExprTree) -> ExprTree:
        ...

    def createStore(self, location: ghidra.sleigh.grammar.Location, qual: StarQuality, ptr: ExprTree, val: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createUserOp(self, sym: ghidra.pcodeCPort.slghsymbol.UserOpSymbol, param: generic.stl.VectorSTL[ExprTree]) -> ExprTree:
        ...

    def createUserOpNoOut(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.UserOpSymbol, param: generic.stl.VectorSTL[ExprTree]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createVariadic(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, param: generic.stl.VectorSTL[ExprTree]) -> ExprTree:
        ...

    def defineLabel(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.LabelSymbol:
        ...

    @staticmethod
    def entry(name: typing.Union[java.lang.String, str], *args: java.lang.Object):
        ...

    def fillinZero(self, op: ghidra.pcodeCPort.semantics.OpTpl, ops: generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]):
        ...

    def finalNamedSection(self, vec: SectionVector, section: ghidra.pcodeCPort.semantics.ConstructTpl) -> SectionVector:
        ...

    def findInternalFunction(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str], operands: generic.stl.VectorSTL[ExprTree]) -> java.lang.Object:
        """
        EXTREMELY IMPORTANT: keep this up to date with isInternalFunction below!!! Lookup the given
        identifier as part of parsing p-code with functional syntax. Build the resulting p-code
        expression object from the parsed operand expressions.
        
        :param ghidra.sleigh.grammar.Location location: identifies the file/line where the p-code is parsed from
        :param java.lang.String or str name: is the given functional identifier
        :param generic.stl.VectorSTL[ExprTree] operands: is the ordered list of operand expressions
        :return: the new expression (ExprTree) object
        :rtype: java.lang.Object
        """

    def findSymbol(self, nm: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SleighSymbol:
        ...

    def firstNamedSection(self, main: ghidra.pcodeCPort.semantics.ConstructTpl, sym: ghidra.pcodeCPort.slghsymbol.SectionSymbol) -> SectionVector:
        ...

    def getConstantSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getDefaultSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getErrors(self) -> int:
        ...

    def getUniqueSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getWarnings(self) -> int:
        ...

    def isInternalFunction(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        EXTREMELY IMPORTANT: keep this up to date with findInternalFunction above!!! Determine if the
        given identifier is a sleigh internal function. Used to prevent user-defined p-code names
        from colliding with internal names
        
        :param java.lang.String or str name: is the given identifier to check
        :return: true if the identifier is a reserved internal function
        :rtype: bool
        """

    def matchSize(self, j: typing.Union[jpype.JInt, int], op: ghidra.pcodeCPort.semantics.OpTpl, inputonly: typing.Union[jpype.JBoolean, bool], ops: generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]):
        ...

    @typing.overload
    def newLocalDefinition(self, location: ghidra.sleigh.grammar.Location, varname: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def newLocalDefinition(self, location: ghidra.sleigh.grammar.Location, varname: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def newOutput(self, location: ghidra.sleigh.grammar.Location, usesLocalKey: typing.Union[jpype.JBoolean, bool], rhs: ExprTree, varname: typing.Union[java.lang.String, str]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def newOutput(self, location: ghidra.sleigh.grammar.Location, usesLocalKey: typing.Union[jpype.JBoolean, bool], rhs: ExprTree, varname: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def newSectionSymbol(self, where: ghidra.sleigh.grammar.Location, text: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SectionSymbol:
        ...

    def nextNamedSection(self, vec: SectionVector, section: ghidra.pcodeCPort.semantics.ConstructTpl, sym: ghidra.pcodeCPort.slghsymbol.SectionSymbol) -> SectionVector:
        ...

    def placeLabel(self, location: ghidra.sleigh.grammar.Location, labsym: ghidra.pcodeCPort.slghsymbol.LabelSymbol) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def propagateSize(self, ct: ghidra.pcodeCPort.semantics.ConstructTpl) -> bool:
        ...

    def recordNop(self, location: ghidra.sleigh.grammar.Location):
        ...

    def reportError(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str]):
        ...

    def reportWarning(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str]):
        ...

    def resetLabelCount(self):
        ...

    def setEnforceLocalKey(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setResultStarVarnode(self, ct: ghidra.pcodeCPort.semantics.ConstructTpl, star: StarQuality, vn: ghidra.pcodeCPort.semantics.VarnodeTpl) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def setResultVarnode(self, ct: ghidra.pcodeCPort.semantics.ConstructTpl, vn: ghidra.pcodeCPort.semantics.VarnodeTpl) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def standaloneSection(self, c: ghidra.pcodeCPort.semantics.ConstructTpl) -> SectionVector:
        ...

    @property
    def uniqueSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def warnings(self) -> jpype.JInt:
        ...

    @property
    def defaultSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def internalFunction(self) -> jpype.JBoolean:
        ...

    @property
    def constantSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def errors(self) -> jpype.JInt:
        ...


class SleighCompileLauncher(ghidra.GhidraLaunchable):
    """
    ``SleighCompileLauncher`` Sleigh compiler launch provider
    """

    class_: typing.ClassVar[java.lang.Class]
    FILE_IN_DEFAULT_EXT: typing.Final = ".slaspec"
    FILE_OUT_DEFAULT_EXT: typing.Final = ".sla"

    def __init__(self):
        ...

    @staticmethod
    def runMain(args: jpype.JArray[java.lang.String]) -> int:
        """
        Execute the Sleigh compiler process
        
        :param jpype.JArray[java.lang.String] args: sleigh compiler command line arguments
        :return: exit code (TODO: exit codes are not well defined)
        :rtype: int
        :raises IOException: for file access errors
        :raises RecognitionException: for parse errors
        """


class ExprTree(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, vn: ghidra.pcodeCPort.semantics.VarnodeTpl):
        ...

    @typing.overload
    def __init__(self, location: ghidra.sleigh.grammar.Location, op: ghidra.pcodeCPort.semantics.OpTpl):
        ...

    def setOutput(self, newLocation: ghidra.sleigh.grammar.Location, newout: ghidra.pcodeCPort.semantics.VarnodeTpl):
        ...

    @staticmethod
    def toVector(expr: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...


class FieldQuality(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[ghidra.sleigh.grammar.Location]
    name: java.lang.String
    low: jpype.JInt
    high: jpype.JInt
    signext: jpype.JBoolean
    flow: jpype.JBoolean
    hex: jpype.JBoolean

    def __init__(self, nm: typing.Union[java.lang.String, str], location: ghidra.sleigh.grammar.Location, l: typing.Union[jpype.JLong, int], h: typing.Union[jpype.JLong, int]):
        ...


class PreprocessorDefinitions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def lookup(self, key: typing.Union[java.lang.String, str]) -> generic.stl.Pair[java.lang.Boolean, java.lang.String]:
        ...

    def set(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    def undefine(self, key: typing.Union[java.lang.String, str]):
        ...


class ErrorWarningReporter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def reportError(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str]):
        ...

    def reportWarning(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str]):
        ...


class SemanticEnvironment(ghidra.pcodeCPort.sleighbase.NamedSymbolProvider, ghidra.pcodeCPort.translate.BasicSpaceProvider):

    class_: typing.ClassVar[java.lang.Class]

    def addressOf(self, var: ghidra.pcodeCPort.semantics.VarnodeTpl, size: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def assignBitRange(self, location: ghidra.sleigh.grammar.Location, vn: ghidra.pcodeCPort.semantics.VarnodeTpl, bitoffset: typing.Union[jpype.JInt, int], numbits: typing.Union[jpype.JInt, int], rhs: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createBitRange(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.SpecificSymbol, bitoffset: typing.Union[jpype.JInt, int], numbits: typing.Union[jpype.JInt, int]) -> ExprTree:
        ...

    def createLoad(self, location: ghidra.sleigh.grammar.Location, qual: StarQuality, ptr: ExprTree) -> ExprTree:
        ...

    def createMacroUse(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.MacroSymbol, param: generic.stl.VectorSTL[ExprTree]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def createOp(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn: ExprTree) -> ExprTree:
        ...

    @typing.overload
    def createOp(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn1: ExprTree, vn2: ExprTree) -> ExprTree:
        ...

    def createOpConst(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, val: typing.Union[jpype.JLong, int]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def createOpNoOut(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def createOpNoOut(self, location: ghidra.sleigh.grammar.Location, opc: ghidra.pcodeCPort.opcodes.OpCode, vn1: ExprTree, vn2: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createStore(self, location: ghidra.sleigh.grammar.Location, qual: StarQuality, ptr: ExprTree, val: ExprTree) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def createUserOp(self, sym: ghidra.pcodeCPort.slghsymbol.UserOpSymbol, param: generic.stl.VectorSTL[ExprTree]) -> ExprTree:
        ...

    def createUserOpNoOut(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.UserOpSymbol, param: generic.stl.VectorSTL[ExprTree]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def defineLabel(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.LabelSymbol:
        ...

    def findInternalFunction(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str], operands: generic.stl.VectorSTL[ExprTree]) -> java.lang.Object:
        ...

    @typing.overload
    def newOutput(self, location: ghidra.sleigh.grammar.Location, rhs: ExprTree, varname: typing.Union[java.lang.String, str]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    @typing.overload
    def newOutput(self, location: ghidra.sleigh.grammar.Location, rhs: ExprTree, varname: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def placeLabel(self, location: ghidra.sleigh.grammar.Location, labsym: ghidra.pcodeCPort.slghsymbol.LabelSymbol) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def recordNop(self, location: ghidra.sleigh.grammar.Location):
        ...

    def setResultStarVarnode(self, ct: ghidra.pcodeCPort.semantics.ConstructTpl, star: StarQuality, vn: ghidra.pcodeCPort.semantics.VarnodeTpl) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def setResultVarnode(self, ct: ghidra.pcodeCPort.semantics.ConstructTpl, vn: ghidra.pcodeCPort.semantics.VarnodeTpl) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...


class SpaceQuality(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    name: java.lang.String
    type: space_class
    size: jpype.JInt
    wordsize: jpype.JInt
    isdefault: jpype.JBoolean

    def __init__(self, nm: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class Yylval(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DirectoryVisitor(java.lang.Iterable[java.io.File]):

    @typing.type_check_only
    class BreadthFirstDirectoryVisitor(java.util.Iterator[java.io.File]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, startingDirectories: collections.abc.Sequence, directoryFilter: java.io.FileFilter, filter: java.io.FileFilter, compareCase: typing.Union[jpype.JBoolean, bool]):
            ...

        def hasNext(self) -> bool:
            ...

        def next(self) -> java.io.File:
            ...

        def remove(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startingDirectory: jpype.protocol.SupportsPath, filter: java.io.FileFilter):
        ...

    @typing.overload
    def __init__(self, startingDirectory: jpype.protocol.SupportsPath, filter: java.io.FileFilter, compareCase: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, startingDirectory: jpype.protocol.SupportsPath, directoryFilter: java.io.FileFilter, filter: java.io.FileFilter):
        ...

    @typing.overload
    def __init__(self, startingDirectory: jpype.protocol.SupportsPath, directoryFilter: java.io.FileFilter, filter: java.io.FileFilter, compareCase: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, startingDirectories: collections.abc.Sequence, filter: java.io.FileFilter):
        ...

    @typing.overload
    def __init__(self, startingDirectories: collections.abc.Sequence, filter: java.io.FileFilter, compareCase: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, startingDirectories: collections.abc.Sequence, directoryFilter: java.io.FileFilter, filter: java.io.FileFilter):
        ...

    @typing.overload
    def __init__(self, startingDirectories: collections.abc.Sequence, directoryFilter: java.io.FileFilter, filter: java.io.FileFilter, compareCase: typing.Union[jpype.JBoolean, bool]):
        ...

    def iterator(self) -> java.util.Iterator[java.io.File]:
        ...


class SleighCompile(ghidra.pcodeCPort.sleighbase.SleighBase):
    """
    ``SleighCompile`` provides the ability to compile Sleigh language module (e.g., *.slaspec)
    files.
    """

    @typing.type_check_only
    class WithBlock(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    pcode: typing.Final[PcodeCompile]

    def __init__(self):
        ...

    def addContextField(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.VarnodeSymbol, qual: FieldQuality) -> bool:
        ...

    def addTokenField(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.TokenSymbol, qual: FieldQuality):
        ...

    def addUserOp(self, names: generic.stl.VectorSTL[java.lang.String], locations: generic.stl.VectorSTL[ghidra.sleigh.grammar.Location]):
        ...

    def attachNames(self, symlist: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol], locations: generic.stl.VectorSTL[ghidra.sleigh.grammar.Location], names: generic.stl.VectorSTL[java.lang.String]):
        ...

    def attachValues(self, symlist: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol], locations: generic.stl.VectorSTL[ghidra.sleigh.grammar.Location], numlist: generic.stl.VectorSTL[java.lang.Long]):
        ...

    def attachVarnodes(self, symlist: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol], locations: generic.stl.VectorSTL[ghidra.sleigh.grammar.Location], varlist: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol]):
        ...

    def buildConstructor(self, big: ghidra.pcodeCPort.slghsymbol.Constructor, pateq: ghidra.pcodeCPort.slghpatexpress.PatternEquation, contvec: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange], vec: SectionVector):
        ...

    def buildMacro(self, sym: ghidra.pcodeCPort.slghsymbol.MacroSymbol, rtl: ghidra.pcodeCPort.semantics.ConstructTpl):
        ...

    def calcContextLayout(self):
        ...

    def compareMacroParams(self, sym: ghidra.pcodeCPort.slghsymbol.MacroSymbol, param: generic.stl.VectorSTL[ExprTree]):
        ...

    def constrainOperand(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.OperandSymbol, patexp: ghidra.pcodeCPort.slghpatexpress.PatternExpression) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def contextMod(self, vec: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange], sym: ghidra.pcodeCPort.slghsymbol.ContextSymbol, pe: ghidra.pcodeCPort.slghpatexpress.PatternExpression) -> bool:
        ...

    def contextSet(self, vec: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange], sym: ghidra.pcodeCPort.slghsymbol.TripleSymbol, cvar: ghidra.pcodeCPort.slghsymbol.ContextSymbol):
        ...

    def createConstructor(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.SubtableSymbol) -> ghidra.pcodeCPort.slghsymbol.Constructor:
        ...

    def createMacro(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str], params: generic.stl.VectorSTL[java.lang.String], locations: generic.stl.VectorSTL[ghidra.sleigh.grammar.Location]) -> ghidra.pcodeCPort.slghsymbol.MacroSymbol:
        ...

    def createMacroUse(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.MacroSymbol, param: generic.stl.VectorSTL[ExprTree]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def dedupSymbolList(self, symlist: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol]) -> ghidra.pcodeCPort.slghsymbol.SleighSymbol:
        ...

    def defineBitrange(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str], sym: ghidra.pcodeCPort.slghsymbol.VarnodeSymbol, bitoffset: typing.Union[jpype.JInt, int], numb: typing.Union[jpype.JInt, int]):
        ...

    def defineInvisibleOperand(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.TripleSymbol) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def defineOperand(self, location: ghidra.sleigh.grammar.Location, sym: ghidra.pcodeCPort.slghsymbol.OperandSymbol, patexp: ghidra.pcodeCPort.slghpatexpress.PatternExpression):
        ...

    def defineToken(self, location: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str], sz: typing.Union[jpype.JLong, int], endian: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.slghsymbol.TokenSymbol:
        ...

    def defineVarnodes(self, spacesym: ghidra.pcodeCPort.slghsymbol.SpaceSymbol, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], names: generic.stl.VectorSTL[java.lang.String], locations: generic.stl.VectorSTL[ghidra.sleigh.grammar.Location]):
        ...

    @staticmethod
    def entry(name: typing.Union[java.lang.String, str], *args: java.lang.Object):
        ...

    def getPreprocValue(self, nm: typing.Union[java.lang.String, str]) -> generic.stl.Pair[java.lang.Boolean, java.lang.String]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Run the sleigh compiler.  This provides a direct means of invoking the
        compiler without using the launcher.  The full SoftwareModeling classpath 
        must be established including any dependencies.
        
        :param jpype.JArray[java.lang.String] args: compiler command line arguments
        :raises IOException: for file access errors
        :raises RecognitionException: for parsing errors
        """

    def newOperand(self, location: ghidra.sleigh.grammar.Location, ct: ghidra.pcodeCPort.slghsymbol.Constructor, nm: typing.Union[java.lang.String, str]):
        ...

    def newSpace(self, location: ghidra.sleigh.grammar.Location, qual: SpaceQuality):
        ...

    def newTable(self, location: ghidra.sleigh.grammar.Location, nm: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SubtableSymbol:
        ...

    def numErrors(self) -> int:
        ...

    def numWarnings(self) -> int:
        ...

    def popWith(self):
        ...

    def pushWith(self, ss: ghidra.pcodeCPort.slghsymbol.SubtableSymbol, pateq: ghidra.pcodeCPort.slghpatexpress.PatternEquation, contvec: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange]):
        ...

    def recordNop(self, location: ghidra.sleigh.grammar.Location):
        ...

    @typing.overload
    def reportError(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def reportError(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str], t: java.lang.Throwable):
        ...

    def reportWarning(self, location: ghidra.sleigh.grammar.Location, msg: typing.Union[java.lang.String, str]):
        ...

    def run_compilation(self, filein: typing.Union[java.lang.String, str], fileout: typing.Union[java.lang.String, str]) -> int:
        ...

    def selfDefine(self, sym: ghidra.pcodeCPort.slghsymbol.OperandSymbol):
        ...

    def setAlignment(self, val: typing.Union[jpype.JInt, int]):
        ...

    def setAllNopWarning(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setAllOptions(self, preprocs: collections.abc.Mapping, unnecessaryPcodeWarning: typing.Union[jpype.JBoolean, bool], lenientConflict: typing.Union[jpype.JBoolean, bool], allCollisionWarning: typing.Union[jpype.JBoolean, bool], allNopWarning: typing.Union[jpype.JBoolean, bool], deadTempWarning: typing.Union[jpype.JBoolean, bool], unusedFieldWarning: typing.Union[jpype.JBoolean, bool], enforceLocalKeyWord: typing.Union[jpype.JBoolean, bool], largeTemporaryWarning: typing.Union[jpype.JBoolean, bool], caseSensitiveRegisterNames: typing.Union[jpype.JBoolean, bool], debugOutput: typing.Union[jpype.JBoolean, bool]):
        ...

    def setDeadTempWarning(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setDebugOutput(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setEndian(self, end: typing.Union[jpype.JInt, int]):
        ...

    def setEnforceLocalKeyWord(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setInsensitiveDuplicateError(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setLargeTemporaryWarning(self, val: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to print out warning info about
        :obj:`Constructor`s which reference varnodes in the
        unique space larger than :obj:`SleighBase.MAX_UNIQUE_SIZE`.
        
        :param jpype.JBoolean or bool val: whether to print info about contructors using large varnodes
        """

    def setLenientConflict(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setLocalCollisionWarning(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setPreprocValue(self, nm: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    def setUnnecessaryPcodeWarning(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setUnusedFieldWarning(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def undefinePreprocValue(self, nm: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def preprocValue(self) -> generic.stl.Pair[java.lang.Boolean, java.lang.String]:
        ...


@typing.type_check_only
class ConsistencyChecker(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cp: SleighCompile, rt: ghidra.pcodeCPort.slghsymbol.SubtableSymbol, unnecessary: typing.Union[jpype.JBoolean, bool], warndead: typing.Union[jpype.JBoolean, bool], warnlargetemp: typing.Union[jpype.JBoolean, bool]):
        ...

    def getNumLargeTemporaries(self) -> int:
        """
        Returns the number of constructors which reference a varnode in the
        unique space with size larger than :obj:`SleighBase.MAX_UNIQUE_SIZE`.
        
        :return: num constructors with large temp varnodes
        :rtype: int
        """

    def getNumReadNoWrite(self) -> int:
        ...

    def getNumUnnecessaryPcode(self) -> int:
        ...

    def getNumWriteNoRead(self) -> int:
        ...

    def optimizeAll(self):
        ...

    def testLargeTemporary(self):
        ...

    def testSizeRestrictions(self) -> bool:
        ...

    def testTruncations(self) -> bool:
        ...

    @property
    def numUnnecessaryPcode(self) -> jpype.JInt:
        ...

    @property
    def numLargeTemporaries(self) -> jpype.JInt:
        ...

    @property
    def numWriteNoRead(self) -> jpype.JInt:
        ...

    @property
    def numReadNoWrite(self) -> jpype.JInt:
        ...


class SleighCompilePreprocessorDefinitionsAdapater(PreprocessorDefinitions):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sleighCompile: SleighCompile):
        ...

    def lookup(self, key: typing.Union[java.lang.String, str]) -> generic.stl.Pair[java.lang.Boolean, java.lang.String]:
        ...

    def set(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    def undefine(self, key: typing.Union[java.lang.String, str]):
        ...


class Token(Yylval):
    """
    Describes the input token stream.
    """

    class_: typing.ClassVar[java.lang.Class]
    kind: jpype.JInt
    """
    An integer that describes the kind of this token.  This numbering
    system is determined by JavaCCParser, and a table of these numbers is
    stored in the file ...Constants.java.
    """

    beginLine: jpype.JInt
    """
    beginLine and beginColumn describe the position of the first character
    of this token; endLine and endColumn describe the position of the
    last character of this token.
    """

    beginColumn: jpype.JInt
    """
    beginLine and beginColumn describe the position of the first character
    of this token; endLine and endColumn describe the position of the
    last character of this token.
    """

    endLine: jpype.JInt
    """
    beginLine and beginColumn describe the position of the first character
    of this token; endLine and endColumn describe the position of the
    last character of this token.
    """

    endColumn: jpype.JInt
    """
    beginLine and beginColumn describe the position of the first character
    of this token; endLine and endColumn describe the position of the
    last character of this token.
    """

    image: java.lang.String
    """
    The string image of the token.
    """

    next: Token
    """
    A reference to the next regular (non-special) token from the input
    stream.  If this is the last token from the input stream, or if the
    token manager has not read tokens beyond this one, this field is
    set to null.  This is true only if this token is also a regular
    token.  Otherwise, see below for a description of the contents of
    this field.
    """

    specialToken: Token
    """
    This field is used to access special tokens that occur prior to this
    token, but after the immediately preceding regular (non-special) token.
    If there are no such special tokens, this field is set to null.
    When there are more than one such special token, this field refers
    to the last of these special tokens, which in turn refers to the next
    previous special token through its specialToken field, and so on
    until the first special token (whose specialToken field is null).
    The next fields of special tokens refer to other special tokens that
    immediately follow it (without an intervening regular token).  If there
    is no such token, this field is null.
    """


    def __init__(self):
        ...

    @staticmethod
    def newToken(ofKind: typing.Union[jpype.JInt, int]) -> Token:
        """
        Returns a new Token object, by default. However, if you want, you
        can create and return subclass objects based on the value of ofKind.
        Simply add the cases to the switch for all those special cases.
        For example, if you have a subclass of Token called IDToken that
        you want to create if ofKind is ID, simlpy add something like :
        
            case MyParserConstants.ID : return new IDToken();
        
        to the following switch statement. Then you can cast matchedToken
        variable to the appropriate type and use it in your lexical actions.
        """

    def toString(self) -> str:
        """
        Returns the image.
        """


class MacroBuilder(ghidra.pcodeCPort.semantics.PcodeBuilder):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sl: SleighCompile, loc: ghidra.sleigh.grammar.Location, ovec: generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl], lbcnt: typing.Union[jpype.JInt, int]):
        ...

    def hasError(self) -> bool:
        ...

    def setMacroOp(self, macroop: ghidra.pcodeCPort.semantics.OpTpl):
        ...


class ParseException(java.lang.Exception):
    """
    This exception is thrown when parse errors are encountered.
    You can explicitly create objects of this exception type by
    calling the method generateParseException in the generated
    parser.
    
    You can modify this class to customize your error reporting
    mechanisms so long as you retain the public fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    currentToken: Token
    """
    This is the last token that has been consumed successfully.  If
    this object has been created due to a parse error, the token
    followng this token will (therefore) be the first error token.
    """

    expectedTokenSequences: jpype.JArray[jpype.JArray[jpype.JInt]]
    """
    Each entry in this array is an array of integers.  Each array
    of integers represents a sequence of tokens (by their ordinal
    values) that is expected at this point of the parse.
    """

    tokenImage: jpype.JArray[java.lang.String]
    """
    This is a reference to the "tokenImage" array of the generated
    parser within which the parse error occurred.  This array is
    defined in the generated ...Constants interface.
    """


    @typing.overload
    def __init__(self, currentTokenVal: Token, expectedTokenSequencesVal: jpype.JArray[jpype.JArray[jpype.JInt]], tokenImageVal: jpype.JArray[java.lang.String]):
        """
        This constructor is used by the method "generateParseException"
        in the generated parser.  Calling this constructor generates
        a new object of this type with the fields "currentToken",
        "expectedTokenSequences", and "tokenImage" set.  The boolean
        flag "specialConstructor" is also set to true to indicate that
        this constructor was used to create this object.
        This constructor calls its super class with the empty string
        to force the "toString" method of parent class "Throwable" to
        print the error message in the form:
            ``ParseException: <result of getMessage>``
        """

    @typing.overload
    def __init__(self):
        """
        The following constructors are for use by you for whatever
        purpose you can think of.  Constructing the exception in this
        manner makes the exception behave in the normal way - i.e., as
        documented in the class "Throwable".  The fields "errorToken",
        "expectedTokenSequences", and "tokenImage" do not contain
        relevant information.  The JavaCC generated code does not use
        these constructors.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    def getMessage(self) -> str:
        """
        This method has the standard behavior when this object has been
        created using the standard constructors.  Otherwise, it uses
        "currentToken" and "expectedTokenSequences" to generate a parse
        error message and returns it.  If this object has been created
        due to a parse error, and you do not catch it (it gets thrown
        from the parser), then this method is called during the printing
        of the final stack trace, and hence the correct error message
        gets displayed.
        """

    @property
    def message(self) -> java.lang.String:
        ...


class space_class(java.lang.Enum[space_class]):

    class_: typing.ClassVar[java.lang.Class]
    ram_space: typing.Final[space_class]
    register_space: typing.Final[space_class]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> space_class:
        ...

    @staticmethod
    def values() -> jpype.JArray[space_class]:
        ...


@typing.type_check_only
class FieldContext(java.lang.Comparable[FieldContext]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SectionVector(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rtl: ghidra.pcodeCPort.semantics.ConstructTpl, scope: ghidra.pcodeCPort.slghsymbol.SymbolScope):
        ...

    def append(self, rtl: ghidra.pcodeCPort.semantics.ConstructTpl, scope: ghidra.pcodeCPort.slghsymbol.SymbolScope):
        ...

    def getMainPair(self) -> RtlPair:
        ...

    def getMainSection(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def getMaxId(self) -> int:
        ...

    def getNamedPair(self, i: typing.Union[jpype.JInt, int]) -> RtlPair:
        ...

    def getNamedSection(self, index: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def setNextIndex(self, i: typing.Union[jpype.JInt, int]):
        ...

    @property
    def namedPair(self) -> RtlPair:
        ...

    @property
    def maxId(self) -> jpype.JInt:
        ...

    @property
    def mainSection(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    @property
    def namedSection(self) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    @property
    def mainPair(self) -> RtlPair:
        ...



__all__ = ["RtlPair", "OptimizeRecord", "StarQuality", "PcodeCompile", "SleighCompileLauncher", "ExprTree", "FieldQuality", "PreprocessorDefinitions", "ErrorWarningReporter", "SemanticEnvironment", "SpaceQuality", "Yylval", "DirectoryVisitor", "SleighCompile", "ConsistencyChecker", "SleighCompilePreprocessorDefinitionsAdapater", "Token", "MacroBuilder", "ParseException", "space_class", "FieldContext", "SectionVector"]
