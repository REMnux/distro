from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import generic.jar
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.app.plugin.processors.sleigh.pattern
import ghidra.app.plugin.processors.sleigh.symbol
import ghidra.app.plugin.processors.sleigh.template
import ghidra.framework.options
import ghidra.pcodeCPort.slgh_compile
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.sleigh.grammar
import ghidra.util.task
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import org.xml.sax # type: ignore


class PcodeEmitObjects(PcodeEmit):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, walk: ParserWalker):
        """
        Pcode emitter constructor for producing PcodeOp objects for unimplemented, snippets or empty responses
        when :meth:`getFallOffset() <.getFallOffset>` will not be used.
        
        :param ParserWalker walk: state of the ParserContext from which to generate p-code
        """

    @typing.overload
    def __init__(self, walk: ParserWalker, fallOffset: typing.Union[jpype.JInt, int]):
        """
        Pcode emitter constructor for producing PcodeOp objects for unimplemented, snippets or empty responses.
        
        :param ParserWalker walk: state of the ParserContext from which to generate p-code
        :param jpype.JInt or int fallOffset: default fall-through offset (i.e., the full length 
        of instruction including delay-sloted instructions)
        """

    @typing.overload
    def __init__(self, walk: ParserWalker, ictx: ghidra.program.model.lang.InstructionContext, fallOffset: typing.Union[jpype.JInt, int], override: ghidra.program.model.pcode.PcodeOverride):
        """
        
        
        :param ParserWalker walk: state of the ParserContext from which to generate p-code
        :param ghidra.program.model.lang.InstructionContext ictx: is the InstructionContext used to resolve delayslot and crossbuild directives
        :param jpype.JInt or int fallOffset: default instruction fall offset (i.e., instruction length including delay slotted instructions)
        :param ghidra.program.model.pcode.PcodeOverride override: required if pcode overrides are to be utilized
        """

    def getPcodeOp(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        ...

    @property
    def pcodeOp(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        ...


class ModuleDefinitionsMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getModuleMap() -> java.util.Map[java.lang.String, java.lang.String]:
        ...


class ParserWalker(java.lang.Object):
    """
    Class for walking the Sleigh Parser tree.  The nodes of the tree are the Sleigh Constructors arranged for a particular
    instruction.  This tree is walked for various purposes:
     
    * SleighInstructionPrototype.resolve        - initial parsing of instruction and building the tree
    * SleighInstructionPrototype.resolveHandles - filling in Varnode values for all the Constructor exports
    * PcodeEmit                                 - for weaving together p-code for an instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, c: SleighParserContext):
        ...

    @typing.overload
    def __init__(self, c: SleighParserContext, cross: SleighParserContext):
        """
        For use with pcode cross-build
        
        :param SleighParserContext c: context
        :param SleighParserContext cross: cross context
        """

    def allocateOperand(self):
        ...

    def baseState(self):
        """
        Initialize a walk of the tree
        """

    def calcCurrentLength(self, minLength: typing.Union[jpype.JInt, int], numopers: typing.Union[jpype.JInt, int]):
        """
        Calculate the length of the current constructor state
        assuming all its operands are constructed
        """

    def getAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getConstSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getConstructor(self) -> Constructor:
        """
        
        
        :return: the Constructor for the current node in the walk
        :rtype: Constructor
        """

    def getContextBits(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getContextBytes(self, byteoff: typing.Union[jpype.JInt, int], numbytes: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getCurSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getCurrentLength(self) -> int:
        ...

    def getCurrentSubtableName(self) -> str:
        ...

    def getFixedHandle(self, i: typing.Union[jpype.JInt, int]) -> FixedHandle:
        ...

    def getFlowDestAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getFlowRefAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getInstructionBits(self, startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getInstructionBytes(self, byteoff: typing.Union[jpype.JInt, int], numbytes: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getN2addr(self) -> ghidra.program.model.address.Address:
        ...

    def getNaddr(self) -> ghidra.program.model.address.Address:
        ...

    def getOffset(self, i: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the offset into the instruction for the current node (i=-1) or one of the current node's children
        
        :param jpype.JInt or int i: selects the desired child of the current node
        :return: the offset (in bytes) for the selected node
        :rtype: int
        """

    def getOperand(self) -> int:
        """
        Find the next child that needs to be traversed
        
        :return: the index of the child
        :rtype: int
        """

    def getParentHandle(self) -> FixedHandle:
        ...

    def getParserContext(self) -> SleighParserContext:
        ...

    def getState(self) -> ConstructState:
        ...

    def isState(self) -> bool:
        """
        Are we at the end of the tree walk
        
        :return: true if there is more walk to go
        :rtype: bool
        """

    def popOperand(self):
        """
        Move to the parent of the current node
        """

    def pushOperand(self, i: typing.Union[jpype.JInt, int]):
        """
        Move down to a particular child of the current node.  Store what would be the next sibling to walk
        
        :param jpype.JInt or int i: is the index of the desired child
        """

    def setConstructor(self, ct: Constructor):
        ...

    def setCurrentLength(self, len: typing.Union[jpype.JInt, int]):
        ...

    def setOffset(self, off: typing.Union[jpype.JInt, int]):
        ...

    def setOutOfBandState(self, ct: Constructor, index: typing.Union[jpype.JInt, int], tempstate: ConstructState, otherwalker: ParserWalker):
        ...

    def snippetState(self):
        """
        Create state suitable for parsing a just a p-code semantics snippet
        """

    def subTreeState(self, subtree: ConstructState):
        ...

    @property
    def fixedHandle(self) -> FixedHandle:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @offset.setter
    def offset(self, value: jpype.JInt):
        ...

    @property
    def naddr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def constructor(self) -> Constructor:
        ...

    @constructor.setter
    def constructor(self, value: Constructor):
        ...

    @property
    def currentSubtableName(self) -> java.lang.String:
        ...

    @property
    def flowDestAddr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def currentLength(self) -> jpype.JInt:
        ...

    @currentLength.setter
    def currentLength(self, value: jpype.JInt):
        ...

    @property
    def flowRefAddr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def n2addr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def state(self) -> ConstructState:
        ...

    @property
    def constSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def addr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def parserContext(self) -> SleighParserContext:
        ...

    @property
    def parentHandle(self) -> FixedHandle:
        ...

    @property
    def curSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def operand(self) -> jpype.JInt:
        ...


class ModuleDefinitionsAdapter(ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PcodeEmit(java.lang.Object):
    """
    Class for converting ConstructTpl into a pcode ops given
    a particular InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, walk: ParserWalker, ictx: ghidra.program.model.lang.InstructionContext, fallOffset: typing.Union[jpype.JInt, int], override: ghidra.program.model.pcode.PcodeOverride):
        """
        Pcode emitter constructor
        
        :param ParserWalker walk: is the ParserWalker state for the tree that needs to be walked to generate pcode
        :param ghidra.program.model.lang.InstructionContext ictx: is the InstructionContext interface to resolve requests for context
        :param jpype.JInt or int fallOffset: default instruction fall offset (i.e., instruction length including delay slotted instructions)
        :param ghidra.program.model.pcode.PcodeOverride override: required if pcode overrides are to be utilized
        """

    def build(self, construct: ghidra.app.plugin.processors.sleigh.template.ConstructTpl, secnum: typing.Union[jpype.JInt, int]):
        ...

    def getFallOffset(self) -> int:
        ...

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getWalker(self) -> ParserWalker:
        ...

    def resolveRelatives(self):
        """
        Now that we have seen all label templates and references
        convert the collected references into full relative
        addresses
        """

    @property
    def fallOffset(self) -> jpype.JInt:
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def walker(self) -> ParserWalker:
        ...


class ContextCommit(ContextChange):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMask(self) -> int:
        ...

    def getWordIndex(self) -> int:
        ...

    @property
    def wordIndex(self) -> jpype.JInt:
        ...

    @property
    def mask(self) -> jpype.JInt:
        ...


class Constructor(java.lang.Comparable[Constructor]):
    """
    The primary sleigh concept representing a semantic action
    taking operands (semantic values) as input
    producing a semantic value as output
    matching a particular pattern
    printing in a certain way
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def applyContext(self, walker: ParserWalker, debug: SleighDebugLogger):
        """
        Apply any operations on context for this Constructor to a
        particular InstructionContext
        
        :param ParserWalker walker: the parser walker
        :param SleighDebugLogger debug: the debug logger
        :raises MemoryAccessException: if the context failed to be applied.
        """

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, sleigh: SleighLanguage):
        ...

    def getContextChanges(self) -> java.util.List[ContextChange]:
        ...

    def getFlowthruIndex(self) -> int:
        ...

    def getId(self) -> int:
        ...

    def getLineno(self) -> int:
        ...

    def getMinimumLength(self) -> int:
        ...

    def getNamedTempl(self, secnum: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        """
        Retrieve a named p-code template section
        
        :param jpype.JInt or int secnum: is the id of the section to return
        :return: the named section (or null)
        :rtype: ghidra.app.plugin.processors.sleigh.template.ConstructTpl
        """

    def getNumOperands(self) -> int:
        ...

    def getOperand(self, i: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol:
        ...

    def getOpsPrintOrder(self) -> jpype.JArray[jpype.JInt]:
        """
        Return the indices of the operands in an array
        in the order they are printed (after the first white space)
        
        :return: array of operand indices
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getParent(self) -> ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol:
        ...

    def getPrintPieces(self) -> java.util.List[java.lang.String]:
        ...

    def getSourceFile(self) -> str:
        """
        Returns the source file
        
        :return: source file
        :rtype: str
        """

    def getTempl(self) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        ...

    def print(self, walker: ParserWalker) -> str:
        ...

    def printBody(self, walker: ParserWalker) -> str:
        ...

    def printList(self, walker: ParserWalker, list: java.util.ArrayList[java.lang.Object]):
        ...

    def printMnemonic(self, walker: ParserWalker) -> str:
        ...

    def printSeparator(self, separatorIndex: typing.Union[jpype.JInt, int]) -> str:
        ...

    def setId(self, val: typing.Union[jpype.JInt, int]):
        ...

    @property
    def parent(self) -> ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol:
        ...

    @property
    def minimumLength(self) -> jpype.JInt:
        ...

    @property
    def opsPrintOrder(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def templ(self) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        ...

    @property
    def sourceFile(self) -> java.lang.String:
        ...

    @property
    def numOperands(self) -> jpype.JInt:
        ...

    @property
    def printPieces(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def contextChanges(self) -> java.util.List[ContextChange]:
        ...

    @property
    def lineno(self) -> jpype.JInt:
        ...

    @property
    def flowthruIndex(self) -> jpype.JInt:
        ...

    @property
    def namedTempl(self) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @id.setter
    def id(self, value: jpype.JInt):
        ...

    @property
    def operand(self) -> ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol:
        ...


class FixedHandle(java.lang.Object):
    """
    The resulting data for a HandleTemplate after all the
    placeholders have been resolved through context
    """

    class_: typing.ClassVar[java.lang.Class]
    space: ghidra.program.model.address.AddressSpace
    size: jpype.JInt
    offset_space: ghidra.program.model.address.AddressSpace
    offset_offset: jpype.JLong
    offset_size: jpype.JInt
    temp_space: ghidra.program.model.address.AddressSpace
    temp_offset: jpype.JLong
    fixable: jpype.JBoolean

    def __init__(self):
        ...

    def getDynamicOffset(self) -> ghidra.program.model.pcode.Varnode:
        ...

    def getDynamicTemp(self) -> ghidra.program.model.pcode.Varnode:
        ...

    def getStaticVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    def isDynamic(self) -> bool:
        ...

    def isInvalid(self) -> bool:
        ...

    def setInvalid(self):
        ...

    @property
    def dynamicOffset(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def dynamicTemp(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def staticVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...


class SleighLanguageValidator(java.lang.Object):
    """
    Validate SLEIGH related XML configuration files: .cspec .pspec and .ldefs
     
    A ResourceFile containing an XML document can be verified with one of the
    static methods:
        - validateCspecFile
        - validateLdefsFile
        - validatePspecFile
     
    Alternately the class can be instantiated, which will allocate a single verifier
    that can be run on multiple files.
    """

    @typing.type_check_only
    class VerifierErrorHandler(org.xml.sax.ErrorHandler):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, file: generic.jar.ResourceFile):
            ...

        @typing.overload
        def __init__(self, title: typing.Union[java.lang.String, str], base: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    CSPEC_TYPE: typing.Final = 1
    PSPEC_TYPE: typing.Final = 2
    LDEFS_TYPE: typing.Final = 3
    CSPECTAG_TYPE: typing.Final = 4

    def __init__(self, type: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def validateCspecFile(cspecFile: generic.jar.ResourceFile):
        ...

    @staticmethod
    def validateLdefsFile(ldefsFile: generic.jar.ResourceFile):
        ...

    @staticmethod
    def validatePspecFile(pspecFile: generic.jar.ResourceFile):
        ...

    @typing.overload
    def verify(self, specFile: generic.jar.ResourceFile):
        """
        Verify the given file against this validator.
        
        :param generic.jar.ResourceFile specFile: is the file
        :raises SleighException: with an explanation if the file does not validate
        """

    @typing.overload
    def verify(self, title: typing.Union[java.lang.String, str], document: typing.Union[java.lang.String, str]):
        """
        Verify an XML document as a string against this validator.
        Currently this only supports verifierType == CSPECTAG_TYPE.
        
        :param java.lang.String or str title: is a description of the document
        :param java.lang.String or str document: is the XML document body
        :raises SleighException: with an explanation if the document does not validate
        """


class OpTplWalker(java.lang.Object):
    """
    Class for walking pcode templates OpTpl in the correct order
    Supports walking the tree of an entire SleighInstructionPrototype or just a single ConstructTpl
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, root: ConstructState, sectionnum: typing.Union[jpype.JInt, int]):
        """
        Constructor for walking an entire parse tree
        
        :param ConstructState root: is the root ConstructState of the tree
        :param jpype.JInt or int sectionnum: is the named section to traverse (or -1 for main section)
        """

    @typing.overload
    def __init__(self, tpl: ghidra.app.plugin.processors.sleigh.template.ConstructTpl):
        """
        Constructor for walking a single template
        
        :param ghidra.app.plugin.processors.sleigh.template.ConstructTpl tpl:
        """

    def getState(self) -> ConstructState:
        ...

    def isState(self) -> bool:
        ...

    def nextOpTpl(self) -> java.lang.Object:
        ...

    def popBuild(self):
        """
        Move to the parent of the current node
        """

    def pushBuild(self, buildnum: typing.Union[jpype.JInt, int]):
        """
        While walking the OpTpl's in order, follow a particular BUILD directive into its respective Constructor and ContructTpl
        Use popBuild to backtrack
        
        :param jpype.JInt or int buildnum: is the operand number of the BUILD directive to follow
        """

    @property
    def state(self) -> ConstructState:
        ...


class SleighException(java.lang.RuntimeException):
    """
    TODO To change the template for this generated type comment go to
    Window - Preferences - Java - Code Style - Code Templates
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.String or str message:
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], e: java.lang.Throwable):
        ...


class ContextCache(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getContext(self, ctx: ghidra.program.model.lang.ProcessorContextView, buf: jpype.JArray[jpype.JInt]):
        ...

    def getContextSize(self) -> int:
        ...

    def registerVariable(self, register: ghidra.program.model.lang.Register):
        ...

    def setContext(self, ctx: ghidra.program.model.lang.ProcessorContext, addr: ghidra.program.model.address.Address, num: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        ...

    @property
    def contextSize(self) -> jpype.JInt:
        ...


class SleighCompilerSpecDescription(ghidra.program.model.lang.BasicCompilerSpecDescription):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: ghidra.program.model.lang.CompilerSpecID, name: typing.Union[java.lang.String, str], file: generic.jar.ResourceFile):
        ...

    def getFile(self) -> generic.jar.ResourceFile:
        ...

    @property
    def file(self) -> generic.jar.ResourceFile:
        ...


class ContextChange(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def apply(self, walker: ParserWalker, debug: SleighDebugLogger):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, lang: SleighLanguage):
        ...


class SleighParserContext(ghidra.program.model.lang.ParserContext):
    """
    All the recovered context for a single instruction
    The main data structure is the tree of constructors and operands
    """

    @typing.type_check_only
    class ContextSet(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        sym: ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol
        num: jpype.JInt
        mask: jpype.JInt
        value: jpype.JInt
        point: ConstructState


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, memBuf: ghidra.program.model.mem.MemBuffer, prototype: SleighInstructionPrototype, processorContext: ghidra.program.model.lang.ProcessorContextView):
        ...

    @typing.overload
    def __init__(self, aAddr: ghidra.program.model.address.Address, nAddr: ghidra.program.model.address.Address, rAddr: ghidra.program.model.address.Address, dAddr: ghidra.program.model.address.Address):
        """
        Constructor for building precompiled templates.
        NOTE: This form does not support use of ``inst_next2``.
        
        :param ghidra.program.model.address.Address aAddr: = address to which 'inst_start' resolves
        :param ghidra.program.model.address.Address nAddr: = address to which 'inst_next' resolves
        :param ghidra.program.model.address.Address rAddr: = special address associated with original call
        :param ghidra.program.model.address.Address dAddr: = destination address of original call being replaced
        """

    @typing.overload
    def __init__(self, origContext: SleighParserContext, delayByteCount: typing.Union[jpype.JInt, int]):
        """
        Generate context specifically for an instruction that has a delayslot.
        When generating p-code SLEIGH has an alternate interpretation of the "inst_next"
        symbol that takes into account the instruction in the delay slot.  This context is
        generated at the point when specific instruction(s) in the delay slot are known.
        
        :param SleighParserContext origContext: is the original context (for the instruction in isolation)
        :param jpype.JInt or int delayByteCount: is the number of bytes in instruction stream occupied by the delay slot
        """

    def addCommit(self, point: ConstructState, sym: ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol, num: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JInt, int]):
        ...

    def applyCommits(self, ctx: ghidra.program.model.lang.ProcessorContext):
        ...

    def getAddr(self) -> ghidra.program.model.address.Address:
        """
        get address of current instruction
        
        :return: address of current instruction
        :rtype: ghidra.program.model.address.Address
        """

    def getConstSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get constant address space
        
        :return: constant address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getContextBits(self, startbit: typing.Union[jpype.JInt, int], bitsize: typing.Union[jpype.JInt, int]) -> int:
        """
        Get bits from context into an int
        
        :param jpype.JInt or int startbit: is the index of the first bit to fetch
        :param jpype.JInt or int bitsize: number of bits (range: 1 - 32)
        :return: the packed bits
        :rtype: int
        """

    @typing.overload
    def getContextBytes(self, bytestart: typing.Union[jpype.JInt, int], bytesize: typing.Union[jpype.JInt, int]) -> int:
        """
        Get bytes from context into an int
        
        :param jpype.JInt or int bytestart: is the index of the first byte to fetch
        :param jpype.JInt or int bytesize: number of bytes (range: 1 - 4)
        :return: the packed bytes from context
        :rtype: int
        """

    @typing.overload
    def getContextBytes(self) -> jpype.JArray[jpype.JInt]:
        """
        Get full set of context bytes.  Sleigh only supports context
        which is a multiple of 4-bytes (i.e., size of int)
        
        :return: the array of context data
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the processor context value as a RegisterValue
        
        :return: processor context value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getCurSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get address space containing current instruction
        
        :return: address space containing current instruction
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getFixedHandle(self, constructState: ConstructState) -> FixedHandle:
        ...

    def getFlowDestAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getFlowRefAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getInstructionBits(self, offset: typing.Union[jpype.JInt, int], startbit: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get bits from the instruction stream into an int
        (packed in big endian format).  Uninitialized or 
        undefined memory will return zero bit values.
        
        :param jpype.JInt or int offset: offset relative start of this context
        :param jpype.JInt or int startbit: is the index of the first bit to fetch
        :param jpype.JInt or int size: is the number of bits to fetch
        :return: requested bit-range value
        :rtype: int
        :raises MemoryAccessException: if no bytes are available at first byte when (offset+bytestart/8==0).
        """

    def getInstructionBytes(self, offset: typing.Union[jpype.JInt, int], bytestart: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> int:
        """
        Get bytes from the instruction stream into an int
        (packed in big endian format).  Uninitialized or 
        undefined memory will return zero byte values.
        
        :param jpype.JInt or int offset: offset relative start of this context
        :param jpype.JInt or int bytestart: pattern byte offset relative to specified context offset
        :param jpype.JInt or int size: is the number of bytes to fetch
        :return: requested byte-range value
        :rtype: int
        :raises MemoryAccessException: if no bytes are available at first byte when (offset+bytestart==0).
        """

    def getMemBuffer(self) -> ghidra.program.model.mem.MemBuffer:
        """
        Get memory buffer for current instruction which may also be used to parse next instruction
        or delay slot instructions.
        
        :return: memory buffer for current instruction
        :rtype: ghidra.program.model.mem.MemBuffer
        """

    def getN2addr(self) -> ghidra.program.model.address.Address:
        """
        Get address of instruction after the next instruction.  This may return :meth:`getNaddr() <.getNaddr>`
        if this context instance does not support use of ``inst_next2`` or parse of next 
        instruction fails.
        
        :return: address of instruction after the next instruction or null
        :rtype: ghidra.program.model.address.Address
        """

    def getNaddr(self) -> ghidra.program.model.address.Address:
        """
        Get address of instruction after current instruction.  This may return null if this context 
        instance does not support use of ``inst_next`` or next address falls beyond end of
        address space.
        
        :return: address of next instruction or null
        :rtype: ghidra.program.model.address.Address
        """

    def isValid(self, buf: ghidra.program.model.mem.MemBuffer) -> bool:
        ...

    def setContextWord(self, i: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JInt, int]):
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def contextBytes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def flowRefAddr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def fixedHandle(self) -> FixedHandle:
        ...

    @property
    def naddr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def memBuffer(self) -> ghidra.program.model.mem.MemBuffer:
        ...

    @property
    def n2addr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def constSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def contextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def addr(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def curSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def flowDestAddr(self) -> ghidra.program.model.address.Address:
        ...


class ConstructState(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: ConstructState):
        ...

    def dumpConstructorTree(self) -> str:
        """
        Used for testing and diagnostics: list the constructor line numbers used to resolve this
        encoding
         
        This includes braces to describe the tree structure
        
        :return: the constructor tree
        :rtype: str
        
        .. seealso::
        
            | :obj:`AssemblyResolvedPatterns.dumpConstructorTree()`
        """

    def getConstructor(self) -> Constructor:
        ...

    def getLength(self) -> int:
        ...

    def getNumSubStates(self) -> int:
        ...

    def getOffset(self) -> int:
        ...

    def getParent(self) -> ConstructState:
        ...

    def getSubState(self, index: typing.Union[jpype.JInt, int]) -> ConstructState:
        ...

    @property
    def parent(self) -> ConstructState:
        ...

    @property
    def numSubStates(self) -> jpype.JInt:
        ...

    @property
    def subState(self) -> ConstructState:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def constructor(self) -> Constructor:
        ...


class PcodeEmitPacked(PcodeEmit):

    class LabelRef(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        opIndex: jpype.JInt
        labelIndex: jpype.JInt
        labelSize: jpype.JInt
        streampos: jpype.JInt

        def __init__(self, op: typing.Union[jpype.JInt, int], lab: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], stream: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, encoder: ghidra.program.model.pcode.PatchEncoder, walk: ParserWalker, ictx: ghidra.program.model.lang.InstructionContext, fallOffset: typing.Union[jpype.JInt, int], override: ghidra.program.model.pcode.PcodeOverride):
        """
        Pcode emitter constructor for producing a packed binary representation.
        
        :param ghidra.program.model.pcode.PatchEncoder encoder: is the stream encoder to emit to
        :param ParserWalker walk: parser walker
        :param ghidra.program.model.lang.InstructionContext ictx: instruction contexts
        :param jpype.JInt or int fallOffset: default instruction fall offset (i.e., instruction length including delay slotted instructions)
        :param ghidra.program.model.pcode.PcodeOverride override: required if pcode overrides are to be utilized
        """

    def emitHeader(self):
        ...

    def emitTail(self):
        ...


class SpecExtensionEditor(ghidra.framework.options.OptionsEditor, java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.database.ProgramDB):
        ...


class SleighLanguageProvider(ghidra.program.model.lang.LanguageProvider):
    """
    Searches resources for spec files and provides LanguageDescriptions for these
    specifications
    """

    class_: typing.ClassVar[java.lang.Class]
    LANGUAGE_DIR_NAME: typing.Final = "languages"

    @staticmethod
    def getSleighLanguageProvider() -> SleighLanguageProvider:
        ...


class SleighDebugLogger(java.lang.Object):
    """
    ``SleighDebugLogger`` provides the ability to obtain detailed instruction
    parse details.
    """

    class SleighDebugMode(java.lang.Enum[SleighDebugLogger.SleighDebugMode]):

        class_: typing.ClassVar[java.lang.Class]
        VERBOSE: typing.Final[SleighDebugLogger.SleighDebugMode]
        MASKS_ONLY: typing.Final[SleighDebugLogger.SleighDebugMode]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SleighDebugLogger.SleighDebugMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[SleighDebugLogger.SleighDebugMode]:
            ...


    @typing.type_check_only
    class DebugInstructionContext(ghidra.program.model.lang.InstructionContext):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PatternGroup(java.util.ArrayList[java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InstructionBitPattern(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyProcessorContextView(ghidra.program.model.lang.ProcessorContextView):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, buf: ghidra.program.model.mem.MemBuffer, context: ghidra.program.model.lang.ProcessorContextView, language: ghidra.program.model.lang.Language, mode: SleighDebugLogger.SleighDebugMode):
        """
        Performs a parse debug at the specified memory location within program.
        
        :param ghidra.program.model.mem.MemBuffer buf: the memory buffer
        :param ghidra.program.model.lang.ProcessorContextView context: the processor context
        :param ghidra.program.model.lang.Language language: the sleigh language
        :param SleighDebugLogger.SleighDebugMode mode: the sleigh debug mode
        :raises IllegalArgumentException: if program language provider is not Sleigh
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address, mode: SleighDebugLogger.SleighDebugMode):
        """
        Performs a parse debug at the specified memory location within program.
        
        :param ghidra.program.model.listing.Program program: the program the memory location is found in
        :param ghidra.program.model.address.Address start: the start address of the memory location
        :param SleighDebugLogger.SleighDebugMode mode: the sleigh debug mode
        :raises IllegalArgumentException: if program language provider is not Sleigh
        """

    def addContextPattern(self, maskvalue: ghidra.app.plugin.processors.sleigh.pattern.PatternBlock):
        """
        Add instruction context pattern to the current pattern group.
        
        :param ghidra.app.plugin.processors.sleigh.pattern.PatternBlock maskvalue: pattern mask/value
        """

    def addInstructionPattern(self, offset: typing.Union[jpype.JInt, int], maskvalue: ghidra.app.plugin.processors.sleigh.pattern.PatternBlock):
        """
        Add instruction bit pattern to the current pattern group.
        
        :param jpype.JInt or int offset: base offset at which the specified maskvalue
        can be applied.
        :param ghidra.app.plugin.processors.sleigh.pattern.PatternBlock maskvalue: pattern mask/value
        """

    @typing.overload
    def append(self, value: typing.Union[jpype.JInt, int], startbit: typing.Union[jpype.JInt, int], bitcount: typing.Union[jpype.JInt, int]):
        """
        Append a binary formatted integer value with the specified range of bits
        bracketed to the log.  A -1 value for both startbit and bitcount disable the
        bit range bracketing. 
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param jpype.JInt or int value: integer value
        :param jpype.JInt or int startbit: identifies the first most-significant bit within the
        bracketed range (left-most value bit is bit-0, right-most value bit is bit-31)
        :param jpype.JInt or int bitcount: number of bits included within range
        """

    @typing.overload
    def append(self, value: jpype.JArray[jpype.JInt], startbit: typing.Union[jpype.JInt, int], bitcount: typing.Union[jpype.JInt, int]):
        """
        Append a binary formatted integer array with the specified range of bits
        bracketed to the log.  A -1 value for both startbit and bitcount disable the
        bit range bracketing.
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param jpype.JArray[jpype.JInt] value: integer array
        :param jpype.JInt or int startbit: identifies the first most-significant bit within the
        bracketed range (left-most value[0] bit is bit-0, right-most value[n] bit is bit-<32(n+1)-1> ).
        :param jpype.JInt or int bitcount: number of bits included within range
        """

    @typing.overload
    def append(self, value: jpype.JArray[jpype.JByte], startbit: typing.Union[jpype.JInt, int], bitcount: typing.Union[jpype.JInt, int]):
        """
        Append a binary formatted byte array with the specified range of bits
        bracketed to the log.  A -1 value for both startbit and bitcount disable the
        bit range bracketing.
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param jpype.JArray[jpype.JByte] value: byte array
        :param jpype.JInt or int startbit: identifies the first most-significant bit within the
        bracketed range (left-most value[0] bit is bit-0, right-most value[n] bit is bit-<8(n+1)-1> ).
        :param jpype.JInt or int bitcount: number of bits included within range
        """

    @typing.overload
    def append(self, str: typing.Union[java.lang.String, str]):
        """
        Append message string to log buffer.
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param java.lang.String or str str: message string
        """

    @typing.overload
    def dropIndent(self):
        """
        Shift log indent left
        """

    @typing.overload
    def dropIndent(self, levels: typing.Union[jpype.JInt, int]):
        ...

    def dumpContextPattern(self, maskvec: jpype.JArray[jpype.JInt], valvec: jpype.JArray[jpype.JInt], byteOffset: typing.Union[jpype.JInt, int], pos: SleighParserContext):
        """
        Dump context pattern details.
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param jpype.JArray[jpype.JInt] maskvec: 
        :param jpype.JArray[jpype.JInt] valvec: 
        :param jpype.JInt or int byteOffset: 
        :param SleighParserContext pos:
        """

    def dumpContextSet(self, pos: SleighParserContext, num: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JInt, int]):
        """
        Dump transient context setting details.
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param SleighParserContext pos: instruction context
        :param jpype.JInt or int num: 4-byte offset within base context register for mask and value
        :param jpype.JInt or int value: 4-byte context value
        :param jpype.JInt or int mask: 4-byte context mask
        """

    def dumpGlobalSet(self, pos: SleighParserContext, state: ConstructState, sym: ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol, num: typing.Union[jpype.JInt, int], mask: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JInt, int]):
        """
        Dump globalset details.  The target address is currently not included in the log.
        NOTE: Method has no affect unless constructed with VERBOSE logging mode.
        
        :param SleighParserContext pos: 
        :param ConstructState state: 
        :param ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol sym: 
        :param jpype.JInt or int num: 
        :param jpype.JInt or int mask: 
        :param jpype.JInt or int value: 
        :raises MemoryAccessException:
        """

    def endPatternGroup(self, commit: typing.Union[jpype.JBoolean, bool]):
        """
        Terminate the current pattern group
        
        :param jpype.JBoolean or bool commit: if false group will be discarded, if true group will be retained
        """

    def getConstructorLineNumbers(self) -> java.util.List[java.lang.String]:
        """
        Get list of constructor names with line numbers.
        Any debug mode may be used.
        
        :return: list
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getFormattedBytes(value: jpype.JArray[jpype.JByte]) -> str:
        """
        Convenience method for formatting bytes as a bit sequence
        
        :param jpype.JArray[jpype.JByte] value: byte array
        :return: binary formatted bytes
        :rtype: str
        """

    def getFormattedInstructionMask(self, opIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Return general/operand bit mask formatted as a String
        
        :param jpype.JInt or int opIndex: operand index or -1 for mnemonic mask
        :return: bit mask string
        :rtype: str
        """

    def getFormattedMaskedValue(self, opIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Return general/operand bit values formatted as a String
        
        :param jpype.JInt or int opIndex: operand index or -1 for mnemonic bit values
        :return: bit value string
        :rtype: str
        """

    def getInstructionMask(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the instruction bit mask which identifies those bits used to uniquely identify
        the instruction (includes addressing modes, generally excludes register selector bits
        associated with attaches or immediate values used in for semantic values only).
        
        :raises IllegalStateException: if prototype parse failed
        
        .. seealso::
        
            | :obj:`.getFormattedInstructionMask(int)`getFormattedInstructionMask(-1)
        """

    def getMaskedBytes(self, mask: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Apply an appropriate mask for the resulting instruction bytes
        to obtain the corresponding masked bytes.
        
        :param jpype.JArray[jpype.JByte] mask: instruction, operand or similarly sized mask
        :return: masked instruction bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getNumOperands(self) -> int:
        """
        Get the number of operands for the resulting prototype
        
        :return: operand count
        :rtype: int
        :raises IllegalStateException: if prototype parse failed
        """

    def getOperandValueMask(self, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Get the byte value mask corresponding to the specified operand.
        
        :param jpype.JInt or int opIndex: operand index within the instruction representation
        :return: byte mask or null if operand does not have a corresponding sub-constructor or attach
        :rtype: jpype.JArray[jpype.JByte]
        :raises IllegalStateException: if prototype parse failed
        :raises IndexOutOfBoundsException: if opIndex is not a valid operand index
        """

    @typing.overload
    def indent(self):
        """
        Shift log indent right
        """

    @typing.overload
    def indent(self, levels: typing.Union[jpype.JInt, int]):
        ...

    def isVerboseEnabled(self) -> bool:
        """
        
        
        :return: true if constructed for verbose logging
        :rtype: bool
        """

    def parseFailed(self) -> bool:
        """
        
        
        :return: true if a parse error was detected, otherwise false is returned.
        The methods getMaskedBytes() and getInstructionMask() should
        only be invoked if this method returns false.
        :rtype: bool
        """

    def startPatternGroup(self, name: typing.Union[java.lang.String, str]):
        """
        Start new pattern group for a specific sub-table.  
        A null can correspond to a top-level constructor or 
        low level complex pattern (AND, OR).  All committed unnamed groups 
        with the same parent group will be combined.
        
        :param java.lang.String or str name: group name or null for unnamed group
        """

    def toString(self) -> str:
        """
        Return log text
        """

    @property
    def operandValueMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def instructionMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def formattedMaskedValue(self) -> java.lang.String:
        ...

    @property
    def maskedBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def verboseEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def constructorLineNumbers(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def formattedInstructionMask(self) -> java.lang.String:
        ...

    @property
    def numOperands(self) -> jpype.JInt:
        ...


class ContextOp(ContextChange):
    """
    An operation on the context (bit-packed form) of an instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMask(self) -> int:
        ...

    def getPatternExpression(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        ...

    def getShift(self) -> int:
        ...

    def getWordIndex(self) -> int:
        ...

    @property
    def shift(self) -> jpype.JInt:
        ...

    @property
    def patternExpression(self) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        ...

    @property
    def wordIndex(self) -> jpype.JInt:
        ...

    @property
    def mask(self) -> jpype.JInt:
        ...


class SleighInstructionPrototype(ghidra.program.model.lang.InstructionPrototype):
    """
    The InstructionPrototype for sleigh languages. The prototype is unique up to the tree of
    Constructors. Variations in the bit pattern that none of the Constructor mask/values care about
    get lumped under the same prototype
    """

    class FlowRecord(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        addressnode: ConstructState
        op: ghidra.app.plugin.processors.sleigh.template.OpTpl
        flowFlags: jpype.JInt

        def __init__(self):
            ...


    class FlowSummary(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        delay: jpype.JInt
        hasCrossBuilds: jpype.JBoolean
        flowState: java.util.ArrayList[SleighInstructionPrototype.FlowRecord]
        lastop: ghidra.app.plugin.processors.sleigh.template.OpTpl

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    RETURN: typing.Final = 1
    CALL_INDIRECT: typing.Final = 2
    BRANCH_INDIRECT: typing.Final = 4
    CALL: typing.Final = 8
    JUMPOUT: typing.Final = 16
    NO_FALLTHRU: typing.Final = 32
    BRANCH_TO_END: typing.Final = 64
    CROSSBUILD: typing.Final = 128
    LABEL: typing.Final = 256

    def __init__(self, lang: SleighLanguage, buf: ghidra.program.model.mem.MemBuffer, context: ghidra.program.model.lang.ProcessorContextView, cache: ContextCache, inDelaySlot: typing.Union[jpype.JBoolean, bool], debug: SleighDebugLogger):
        ...

    def dumpConstructorTree(self) -> str:
        """
        Used for testing and diagnostics: list the constructor line numbers used to resolve this
        encoding
         
        This includes braces to describe the tree structure
        
        :return: the constructor tree
        :rtype: str
        
        .. seealso::
        
            | :obj:`AssemblyResolvedPatterns.dumpConstructorTree()`
        """

    @staticmethod
    def flowListToFlowType(flowstate: java.util.List[SleighInstructionPrototype.FlowRecord]) -> ghidra.program.model.symbol.FlowType:
        ...

    def getRootState(self) -> ConstructState:
        ...

    @staticmethod
    def walkTemplates(walker: OpTplWalker) -> SleighInstructionPrototype.FlowSummary:
        """
        Walk the pcode templates in the order they would be emitted. Collect flowFlags FlowRecords
        
        :param OpTplWalker walker: the pcode template walker
        :return: a summary of the flow information
        :rtype: SleighInstructionPrototype.FlowSummary
        """

    @property
    def rootState(self) -> ConstructState:
        ...


class SleighLanguage(ghidra.program.model.lang.Language):

    class_: typing.ClassVar[java.lang.Class]

    def encodeTranslator(self, encoder: ghidra.program.model.pcode.Encoder, factory: ghidra.program.model.address.AddressFactory, uniqueOffset: typing.Union[jpype.JLong, int]):
        """
        Encode limited information to the stream about the SLEIGH translator for the specified
        address factory and optional register set.
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.AddressFactory factory: is the specified address factory
        :param jpype.JLong or int uniqueOffset: the initial offset within the unique address space to start assigning temporary registers
        :raises IOException: for errors writing to the underlying stream
        """

    def getAdditionalInject(self) -> java.util.List[ghidra.program.model.lang.InjectPayloadSleigh]:
        ...

    @deprecated("Will be removed once we have better way to attach address spaces to pointer data-types")
    def getDefaultPointerWordSize(self) -> int:
        """
        
        
        
        .. deprecated::
        
        Will be removed once we have better way to attach address spaces to pointer data-types
        :return: the default wordsize to use when analyzing pointer offsets
        :rtype: int
        """

    def getRootDecisionNode(self) -> DecisionNode:
        ...

    def getSourceFileIndexer(self) -> ghidra.sleigh.grammar.SourceFileIndexer:
        """
        Returns the source file indexer
        
        :return: indexer
        :rtype: ghidra.sleigh.grammar.SourceFileIndexer
        """

    def getSymbolTable(self) -> ghidra.app.plugin.processors.sleigh.symbol.SymbolTable:
        ...

    def getUniqueAllocationMask(self) -> int:
        ...

    def getUniqueBase(self) -> int:
        """
        Returns the unique base offset from which additional temporary variables
        may be created.
        
        :return: unique base offset
        :rtype: int
        """

    def loadIndex(self, processorFile: generic.jar.ResourceFile):
        ...

    def numSections(self) -> int:
        """
        
        
        :return: (maximum) number of named p-code sections
        :rtype: int
        """

    @property
    def symbolTable(self) -> ghidra.app.plugin.processors.sleigh.symbol.SymbolTable:
        ...

    @property
    def additionalInject(self) -> java.util.List[ghidra.program.model.lang.InjectPayloadSleigh]:
        ...

    @property
    def rootDecisionNode(self) -> DecisionNode:
        ...

    @property
    def uniqueBase(self) -> jpype.JLong:
        ...

    @property
    def defaultPointerWordSize(self) -> jpype.JInt:
        ...

    @property
    def sourceFileIndexer(self) -> ghidra.sleigh.grammar.SourceFileIndexer:
        ...

    @property
    def uniqueAllocationMask(self) -> jpype.JInt:
        ...


class UniqueLayout(java.lang.Enum[UniqueLayout]):
    """
    Offsets for various ranges in the p-code unique space.  Offsets are either:
        1) Relative to the last temporary allocated statically by the SLEIGH compiler
            or a particular language (.sla), OR
        2) Absolute within the unique address space.
    So the layout of the unique address space looks like:
        1)  SLEIGH static temporaries
        2)  Runtime temporaries used by the SLEIGH p-code generator
        3)  Temporaries used by the PcodeInjectLibrary for p-code snippets
        4)  Temporaries generated during (decompiler) analysis
    
        The "unique" space is set to 32 bits across all architectures.
        The maximum offset is 0xFFFFFFFF.
        The offsets and names should match with the parallel decompiler enum in translate.hh
    """

    class_: typing.ClassVar[java.lang.Class]
    SLEIGH_BASE: typing.Final[UniqueLayout]
    RUNTIME_BOOLEAN_INVERT: typing.Final[UniqueLayout]
    RUNTIME_RETURN_LOCATION: typing.Final[UniqueLayout]
    RUNTIME_BITRANGE_EA: typing.Final[UniqueLayout]
    INJECT: typing.Final[UniqueLayout]
    ANALYSIS: typing.Final[UniqueLayout]

    def getOffset(self, language: SleighLanguage) -> int:
        """
        Get the starting offset of a named range in the unique address space.  The returned offset
        is absolute and specific to the given SLEIGH language.
        
        :param SleighLanguage language: is the given SLEIGH language
        :return: the absolute offset
        :rtype: int
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> UniqueLayout:
        ...

    @staticmethod
    def values() -> jpype.JArray[UniqueLayout]:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...


class VarnodeData(java.lang.Object):
    """
    All the resolved pieces of data needed to build a Varnode
    """

    class_: typing.ClassVar[java.lang.Class]
    space: ghidra.program.model.address.AddressSpace
    offset: jpype.JLong
    size: jpype.JInt

    def __init__(self):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode the data to stream as an ``<addr>`` element
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for errors writing to the underlying stream
        """


class SpecExtensionPanel(javax.swing.JPanel):

    class Status(java.lang.Enum[SpecExtensionPanel.Status]):
        """
        Status of a particular compiler specification element
        """

        class_: typing.ClassVar[java.lang.Class]
        CORE: typing.Final[SpecExtensionPanel.Status]
        EXTENSION: typing.Final[SpecExtensionPanel.Status]
        EXTENSION_ERROR: typing.Final[SpecExtensionPanel.Status]
        EXTENSION_INSTALL: typing.Final[SpecExtensionPanel.Status]
        EXTENSION_REPLACE: typing.Final[SpecExtensionPanel.Status]
        EXTENSION_REMOVE: typing.Final[SpecExtensionPanel.Status]
        EXTENSION_OVERRIDE: typing.Final[SpecExtensionPanel.Status]
        EXTENSION_OVERPENDING: typing.Final[SpecExtensionPanel.Status]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SpecExtensionPanel.Status:
            ...

        @staticmethod
        def values() -> jpype.JArray[SpecExtensionPanel.Status]:
            ...


    @typing.type_check_only
    class CompilerElement(java.lang.Comparable[SpecExtensionPanel.CompilerElement]):
        """
        A row in the table of compiler spec elements
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, nm: typing.Union[java.lang.String, str], tp: ghidra.program.database.SpecExtension.Type, st: SpecExtensionPanel.Status):
            ...

        def isExisting(self) -> bool:
            """
            Return true if the element is already installed (not pending)
            
            :return: true for an existing extension
            :rtype: bool
            """

        @property
        def existing(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class TableSelectionListener(javax.swing.event.ListSelectionListener):
        """
        Selection listener class for the table model.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SpecExtensionTableModel(docking.widgets.table.AbstractGTableModel[SpecExtensionPanel.CompilerElement]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CompilerElementTable(docking.widgets.table.GTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ElementRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class ChangeExtensionTask(ghidra.util.task.Task):
        """
        Task for applying any accumulated changes in the list of CompilerElements for this Panel to the Program.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    PREFERENCES_FILE_EXTENSION: typing.Final = ".xml"

    def apply(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def cancel(self):
        """
        Cancel any pending changes and reload the current table
        """


class DecisionNode(java.lang.Object):
    """
    A node in the decision tree for resolving a Constructor in 
    a SubtableSymbol based on the InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, par: DecisionNode, sub: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol):
        ...

    def getChildren(self) -> java.util.List[DecisionNode]:
        ...

    def getConstructors(self) -> java.util.List[Constructor]:
        ...

    def getPatterns(self) -> java.util.List[ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern]:
        ...

    def resolve(self, walker: ParserWalker, debug: SleighDebugLogger) -> Constructor:
        ...

    @property
    def constructors(self) -> java.util.List[Constructor]:
        ...

    @property
    def children(self) -> java.util.List[DecisionNode]:
        ...

    @property
    def patterns(self) -> java.util.List[ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern]:
        ...



__all__ = ["PcodeEmitObjects", "ModuleDefinitionsMap", "ParserWalker", "ModuleDefinitionsAdapter", "PcodeEmit", "ContextCommit", "Constructor", "FixedHandle", "SleighLanguageValidator", "OpTplWalker", "SleighException", "ContextCache", "SleighCompilerSpecDescription", "ContextChange", "SleighParserContext", "ConstructState", "PcodeEmitPacked", "SpecExtensionEditor", "SleighLanguageProvider", "SleighDebugLogger", "ContextOp", "SleighInstructionPrototype", "SleighLanguage", "UniqueLayout", "VarnodeData", "SpecExtensionPanel", "DecisionNode"]
