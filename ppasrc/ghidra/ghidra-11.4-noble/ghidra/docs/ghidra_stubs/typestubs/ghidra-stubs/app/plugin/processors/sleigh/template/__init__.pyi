from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang # type: ignore


class ConstTpl(java.lang.Object):
    """
    A placeholder for what will resolve to a field of a Varnode
    (an AddressSpace or integer offset or integer size)
    given a particular InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]
    REAL: typing.Final = 0
    HANDLE: typing.Final = 1
    J_START: typing.Final = 2
    J_NEXT: typing.Final = 3
    J_NEXT2: typing.Final = 4
    J_CURSPACE: typing.Final = 5
    J_CURSPACE_SIZE: typing.Final = 6
    SPACEID: typing.Final = 7
    J_RELATIVE: typing.Final = 8
    J_FLOWREF: typing.Final = 9
    J_FLOWREF_SIZE: typing.Final = 10
    J_FLOWDEST: typing.Final = 11
    J_FLOWDEST_SIZE: typing.Final = 12
    V_SPACE: typing.Final = 0
    V_OFFSET: typing.Final = 1
    V_SIZE: typing.Final = 2
    V_OFFSET_PLUS: typing.Final = 3
    calc_mask: typing.Final[jpype.JArray[jpype.JLong]]

    @typing.overload
    def __init__(self, op2: ConstTpl):
        ...

    @typing.overload
    def __init__(self, tp: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, tp: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, spc: ghidra.program.model.address.AddressSpace):
        ...

    @typing.overload
    def __init__(self, tp: typing.Union[jpype.JInt, int], ht: typing.Union[jpype.JInt, int], vf: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, tp: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JLong, int], spc: ghidra.program.model.address.AddressSpace, ht: typing.Union[jpype.JInt, int], sel: typing.Union[jpype.JInt, int]):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def fillinOffset(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker):
        """
        Fillin the offset portion of a FixedHandle based on this
        const. If the offset value is dynamic, fill in the handle
        appropriately.  We don't just fill in the temporary
        variable offset, like "fix". Assume that hand.space is
        already filled in
        
        :param ghidra.app.plugin.processors.sleigh.FixedHandle hand: handle to fillin
        :param ghidra.app.plugin.processors.sleigh.ParserWalker walker: current parser walker
        """

    def fillinSpace(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker):
        """
        Fill in the space portion of a FixedHandle, based
        on this const.
        
        :param ghidra.app.plugin.processors.sleigh.FixedHandle hand: handle to fillin
        :param ghidra.app.plugin.processors.sleigh.ParserWalker walker: current parser walker
        """

    def fix(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> int:
        ...

    def fixSpace(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> ghidra.program.model.address.AddressSpace:
        ...

    def getHandleIndex(self) -> int:
        ...

    def getReal(self) -> int:
        ...

    def getSelect(self) -> int:
        ...

    def getSpaceId(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getType(self) -> int:
        ...

    def isConstSpace(self) -> bool:
        ...

    def isUniqueSpace(self) -> bool:
        ...

    @property
    def spaceId(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def select(self) -> jpype.JInt:
        ...

    @property
    def uniqueSpace(self) -> jpype.JBoolean:
        ...

    @property
    def handleIndex(self) -> jpype.JInt:
        ...

    @property
    def constSpace(self) -> jpype.JBoolean:
        ...

    @property
    def real(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class VarnodeTpl(java.lang.Object):
    """
    Placeholder for what will resolve to a Varnode instance given
    a specific InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: ConstTpl, offset: ConstTpl, size: ConstTpl):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def getOffset(self) -> ConstTpl:
        ...

    def getSize(self) -> ConstTpl:
        ...

    def getSpace(self) -> ConstTpl:
        ...

    def isDynamic(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> bool:
        ...

    def isRelative(self) -> bool:
        ...

    @property
    def size(self) -> ConstTpl:
        ...

    @property
    def offset(self) -> ConstTpl:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def space(self) -> ConstTpl:
        ...

    @property
    def relative(self) -> jpype.JBoolean:
        ...


class HandleTpl(java.lang.Object):
    """
    Placeholder that resolves for a specific :obj:`InstructionContext` into a :obj:`FixedHandle`
    representing the semantic value of a :obj:`Constructor`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ConstTpl, sz: ConstTpl, ptrspc: ConstTpl, ptroff: ConstTpl, ptrsz: ConstTpl, tmpspc: ConstTpl, tmpoff: ConstTpl):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def fix(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker):
        ...

    def fixPrintPiece(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker, handleIndex: typing.Union[jpype.JInt, int]):
        ...

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the address space of the value, if applicable
        
        :return: the address space, or null if not applicable
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getOffsetOperandIndex(self) -> int:
        ...

    def getSize(self) -> int:
        """
        Get the size of the expected value in bits
        
        :return: the number of bits
        :rtype: int
        """

    @property
    def offsetOperandIndex(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...


class ConstructTpl(java.lang.Object):
    """
    A constructor template, representing the semantic action of a SLEIGH constructor, without
    its final context.  The constructor template is made up of a list of p-code op templates,
    which are in turn made up of varnode templates.
    This is one step removed from the final array of PcodeOp objects, but:
    - Constants may still need to incorporate context dependent address resolution and relative offsets.
    - Certain p-code operations may still need expansion to include a dynamic LOAD or STORE operation.
    - The list may hold "build" directives for sub-constructor templates.
    - The list may still hold "label" information for the final resolution of relative jump offsets.
     
    The final PcodeOps are produced by handing this to the build() method of PcodeEmit which has
    the InstructionContext necessary for final resolution.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor for use with decode
        """

    @typing.overload
    def __init__(self, opvec: jpype.JArray[OpTpl]):
        """
        Manually build a constructor template. This is useful for building constructor templates
        outside of the normal SLEIGH pipeline, as for an internally created InjectPayload.
        
        :param jpype.JArray[OpTpl] opvec: is the list of p-code op templates making up the constructor
        """

    @typing.overload
    def __init__(self, opvec: jpype.JArray[OpTpl], res: HandleTpl, nmLabels: typing.Union[jpype.JInt, int]):
        """
        Manually build a constructor template from pieces.  This is used to translate from the
        internal SLEIGH compiler pcodeCPort.semantics.ConstructTpl
        
        :param jpype.JArray[OpTpl] opvec: is the list of p-code op templates making up the constructor
        :param HandleTpl res: is the result handle template for the constructor
        :param jpype.JInt or int nmLabels: is the number of labels int the template
        """

    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> int:
        """
        Decode this template from a ``<construct_tpl>`` tag in the stream.
        
        :param ghidra.program.model.pcode.Decoder decoder: is the stream
        :return: the constructor section id described by the tag
        :rtype: int
        :raises DecoderException: for errors in the encoding
        """

    def getNumLabels(self) -> int:
        """
        
        
        :return: the number of labels needing resolution in this template
        :rtype: int
        """

    def getOpVec(self) -> jpype.JArray[OpTpl]:
        """
        
        
        :return: the list of p-code op templates making up this constructor template
        :rtype: jpype.JArray[OpTpl]
        """

    def getResult(self) -> HandleTpl:
        """
        
        
        :return: the (possibly dynamic) location of the final semantic value produced by this constructor
        :rtype: HandleTpl
        """

    @property
    def result(self) -> HandleTpl:
        ...

    @property
    def opVec(self) -> jpype.JArray[OpTpl]:
        ...

    @property
    def numLabels(self) -> jpype.JInt:
        ...


class OpTpl(java.lang.Object):
    """
    Placeholder for what will resolve to a PcodeOp
    for a specific InstructionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, opcode: typing.Union[jpype.JInt, int], output: VarnodeTpl, inputs: jpype.JArray[VarnodeTpl]):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...

    def getInput(self) -> jpype.JArray[VarnodeTpl]:
        ...

    def getOpcode(self) -> int:
        ...

    def getOutput(self) -> VarnodeTpl:
        ...

    @property
    def output(self) -> VarnodeTpl:
        ...

    @property
    def input(self) -> jpype.JArray[VarnodeTpl]:
        ...

    @property
    def opcode(self) -> jpype.JInt:
        ...



__all__ = ["ConstTpl", "VarnodeTpl", "HandleTpl", "ConstructTpl", "OpTpl"]
