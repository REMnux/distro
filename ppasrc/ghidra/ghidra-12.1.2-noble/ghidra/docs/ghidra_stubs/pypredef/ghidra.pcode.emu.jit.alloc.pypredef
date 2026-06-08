from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.analysis
import ghidra.pcode.emu.jit.gen
import ghidra.pcode.emu.jit.gen.opnd
import ghidra.pcode.emu.jit.gen.util
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang # type: ignore
import java.util # type: ignore


FJT = typing.TypeVar("FJT")
FT = typing.TypeVar("FT")
JT = typing.TypeVar("JT")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
SJT = typing.TypeVar("SJT")
ST = typing.TypeVar("ST")
T = typing.TypeVar("T")
THIS = typing.TypeVar("THIS")
TJT = typing.TypeVar("TJT")
TT = typing.TypeVar("TT")
WJT = typing.TypeVar("WJT")
WT = typing.TypeVar("WT")


class JvmLocal(java.lang.Record, typing.Generic[T, JT]):
    """
    An allocated JVM local
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: ghidra.pcode.emu.jit.gen.util.Local[T], type: JT, vn: ghidra.program.model.pcode.Varnode, opnd: ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd[T, JT]) -> None:
        ...

    def castOf(self, type: TJT) -> JvmLocal[TT, TJT]:
        """
        Cast this local to satisfy checkers when a type variable is known to be of a given type
         
        
        This will verify at runtime that the types are in fact identical.
        
        :param TT: the "to" JVM type:param TJT: the "to" p-code type:param TJT type: the "to" p-code type
        :return: this local as the given type
        :rtype: JvmLocal[TT, TJT]
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def genBirthCode(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode to bring this varnode into scope.
         
         
        
        This will copy the value from the :obj:`state <JitBytesPcodeExecutorState>` into the local
        variable.
        
        :param THIS: the type of the compiled passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genInit(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode into the class constructor needed to access the varnode's actual value from the
        underlying :obj:`PcodeExecutorState`.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genLoadToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: TJT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, TT]]:
        """
        Emit bytecode to load this local's value onto the JVM stack as the given type
        
        :param TT: the desired JVM type:param TJT: the desired p-code type:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param TJT type: the desired p-code type
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter typed with the resulting stack, i.e., having pushed the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, TT]]
        """

    def genRetireCode(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], localThis: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode to take this varnode out of scope.
         
         
        
        This will copy the value from the local variable into the :obj:`state <JitBytesPcodeExecutorState>`.
        
        :param THIS: the type of the compiled passage:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[THIS]] localThis: a handle to the local holding the ``this`` reference
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[THIS] gen: the code generator
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genStoreFromStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: FJT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode to store the value on the JVM stack into the local
        
        :param FT: the JVM type of the value on the stack:param FJT: the p-code type of the value on the stack:param N1: the tail of the incoming stack:param N0: the incoming stack with the value on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param FJT type: the p-code type of the value on the stack
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., having popped the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def hashCode(self) -> int:
        ...

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[T]:
        ...

    def maxPrimAddr(self) -> ghidra.program.model.address.Address:
        """
        :return: the maximum address that would be occupied by the full primitive type
        :rtype: ghidra.program.model.address.Address
        """

    def name(self) -> str:
        """
        Get the name of the wrapped local
        
        :return: the name
        :rtype: str
        """

    @staticmethod
    def of(local: ghidra.pcode.emu.jit.gen.util.Local[T], type: JT, vn: ghidra.program.model.pcode.Varnode) -> JvmLocal[T, JT]:
        """
        Create a :obj:`JvmLocal` with the given local, type, and varnode
        
        :param T: the JVM type of the local:param JT: the p-code type of the local:param ghidra.pcode.emu.jit.gen.util.Local[T] local: the local
        :param JT type: the p-code type of the local
        :param ghidra.program.model.pcode.Varnode vn: the varnode to assign to the local
        :return: the new local (wrapper)
        :rtype: JvmLocal[T, JT]
        """

    def opnd(self) -> ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd[T, JT]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> JT:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class ShiftedMpIntHandler(java.lang.Record, VarHandler):
    """
    The handler used for a varnode requiring allocation of multiple integers, where those integers
    *do not* align to the variable's legs.
     
    
    The below diagram is an example shifted allocation, whose ``byteShift`` value is 3, and whose
    varnode size is 11 (admittedly pathological, but made to illustrate a complicated example).
     
     
    +--*--*--*--+--*--*--*--+--*--*--*--+--*--*--*--+
    | parts[3]  | parts[2]  | parts[1]  | parts[0]  |
    +-----------+-----------+-----------+-----------+
        +--*--*--+--*--*--*--+--*--*--*--+
        |  leg2  |   leg1    |   leg0    |
        +--------+-----------+-----------+
     
     
    
    In the unaligned case, all loads and stores require copying the shifted value into a series of
    temporary locals, representing the legs of the value. Because these are already temporary, the
    operator may freely use the legs as temporary storage.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parts: java.util.List[JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, vn: ghidra.program.model.pcode.Varnode, byteShift: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteShift(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def parts(self) -> java.util.List[JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class NoHandler(java.lang.Enum[NoHandler], VarHandler):
    """
    A dummy handler for values/variables that are not allocated in JVM locals
     
    
    Every operation on this handler will throw an exception at code generation time.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[NoHandler]
    """
    Singleton
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> NoHandler:
        ...

    @staticmethod
    def values() -> jpype.JArray[NoHandler]:
        ...


class IntInLongHandler(java.lang.Record, SubInLongHandler[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    The handler for an :obj:`int <IntJitType>` p-code variable stored in part of a JVM ``long``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, vn: ghidra.program.model.pcode.Varnode, byteShift: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteShift(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class DoubleVarAlloc(java.lang.Record, SimpleVarHandler[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
    """
    The handler for a p-code variable allocated in one JVM ``double``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType], type: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType:
        ...


class AlignedMpIntHandler(java.lang.Record, VarHandler):
    """
    The handler used for a varnode requiring allocation of multiple integers, where those integers
    correspond exactly to the variable's legs.
     
    
    In this case, we can usually give the operators direct access to the underlying mp-int operand.
    We do need to be careful that we don't unintentionally permit the operator to use the variable's
    storage for intermediate values. Thus, we have some provision for saying each leg is read-only,
    which will cause attempts to store into them to instead generate a writable temporary local. Such
    intermediate results will get written only by a call to
    :meth:`genStoreFromOpnd(Emitter, JitCodeGenerator, Opnd, Ext, Scope) <.genStoreFromOpnd>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, legs: java.util.List[JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, vn: ghidra.program.model.pcode.Varnode) -> None:
        """
        Preferred constructor
        
        :param java.util.List[JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]] legs: the list o legs in little-endian order
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the type of the full muti-precision integer variable
        :param ghidra.program.model.pcode.Varnode vn: the complete varnode accessible to this handler
        """

    @typing.overload
    def __init__(self, legs: java.util.List[JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, vn: ghidra.program.model.pcode.Varnode, opnd: ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd, roOpnd: ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def legs(self) -> java.util.List[JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]]:
        ...

    def opnd(self) -> ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd:
        ...

    def roOpnd(self) -> ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class LongInLongHandler(java.lang.Record, SubInLongHandler[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
    """
    The handler for an :obj:`long <LongJitType>` p-code variable stored in part of a JVM ``long``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType], type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, vn: ghidra.program.model.pcode.Varnode, byteShift: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteShift(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class IntVarAlloc(java.lang.Record, SimpleVarHandler[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    The handler for a p-code variable allocated in one JVM ``int``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        ...


class SubVarHandler(VarHandler, typing.Generic[ST, SJT, WT, WJT]):
    """
    A handler to p-code variables stored in just a portion of a single JVM local variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def assertShiftFits(self, byteShift: typing.Union[jpype.JInt, int], type: SJT, local: JvmLocal[WT, WJT]) -> None:
        """
        Verify that the sub variable as shifted actually fits in the containing variable
        
        :param jpype.JInt or int byteShift: the number of unused bytes in the container variable to the right of the sub
                    variable
        :param SJT type: the type of the sub variable
        :param JvmLocal[WT, WJT] local: the containing local variable
        """

    def bitShift(self) -> int:
        """
        :return: the number of unused bits in the container variable to the right of the sub
        variable
        :rtype: int
        """

    def bitSize(self) -> int:
        """
        :return: the number of bits in the sub variable
        :rtype: int
        """

    def byteShift(self) -> int:
        """
        :return: the number of unused bytes in the container variable to the right of the sub
        variable
        :rtype: int
        """

    def getConvToSub(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ST, SJT]:
        """
        Get the converter of multi-precision integers to the type of the sub variable.
         
        
        The converter need not worry about positioning or masking wrt. the sub variable. It should
        extract from the multi-precision integer the minimum number of legs needed to fill the sub
        variable, i.e., it need only consider the sub variable's size. This handler will then mask
        and position it within the containing variable for storage.
        
        :return: the converter
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ST, SJT]
        """

    def intMask(self) -> int:
        """
        :return: the mask indicating which parts of the ``int`` containing variable are within
        the sub variable
        :rtype: int
        """

    def local(self) -> JvmLocal[WT, WJT]:
        """
        :return: The containing local variable
        :rtype: JvmLocal[WT, WJT]
        """

    def longMask(self) -> int:
        """
        :return: the mask indicating which parts of the ``long`` containing variable are within
        the sub variable
        :rtype: int
        """

    @property
    def convToSub(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ST, SJT]:
        ...


class FloatVarAlloc(java.lang.Record, SimpleVarHandler[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
    """
    The handler for a p-code variable allocated in one JVM ``float``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType], type: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.FloatJitType:
        ...


class VarHandler(java.lang.Object):
    """
    A handler that knows how to load and store variables' values from local storage.
     
    
    Some variables are hosted in a single JVM local of compatible type. Others, notably
    multi-precision integers, are allocated among two or more JVM local integers. Each such integer
    is called a "leg" of the multi-precision integer. Other literature may call these "digits" (whose
    value is in [0, 0xffffffff]). Depending on the operator implementation, value may need to be
    loaded with alternative types or in different forms. e.g., any float operator will need to
    convert its inputs into the appropriate float type, even if the operands were allocated as an int
    type. Similarly, some operators are implement their multi-precision computations by invoking
    static methods whose parameters are ``int[]``, and so they will load and store the array
    forms instead of accessing the legs' locals. This interface provides generators for the various
    circumstances. Each subclass provides the implementations for various allocations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def genLoadLegToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, leg: typing.Union[jpype.JInt, int], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit bytecode to load one leg of a multi-precision value from the varnode onto the JVM stack.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the complete multi-precision value
        :param jpype.JInt or int leg: the index of the leg to load, 0 being least significant
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genLoadToArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
        """
        Emit bytecode to load the varnode's value into an integer array in little-endian order,
        pushing its ref onto the JVM stack.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the complete multi-precision value
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :param jpype.JInt or int slack: the number of additional, more significant, elements to allocate in the array
        :return: the emitter typed with the resulting stack, i.e., having the ref pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
        """

    def genLoadToBool(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit bytecode to load the varnode's value, interpreted as a boolean, as an integer onto the
        JVM stack.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :return: the emitter typed with the resulting stack, i.e., having the int boolean pushed onto
                it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genLoadToOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]:
        """
        Emit bytecode to load the varnode's value into several locals.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the value expected on the JVM stack by the proceeding bytecode
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the operand containing the locals, and the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]
        """

    def genLoadToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: TJT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, TT]]:
        """
        Emit bytecode to load the varnode's value onto the JVM stack.
        
        :param TT: the JVM type of the value to load onto the stack:param TJT: the p-code type of the value to load onto the stack:param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param TJT type: the p-code type of the value expected on the JVM stack by the proceeding bytecode
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply when adjusting from JVM size to varnode size
        :return: the emitter typed with the resulting stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, TT]]
        """

    def genStoreFromArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode to store a varnode's value from an array of integer legs, in little endian
        order
        
        :param N1: the tail of the incoming stack:param N0: the incoming stack having the array ref on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the value on the stack
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., having popped the array
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def genStoreFromOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], opnd: ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
        """
        Emit bytecode to store a varnode's value from several locals.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType] opnd: the operand whose locals contain the value to be stored
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the incoming stack
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
        """

    def genStoreFromStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: FJT, ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit bytecode to store a value into a variable from the JVM stack.
        
        :param FT: the JVM type of the value on the stack:param FJT: the p-code type of the value on the stack:param N1: the tail of the incoming stack:param N0: the incoming stack having the value to store on top:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param FJT type: the p-code type of the value on the stack
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generating temporary local storage
        :return: the emitter typed with the resulting stack, i.e., having popped the value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """

    def name(self) -> str:
        """
        Get the name for this handler's local variable, named after the varnode is represents.
        
        :return: the name of the local variable
        :rtype: str
        """

    @staticmethod
    def nameVn(vn: ghidra.program.model.pcode.Varnode) -> str:
        """
        Generate a name for the variable representing the given varnode
         
        
        These are for debugging purposes. When dumping generating bytecode, the declared local
        variables and their scopes are often also dumped. This provides a human with the local
        variable index for various varnodes.
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the name
        :rtype: str
        """

    def subpiece(self, endian: ghidra.program.model.lang.Endian, byteOffset: typing.Union[jpype.JInt, int], maxByteSize: typing.Union[jpype.JInt, int]) -> VarHandler:
        """
        Create a handler for a :obj:`PcodeOp.SUBPIECE` of a value.
         
        
        To implement :obj:`subpiece <SubPieceOpGen>`, we could load the entire varnode and then
        extract the designated portion. Or, we could load only the designated portion, averting any
        code and execution cost of loading the un-designated portions. We accomplish this by
        re-writing the subpiece op and a load of the sub-varnode.
        
        :param ghidra.program.model.lang.Endian endian: the endianness of the emulation target
        :param jpype.JInt or int byteOffset: the number of least-significant bytes to remove
        :param jpype.JInt or int maxByteSize: the maximum size of the resulting variable. In general, a subpiece should
                    never exceed the size of the parent varnode, but if it does, this will truncate
                    that excess.
        :return: the resulting subpiece handler
        :rtype: VarHandler
        """

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType:
        """
        Get the p-code type of the local variable this handler uses.
        
        :return: the type
        :rtype: ghidra.pcode.emu.jit.analysis.JitType
        """

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        """
        Get the complete varnode accessible to this handler
        
        :return: the varnode
        :rtype: ghidra.program.model.pcode.Varnode
        """


class IntInIntHandler(java.lang.Record, SubVarHandler[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    The handler for an :obj:`int <IntJitType>` p-code variable stored in part of a JVM ``int``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, vn: ghidra.program.model.pcode.Varnode, byteShift: typing.Union[jpype.JInt, int]) -> None:
        ...

    def byteShift(self) -> int:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        ...

    def vn(self) -> ghidra.program.model.pcode.Varnode:
        ...


class SimpleVarHandler(VarHandler, typing.Generic[T, JT]):
    """
    A handler for p-code variables composed of a single JVM local variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def genLoadLegToStackC1(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, leg: typing.Union[jpype.JInt, int], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        This provides the implementation of
        :meth:`genLoadLegToStack(Emitter, JitCodeGenerator, MpIntJitType, int, Ext) <.genLoadLegToStack>` for category-1
        primitives, i.e., ``int`` and ``float``.
         
        
        Only leg 0 is meaningful for a category-1 primitive. Any other leg is just the extension of
        the one leg.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the complete multi-precision value
        :param jpype.JInt or int leg: the index of the leg to load, 0 being least significant
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def genLoadLegToStackC2(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], gen: ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any], type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, leg: typing.Union[jpype.JInt, int], ext: ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        This provides the implementation of
        :meth:`genLoadLegToStack(Emitter, JitCodeGenerator, MpIntJitType, int, Ext) <.genLoadLegToStack>` for category-2
        primitives, i.e., ``long`` and ``double``.
         
        
        Only legs 0 and 1 are meaningful for a category-2 primitive. Any other leg is just the
        extension of the upper leg.
        
        :param N: the incoming stack:param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter typed with the incoming stack
        :param ghidra.pcode.emu.jit.gen.JitCodeGenerator[typing.Any] gen: the code generator
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type of the complete multi-precision value
        :param jpype.JInt or int leg: the index of the leg to load, 0 being least significant
        :param ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext ext: the kind of extension to apply
        :return: the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def getConvToStack(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, T, JT]:
        """
        Get the converter of multi-precision integers to the stack type of this handler's local.
         
        
        Note that the converter need only extract the least 1 or 2 legs of the source multi-precision
        int, depending on the category of the destination's type. The converter knows how to handle
        both the operand (series of locals) and array forms.
        
        :return: the converter
        :rtype: ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, T, JT]
        """

    def local(self) -> JvmLocal[T, JT]:
        """
        Get the local variable into which this p-code variable is allocated
        
        :return: the local
        :rtype: JvmLocal[T, JT]
        """

    @property
    def convToStack(self) -> ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, T, JT]:
        ...


class SubInLongHandler(SubVarHandler[ST, SJT, ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType], typing.Generic[ST, SJT]):
    """
    A handler for a p-code variable stored in part of a JVM ``long``.
    """

    class_: typing.ClassVar[java.lang.Class]


class LongVarAlloc(java.lang.Record, SimpleVarHandler[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
    """
    The handler for a p-code variable allocated in one JVM ``long``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, local: JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType], type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> JvmLocal[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        ...



__all__ = ["JvmLocal", "ShiftedMpIntHandler", "NoHandler", "IntInLongHandler", "DoubleVarAlloc", "AlignedMpIntHandler", "LongInLongHandler", "IntVarAlloc", "SubVarHandler", "FloatVarAlloc", "VarHandler", "IntInIntHandler", "SimpleVarHandler", "SubInLongHandler", "LongVarAlloc"]
