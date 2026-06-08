from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu.jit.gen.util
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


FJT = typing.TypeVar("FJT")
FLT = typing.TypeVar("FLT")
FT = typing.TypeVar("FT")
JT = typing.TypeVar("JT")
N = typing.TypeVar("N")
N0 = typing.TypeVar("N0")
N1 = typing.TypeVar("N1")
N2 = typing.TypeVar("N2")
T = typing.TypeVar("T")
TJT = typing.TypeVar("TJT")
TLT = typing.TypeVar("TLT")
TT = typing.TypeVar("TT")


@typing.type_check_only
class DoubleConstOpnd(java.lang.Record, ConstSimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
    """
    A constant ``double``
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType:
        ...

    def value(self) -> float:
        ...


@typing.type_check_only
class IntLocalOpnd(java.lang.Record, LocalOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    A ``int`` local variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TInt]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        ...


@typing.type_check_only
class ConstSimpleOpnd(SimpleOpnd[T, JT], typing.Generic[T, JT]):
    """
    A constant that can be pushed onto the JVM stack
    """

    class_: typing.ClassVar[java.lang.Class]

    def tempName(self) -> str:
        """
        Generate a name should this need conversion into a temporary variable
        
        :return: the name
        :rtype: str
        """


@typing.type_check_only
class MpIntConstOpnd(java.lang.Record, Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
    """
    A constant multi-precision integer operand
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: java.math.BigInteger, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def legsLE(self) -> java.util.List[IntConstOpnd]:
        ...

    def name(self) -> str:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        ...


@typing.type_check_only
class FloatLocalOpnd(java.lang.Record, LocalOpnd[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
    """
    A ``float`` local variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TFloat]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.FloatJitType:
        ...


@typing.type_check_only
class LongLocalOpnd(java.lang.Record, LocalOpnd[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
    """
    A ``long`` local variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TLong]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        ...


@typing.type_check_only
class IntReadOnlyLocalOpnd(java.lang.Record, LocalOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    A ``int`` local variable that cannot be used for temporary values
    
    
    .. seealso::
    
        | :obj:`SimpleOpnd.ofIntReadOnly(IntJitType, Local)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TInt]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        ...


class Opnd(java.lang.Object, typing.Generic[T]):
    """
    A (sometimes temporary) operand
     
    
    This class is also the namespace for a number of convesion operations. Please note that
    "conversions" here deal entirely in bits. While a lot of machinery is needed to represent p-code
    values, esp., when the number of bytes exceeds a JVM long, in essence, every conversion
    operation, if it performs any operation at all, is merely *bit* truncation or extension.
    Otherwise, all we are doing is convincing the JVM that the operand's type has changed. In
    particular, an int-to-float conversion is *not* accomplished using :meth:`i2f <Op.i2f>`, as that would actually change the raw bit contents of the value. Rather, we use
    :meth:`Float.intBitsToFloat(int) <Float.intBitsToFloat>`.
    """

    class OpndEm(java.lang.Record, typing.Generic[T, N]):
        """
        An operand-emitter tuple
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, opnd: Opnd[T], em: ghidra.pcode.emu.jit.gen.util.Emitter[N]) -> None:
            ...

        def castBack(self, to: TT, from_: T) -> Opnd.OpndEm[TT, N]:
            ...

        def em(self) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def opnd(self) -> Opnd[T]:
            ...

        def toString(self) -> str:
            ...


    class StackToStackConv(java.lang.Object, typing.Generic[FT, FJT, TT, TJT]):
        """
        An interface for converting between simple stack operands
        """

        class_: typing.ClassVar[java.lang.Class]

        def convertStackToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, to: TJT, ext: Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]:
            """
            Convert a stack operand to another stack operand
            
            :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
            :param FJT from: the source p-code type
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :return: the emitter with ..., result
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]
            """


    class StackToMpConv(java.lang.Object, typing.Generic[FT, FJT, TT, TLT, TJT]):
        """
        An interface for converting simple stack operands to multi-precision operands
        """

        class_: typing.ClassVar[java.lang.Class]

        def convertStackToArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, name: typing.Union[java.lang.String, str], to: TJT, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
            """
            Convert a stack operand to an mp operand in an array
            
            :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
            :param FJT from: the source p-code type
            :param java.lang.String or str name: the name to give the resulting operand
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary locals
            :param jpype.JInt or int slack: the number of extra (more significant) elements to allocate in the array
            :return: the emitter with ..., arrayref
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
            """

        def convertStackToOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, name: typing.Union[java.lang.String, str], to: TJT, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> Opnd.OpndEm[TJT, N1]:
            """
            Convert a stack operand to an mp operand in locals
            
            :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
            :param FJT from: the source p-code type
            :param java.lang.String or str name: the name to give the resulting operand
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary locals
            :return: the resulting operand and the emitter with ...
            :rtype: Opnd.OpndEm[TJT, N1]
            """


    class MpToStackConv(java.lang.Object, typing.Generic[FT, FLT, FJT, TT, TJT]):
        """
        An interface for converting multi-precision operands to simple stack operands
        """

        class_: typing.ClassVar[java.lang.Class]

        def convertArrayToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, to: TJT, ext: Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]:
            """
            Convert an mp operand in an array to a stack operand
            
            :param N1: the tail of the stack (...):param N0: ..., arrayref:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
            :param FJT from: the source p-code type
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :return: the emitter with ..., result
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]
            """

        def convertOpndToStack(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], from_: Opnd[FJT], to: TJT, ext: Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, TT]]:
            """
            Convert an mp operand in locals to a stack operand
            
            :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
            :param Opnd[FJT] from: the source operand
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :return: the emitter with ..., result
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, TT]]
            """


    class MpToMpConv(java.lang.Object, typing.Generic[FT, FLT, FJT, TT, TLT, TJT]):
        """
        An interface for converting between multi-precision operands
        """

        class_: typing.ClassVar[java.lang.Class]

        def convertOpndToArray(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], from_: Opnd[FJT], to: TJT, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
            """
            Convert an operand in locals to an array
            
            :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
            :param Opnd[FJT] from: the source operand
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary variables
            :param jpype.JInt or int slack: the number of extra (more significant) elements to allocate in the array
            :return: the emitter with ..., arrayref
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
            """

        def convertOpndToOpnd(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], from_: Opnd[FJT], to: TJT, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> Opnd.OpndEm[TJT, N]:
            """
            Convert an operand in locals to another in locals
             
            
            NOTE: This may be accomplished in part be re-using legs from the source operand in the
            destination operand
            
            :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
            :param Opnd[FJT] from: the source operand
            :param TJT to: the destination p-code type
            :param Opnd.Ext ext: the kind of extension to apply
            :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary variables
            :return: the resulting operand and emitter with ...
            :rtype: Opnd.OpndEm[TJT, N]
            """


    class IntToInt(java.lang.Enum[Opnd.IntToInt], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
        """
        Converter from int to int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.IntToInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.IntToInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.IntToInt]:
            ...


    class IntToLong(java.lang.Enum[Opnd.IntToLong], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
        """
        Converter from int to long
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.IntToLong]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.IntToLong:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.IntToLong]:
            ...


    class IntToMpInt(java.lang.Enum[Opnd.IntToMpInt], Opnd.StackToMpConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
        """
        Converter from int to mp-int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.IntToMpInt]

        def doConvert(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N], temp: SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType], name: typing.Union[java.lang.String, str], to: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> Opnd.OpndEm[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, N]:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.IntToMpInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.IntToMpInt]:
            ...


    class IntToFloat(java.lang.Enum[Opnd.IntToFloat], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
        """
        Converter from int to float
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.IntToFloat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.IntToFloat:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.IntToFloat]:
            ...


    class IntToDouble(java.lang.Enum[Opnd.IntToDouble], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
        """
        Converter from int to double
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.IntToDouble]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.IntToDouble:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.IntToDouble]:
            ...


    class LongToInt(java.lang.Enum[Opnd.LongToInt], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
        """
        Converter from long to int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.LongToInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.LongToInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.LongToInt]:
            ...


    class LongToLong(java.lang.Enum[Opnd.LongToLong], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType, ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
        """
        Converter from long to long
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.LongToLong]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.LongToLong:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.LongToLong]:
            ...


    class LongToMpInt(java.lang.Enum[Opnd.LongToMpInt], Opnd.StackToMpConv[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
        """
        Converter from long to mp-int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.LongToMpInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.LongToMpInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.LongToMpInt]:
            ...


    class LongToFloat(java.lang.Enum[Opnd.LongToFloat], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType, ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
        """
        Converter from long to float
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.LongToFloat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.LongToFloat:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.LongToFloat]:
            ...


    class LongToDouble(java.lang.Enum[Opnd.LongToDouble], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType, ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
        """
        Converter from long to double
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.LongToDouble]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.LongToDouble:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.LongToDouble]:
            ...


    class MpIntToInt(java.lang.Enum[Opnd.MpIntToInt], Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
        """
        Converter from mp-int to (simple) int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.MpIntToInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.MpIntToInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.MpIntToInt]:
            ...


    class MpIntToLong(java.lang.Enum[Opnd.MpIntToLong], Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
        """
        Converter from mp-int to long
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.MpIntToLong]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.MpIntToLong:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.MpIntToLong]:
            ...


    class MpIntToMpInt(java.lang.Enum[Opnd.MpIntToMpInt], Opnd.MpToMpConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
        """
        Converter from mp-int to mp-int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.MpIntToMpInt]

        @staticmethod
        def doGenArrExt(em: ghidra.pcode.emu.jit.gen.util.Emitter[N], arr: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]], legsOut: typing.Union[jpype.JInt, int], defLegs: typing.Union[jpype.JInt, int], ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
            """
            Emit code that extends a value to fill the rest of an array
             
            
            For sign extension, this will assume the last filled element of the array so far is the
            leg having the sign bit. It shifts and extends that bit to fill a new temporary leg and
            uses it to fill the remaining more-significant legs. NOTE: ``legsOut`` may be less
            than the actual size of the array, since slack elements may have been allocated.
            
            :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
            :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]] arr: a handle to the local containing the array
            :param jpype.JInt or int legsOut: the number of output legs
            :param jpype.JInt or int defLegs: the number of legs already filled
            :param Opnd.Ext ext: the kind of extension to apply
            :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary variables
            :return: the emitter with ...
            :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N]
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.MpIntToMpInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.MpIntToMpInt]:
            ...


    class MpIntToFloat(java.lang.Enum[Opnd.MpIntToFloat], Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
        """
        Converter from mp-int to (simple) float
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.MpIntToFloat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.MpIntToFloat:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.MpIntToFloat]:
            ...


    class MpIntToDouble(java.lang.Enum[Opnd.MpIntToDouble], Opnd.MpToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
        """
        Converter from mp-int to double
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.MpIntToDouble]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.MpIntToDouble:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.MpIntToDouble]:
            ...


    class FloatToInt(java.lang.Enum[Opnd.FloatToInt], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
        """
        Converter from float to int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.FloatToInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.FloatToInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.FloatToInt]:
            ...


    class FloatToLong(java.lang.Enum[Opnd.FloatToLong], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
        """
        Converter from float to long
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.FloatToLong]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.FloatToLong:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.FloatToLong]:
            ...


    class FloatToMpInt(java.lang.Enum[Opnd.FloatToMpInt], Opnd.StackToMpConv[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
        """
        Converter from float to mp-int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.FloatToMpInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.FloatToMpInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.FloatToMpInt]:
            ...


    class FloatToFloat(java.lang.Enum[Opnd.FloatToFloat], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
        """
        Converter from float to float
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.FloatToFloat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.FloatToFloat:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.FloatToFloat]:
            ...


    class FloatToDouble(java.lang.Enum[Opnd.FloatToDouble], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
        """
        Converter from float to double
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.FloatToDouble]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.FloatToDouble:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.FloatToDouble]:
            ...


    class DoubleToInt(java.lang.Enum[Opnd.DoubleToInt], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
        """
        Converter from double to int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.DoubleToInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.DoubleToInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.DoubleToInt]:
            ...


    class DoubleToLong(java.lang.Enum[Opnd.DoubleToLong], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
        """
        Converter from double to long
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.DoubleToLong]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.DoubleToLong:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.DoubleToLong]:
            ...


    class DoubleToMpInt(java.lang.Enum[Opnd.DoubleToMpInt], Opnd.StackToMpConv[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
        """
        Converter from double to mp-int
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.DoubleToMpInt]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.DoubleToMpInt:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.DoubleToMpInt]:
            ...


    class DoubleToFloat(java.lang.Enum[Opnd.DoubleToFloat], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):
        """
        Converter from double to float
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.DoubleToFloat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.DoubleToFloat:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.DoubleToFloat]:
            ...


    class DoubleToDouble(java.lang.Enum[Opnd.DoubleToDouble], Opnd.StackToStackConv[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
        """
        Converter from double to double
        """

        class_: typing.ClassVar[java.lang.Class]
        INSTANCE: typing.Final[Opnd.DoubleToDouble]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.DoubleToDouble:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.DoubleToDouble]:
            ...


    class Ext(java.lang.Enum[Opnd.Ext]):
        """
        Kinds of extension
        """

        class_: typing.ClassVar[java.lang.Class]
        ZERO: typing.Final[Opnd.Ext]
        """
        Zero extension
        """

        SIGN: typing.Final[Opnd.Ext]
        """
        Sign extension
        """


        @staticmethod
        def forSigned(signed: typing.Union[jpype.JBoolean, bool]) -> Opnd.Ext:
            """
            Get the extension based on signedness
            
            :param jpype.JBoolean or bool signed: true for signed, false for unsigned
            :return: the kind of extension
            :rtype: Opnd.Ext
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Opnd.Ext:
            ...

        @staticmethod
        def values() -> jpype.JArray[Opnd.Ext]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def castStack1(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, to: TJT) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]:
        """
        Emit nothing, but cast the emitter by asserting two given p-code types are identical
         
        
        This is often used in switch statements where the cases are specific types. Likely the switch
        variable has a generic type. For a given case, we know that generic type is identical to a
        given p-code type, but to convince the Java compiler, we need to cast. This method provides a
        structured mechanism for that cast to prevent mistakes. Additionally, at runtime, if
        assertions are enabled, this will fail when the given types are not actually identical.
        
        :param TT: the "to" JVM type:param TJT: the "to" p-code type:param FT: the "from" JVM type:param FJT: the "from" p-code type:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param FJT from: the p-code type
        :param TJT to: the same p-code type, but with an apparently different type at compile time
        :return: the emitter with ..., value (unchanged)
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]
        """

    @staticmethod
    @typing.overload
    def constOf(type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, value: typing.Union[jpype.JInt, int]) -> SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]:
        """
        Create a constant int operand of the given type
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type
        :param jpype.JInt or int value: the value
        :return: the constant
        :rtype: SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]
        """

    @staticmethod
    @typing.overload
    def constOf(type: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, value: typing.Union[jpype.JLong, int]) -> SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]:
        """
        Create a constant long operand of the given type
        
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType type: the p-code type
        :param jpype.JLong or int value: the value
        :return: the constant
        :rtype: SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]
        """

    @staticmethod
    @typing.overload
    def constOf(type: ghidra.pcode.emu.jit.analysis.JitType.FloatJitType, value: typing.Union[jpype.JFloat, float]) -> SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]:
        """
        Create a constant float operand of the given type
        
        :param ghidra.pcode.emu.jit.analysis.JitType.FloatJitType type: the p-code type
        :param jpype.JFloat or float value: the value
        :return: the constant
        :rtype: SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]
        """

    @staticmethod
    @typing.overload
    def constOf(type: ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType, value: typing.Union[jpype.JDouble, float]) -> SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]:
        """
        Create a constant double operand of the given type
        
        :param ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType type: the p-code type
        :param jpype.JDouble or float value: the value
        :return: the constant
        :rtype: SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]
        """

    @staticmethod
    @typing.overload
    def constOf(type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, value: java.math.BigInteger) -> Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]:
        """
        Create a constant mp-int operand of the given type
        
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type
        :param java.math.BigInteger value: the value
        :return: the constant
        :rtype: Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]
        """

    @staticmethod
    def convert(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, to: TJT, ext: Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]:
        """
        Convert from a given simple type to another simple type
        
        :param FT: the "from" JVM type:param FJT: the "from" p-code type:param TT: the "to" JVM type:param TJT: the "to" p-code type:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param FJT from: the source p-code type
        :param TJT to: the destination p-code type
        :param Opnd.Ext ext: the kind of extension to apply
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, TT]]
        """

    @staticmethod
    def convertIntToInt(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, ext: Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Convert from an int type to another int type
        
        :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType from: the source p-code type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination p-code type
        :param Opnd.Ext ext: the kind of extension to apply
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    @staticmethod
    def convertToArray(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, name: typing.Union[java.lang.String, str], to: TJT, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope, slack: typing.Union[jpype.JInt, int]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]:
        """
        Convert from a simple type to an mp type in an array
        
        :param FT: the "from" JVM type:param FJT: the "from" p-code type:param TT: the "to" JVM type for each mp leg:param TLT: the "to" p-code type for each mp leg:param TJT: the "to" p-code type:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param FJT from: the source p-code type
        :param java.lang.String or str name: a name (prefix) for the mp-int
        :param TJT to: the destination p-code type
        :param Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated variables
        :param jpype.JInt or int slack: the number of extra (more significant) elements to allocate in the array
        :return: the emitter with ..., arrayref
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TRef[jpype.JArray[jpype.JInt]]]]
        """

    @staticmethod
    def convertToOpnd(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], from_: FJT, name: typing.Union[java.lang.String, str], to: TJT, ext: Opnd.Ext, scope: ghidra.pcode.emu.jit.gen.util.Scope) -> Opnd.OpndEm[TJT, N1]:
        """
        Convert from a simple type to an mp type in local variables
        
        :param FT: the "from" JVM type:param FJT: the "from" p-code type:param TT: the "to" JVM type for each mp leg:param TLT: the "to" p-code type for each mp leg:param TJT: the "to" p-code type:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param FJT from: the source p-code type
        :param java.lang.String or str name: a name (prefix) for the mp-int
        :param TJT to: the destination p-code type
        :param Opnd.Ext ext: the kind of extension to apply
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated variables
        :return: the resulting operand and emitter with ...
        :rtype: Opnd.OpndEm[TJT, N1]
        """

    @staticmethod
    def create(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: JT, name: typing.Union[java.lang.String, str], scope: ghidra.pcode.emu.jit.gen.util.Scope) -> SimpleOpnd.SimpleOpndEm[T, JT, N1]:
        """
        Create an operand of the given p-code type from the value on the stack
        
        :param T: the JVM type:param JT: the p-code type:param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param JT type: the p-code type
        :param java.lang.String or str name: the name of the local variable to create
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for the local variable
        :return: the operand and emitter with ...
        :rtype: SimpleOpnd.SimpleOpndEm[T, JT, N1]
        """

    @staticmethod
    def createInt(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, name: typing.Union[java.lang.String, str], scope: ghidra.pcode.emu.jit.gen.util.Scope) -> SimpleOpnd.SimpleOpndEm[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, N1]:
        """
        Create an int operand from the value on the stack
        
        :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type
        :param java.lang.String or str name: the name of the local variable to create
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for the local variable
        :return: the operand and emitter with ...
        :rtype: SimpleOpnd.SimpleOpndEm[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, N1]
        """

    @staticmethod
    def createIntReadOnly(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, name: typing.Union[java.lang.String, str], scope: ghidra.pcode.emu.jit.gen.util.Scope) -> SimpleOpnd.SimpleOpndEm[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, N1]:
        """
        Create a read-only int operand from the value on the stack
        
        :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type
        :param java.lang.String or str name: the name of the local variable to create
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for the local variable
        :return: the operand and emitter with ...
        :rtype: SimpleOpnd.SimpleOpndEm[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType, N1]
        
        .. seealso::
        
            | :obj:`SimpleOpnd.ofIntReadOnly(IntJitType, Local)`
        """

    @staticmethod
    def getStackToMp(from_: FJT, to: TJT) -> Opnd.StackToMpConv[FT, FJT, TT, TLT, TJT]:
        """
        Obtain the converter from a simple type to an mp type
        
        :param FT: the "from" JVM type:param FJT: the "from" p-code type:param TT: the "to" JVM type for each mp leg:param TLT: the "to" p-code type for each mp leg:param TJT: the "to" p-code type:param FJT from: the source p-code type
        :param TJT to: the destination p-code type
        :return: the converter
        :rtype: Opnd.StackToMpConv[FT, FJT, TT, TLT, TJT]
        """

    @staticmethod
    def getStackToStack(from_: FJT, to: TJT) -> Opnd.StackToStackConv[FT, FJT, TT, TJT]:
        """
        Obtain the converter between two given simple types
        
        :param FT: the "from" JVM type:param FJT: the "from" p-code type:param TT: the "to" JVM type:param TJT: the "to" p-code type:param FJT from: the source p-code type
        :param TJT to: the destination p-code type
        :return: the converter
        :rtype: Opnd.StackToStackConv[FT, FJT, TT, TJT]
        """

    @staticmethod
    def intToBool(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]:
        """
        Emit code to convert a simple int to a boolean
         
        
        This treats any non-zero value as true. Only zero is treated as false. The result is either 1
        (true) or 0 (false). In other words, this converts any non-zero value to 1. Zero is left as
        0.
        
        :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :return: ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N1, ghidra.pcode.emu.jit.gen.util.Types.TInt]]
        """

    def legsLE(self) -> java.util.List[SimpleOpnd[typing.Any, typing.Any]]:
        """
        :return: the legs in little-endian order
        :rtype: java.util.List[SimpleOpnd[typing.Any, typing.Any]]
        
         
        
        For non-legged types, this returns the singleton list containing only this operand
        """

    @staticmethod
    def lextshr(em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], ext: Opnd.Ext) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TLong]]:
        """
        Emit a long left shift, selecting signed or unsigned by the given extension
        
        :param N2: the tail of the stack (...):param N1: ..., value1:param N0: ..., value1, value2:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param Opnd.Ext ext: the kind of extension to apply
        :return: the emitter with ..., result
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N2, ghidra.pcode.emu.jit.gen.util.Types.TLong]]
        """

    def name(self) -> str:
        """
        :return: the name
        :rtype: str
        """

    @staticmethod
    def needsIntExt(from_: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, to: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> bool:
        """
        Check if the given int-to-int conversion would require extension
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType from: the source p-code type
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType to: the destination p-code type
        :return: true if extension is needed, i.e., ``to`` is strictly larger than ``from``
        :rtype: bool
        """

    @staticmethod
    def needsLongExt(from_: ghidra.pcode.emu.jit.analysis.JitType.LongJitType, to: ghidra.pcode.emu.jit.analysis.JitType.LongJitType) -> bool:
        """
        Check if the given long-to-long conversion would require extension
        
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType from: the source p-code type
        :param ghidra.pcode.emu.jit.analysis.JitType.LongJitType to: the destination p-code type
        :return: true if extension is needed, i.e., ``to`` is strictly larger than ``from``
        :rtype: bool
        """

    def type(self) -> T:
        """
        :return: the p-code type
        :rtype: T
        """


@typing.type_check_only
class DoubleLocalOpnd(java.lang.Record, LocalOpnd[ghidra.pcode.emu.jit.gen.util.Types.TDouble, ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType]):
    """
    A ``double`` local variable
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TDouble]:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType:
        ...


class IntConstOpnd(java.lang.Record, ConstSimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]):
    """
    A constant ``int``
    """

    class_: typing.ClassVar[java.lang.Class]
    ZERO_I1: typing.Final[IntConstOpnd]
    """
    0 of type :obj:`int1 <IntJitType.I1>`
    """

    ZERO_I2: typing.Final[IntConstOpnd]
    """
    0 of type :obj:`int2 <IntJitType.I2>`
    """

    ZERO_I3: typing.Final[IntConstOpnd]
    """
    0 of type :obj:`int3 <IntJitType.I3>`
    """

    ZERO_I4: typing.Final[IntConstOpnd]
    """
    0 of type :obj:`int4 <IntJitType.I4>`
    """


    def __init__(self, value: typing.Union[jpype.JInt, int], type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.IntJitType:
        ...

    def value(self) -> int:
        ...

    @staticmethod
    def zero(type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType) -> IntConstOpnd:
        """
        Get a constant 0 of the given p-code :obj:`int <IntJitType>` type.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the type
        :return: the constant 0
        :rtype: IntConstOpnd
        """


@typing.type_check_only
class LocalOpnd(SimpleOpnd[T, JT], typing.Generic[T, JT]):
    """
    A mutable operand that can be contained in a single JVM local
    """

    class_: typing.ClassVar[java.lang.Class]

    def local(self) -> ghidra.pcode.emu.jit.gen.util.Local[T]:
        """
        :return: the local handle
        :rtype: ghidra.pcode.emu.jit.gen.util.Local[T]
        """


@typing.type_check_only
class FloatConstOpnd(java.lang.Record, ConstSimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TFloat, ghidra.pcode.emu.jit.analysis.JitType.FloatJitType]):

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.FloatJitType:
        ...

    def value(self) -> float:
        ...


@typing.type_check_only
class LongConstOpnd(java.lang.Record, ConstSimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TLong, ghidra.pcode.emu.jit.analysis.JitType.LongJitType]):
    """
    A constant ``long``
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.LongJitType:
        ...

    def value(self) -> int:
        ...


class MpIntLocalOpnd(java.lang.Record, Opnd[ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType]):
    """
    A (usually mutable) multi-precision integer operand
     
    
    This may be composed of simple mutable and constant operands. The most common cause of constant
    operands is zero extension. It is also possible the same mutable (local) operand may appear more
    than once. The most common cause of such duplication is sign extension.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, name: typing.Union[java.lang.String, str], legsLE: java.util.List[SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]]) -> None:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def legsLE(self) -> java.util.List[SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]]:
        ...

    def name(self) -> str:
        ...

    @staticmethod
    def of(type: ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType, name: typing.Union[java.lang.String, str], legsLE: java.util.List[SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]]) -> MpIntLocalOpnd:
        """
        Create a multi-precision integer operand from the given legs
        
        :param ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType type: the p-code type
        :param java.lang.String or str name: the name (prefix) to use for generate temporary legs
        :param java.util.List[SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]] legsLE: the legs in little-endian order
        :return: the operand
        :rtype: MpIntLocalOpnd
        """

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType:
        ...


class SimpleOpnd(Opnd[JT], typing.Generic[T, JT]):
    """
    An operand stored in a single JVM local variable
    """

    class SimpleOpndEm(java.lang.Record, typing.Generic[T, JT, N]):
        """
        An operand-emitter tuple
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, opnd: SimpleOpnd[T, JT], em: ghidra.pcode.emu.jit.gen.util.Emitter[N]) -> None:
            ...

        def castBack(self, to: TJT) -> SimpleOpnd.SimpleOpndEm[TT, TJT, N]:
            """
            Cast the operand safely between generic and concrete type
             
            
            The given types are checked for equality at runtime, if assertions are enabled
            
            :param TT: the "to" JVM type:param TJT: the "to" p-code type:param TJT to: the destination p-code type
            :return: this cast to the same type, but expressed generically
            :rtype: SimpleOpnd.SimpleOpndEm[TT, TJT, N]
            """

        def em(self) -> ghidra.pcode.emu.jit.gen.util.Emitter[N]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def opnd(self) -> SimpleOpnd[T, JT]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def of(type: JT, local: ghidra.pcode.emu.jit.gen.util.Local[T]) -> SimpleOpnd[T, JT]:
        """
        Create a simple local operand
        
        :param T: the JVM type:param JT: the p-code type:param JT type: the p-code type
        :param ghidra.pcode.emu.jit.gen.util.Local[T] local: the JVM local
        :return: the operand
        :rtype: SimpleOpnd[T, JT]
        """

    @staticmethod
    def ofIntReadOnly(type: ghidra.pcode.emu.jit.analysis.JitType.IntJitType, local: ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TInt]) -> SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]:
        """
        Create a read-only ``int`` local operand
         
        
        Multi-precision integer operators work by composing several locals into a single p-code
        variable. Some of these operators need temporary variables. To avoid generating tons of
        those, we generally allow the temporary locals to be mutated. However, the local variables
        allocated to hold p-code variables cannot be mutated until the full output value has been
        successfully computed. Furthermore, we certainly cannot mutate any input operand by mistake.
        Using a read-only local for input operands ensures this does not happen. An attempt to write
        to one of these will instead generate a new temporary local, assign the value to it, and
        return the new operand. An attempt to write directly to this operand will result in an
        exception being thrown at generation time.
        
        :param ghidra.pcode.emu.jit.analysis.JitType.IntJitType type: the p-code type
        :param ghidra.pcode.emu.jit.gen.util.Local[ghidra.pcode.emu.jit.gen.util.Types.TInt] local: the local handle
        :return: the read-only operand
        :rtype: SimpleOpnd[ghidra.pcode.emu.jit.gen.util.Types.TInt, ghidra.pcode.emu.jit.analysis.JitType.IntJitType]
        """

    def read(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N]) -> ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]:
        """
        Emit code to read the operand onto the stack
        
        :param N: the tail of the stack (...):param ghidra.pcode.emu.jit.gen.util.Emitter[N] em: the emitter
        :return: the emitter with ..., value
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[ghidra.pcode.emu.jit.gen.util.Emitter.Ent[N, T]]
        """

    def write(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0], scope: ghidra.pcode.emu.jit.gen.util.Scope) -> SimpleOpnd.SimpleOpndEm[T, JT, N1]:
        """
        Emit code to write the operand from the stack
         
        
        This will generate a new operand if this operand is read-only. Callers must therefore be
        prepared to take the result in place of this operand.
        
        :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :param ghidra.pcode.emu.jit.gen.util.Scope scope: a scope for generated temporary variables
        :return: the resulting operand and emitter with ...
        :rtype: SimpleOpnd.SimpleOpndEm[T, JT, N1]
        """

    def writeDirect(self, em: ghidra.pcode.emu.jit.gen.util.Emitter[N0]) -> ghidra.pcode.emu.jit.gen.util.Emitter[N1]:
        """
        Emit code to write the operand, without generating a new operand
         
        
        This will throw an exception during generation if this operand is read-only. This should only
        be used when the caller is certain the operand can be written and when a scope is not
        available.
        
        :param N1: the tail of the stack (...):param N0: ..., value:param ghidra.pcode.emu.jit.gen.util.Emitter[N0] em: the emitter
        :return: the emitter with ...
        :rtype: ghidra.pcode.emu.jit.gen.util.Emitter[N1]
        """



__all__ = ["DoubleConstOpnd", "IntLocalOpnd", "ConstSimpleOpnd", "MpIntConstOpnd", "FloatLocalOpnd", "LongLocalOpnd", "IntReadOnlyLocalOpnd", "Opnd", "DoubleLocalOpnd", "IntConstOpnd", "LocalOpnd", "FloatConstOpnd", "LongConstOpnd", "MpIntLocalOpnd", "SimpleOpnd"]
