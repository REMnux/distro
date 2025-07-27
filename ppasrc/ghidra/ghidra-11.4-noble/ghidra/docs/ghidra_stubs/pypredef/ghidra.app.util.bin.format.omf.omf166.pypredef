from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import java.lang # type: ignore


class Omf166RecordTypes(java.lang.Object):
    """
    OMF-166 record types
    
    
    .. seealso::
    
        | `OMF-166 Description <https://www.keil.com/download/files/omf166.pdf>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    RTXDEF: typing.Final = 48
    DEPLST: typing.Final = 112
    REGMSK: typing.Final = 114
    TYPNEW: typing.Final = 240
    BLKEND: typing.Final = 124
    THEADR: typing.Final = 128
    LHEADR: typing.Final = 130
    COMMENT: typing.Final = 136
    MODEND: typing.Final = 138
    LINNUM: typing.Final = 148
    LNAMES: typing.Final = 150
    LIBLOC: typing.Final = 168
    LIBNAMES: typing.Final = 166
    LIBDICT: typing.Final = 170
    LIBHDR: typing.Final = 186
    PHEADR: typing.Final = 224
    PECDEF: typing.Final = 228
    SSKDEF: typing.Final = 229
    MODINF: typing.Final = 231
    TSKDEF: typing.Final = 225
    REGDEF: typing.Final = 227
    SEDEF: typing.Final = 176
    TYPDEF: typing.Final = 178
    GRPDEF: typing.Final = 177
    PUBDEF: typing.Final = 179
    GLBDEF: typing.Final = 230
    EXTDEF: typing.Final = 140
    LOCSYM: typing.Final = 181
    BLKDEF: typing.Final = 183
    DEBSYM: typing.Final = 182
    LEDATA: typing.Final = 184
    PEDATA: typing.Final = 185
    VECTAB: typing.Final = 233
    FIXUPP: typing.Final = 180
    TSKEND: typing.Final = 226
    XSECDEF: typing.Final = 197

    def __init__(self):
        ...

    @staticmethod
    def getName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the name of the given record type
        
        :param jpype.JInt or int type: The record type
        :return: The name of the given record type
        :rtype: str
        """


class Omf166DepList(ghidra.app.util.bin.format.omf.OmfRecord):

    @typing.type_check_only
    class Info(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def mark(self) -> int:
            ...

        def name(self) -> ghidra.app.util.bin.format.omf.OmfString:
            ...

        def time(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...



__all__ = ["Omf166RecordTypes", "Omf166DepList"]
