from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.util.charset
import java.lang # type: ignore
import java.nio.charset # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


class CharsetPickerPanel(javax.swing.JPanel):
    """
    JPanel that displays a table of all charsets on top and a detail panel on bottom.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, charsetListener: java.util.function.Consumer[java.nio.charset.Charset]) -> None:
        ...

    def getSelectedCharset(self) -> ghidra.util.charset.CharsetInfo:
        ...

    def setCharsetListener(self, charsetListener: java.util.function.Consumer[java.nio.charset.Charset]) -> None:
        ...

    def setSelectedCharset(self, csi: ghidra.util.charset.CharsetInfo) -> None:
        ...

    @property
    def selectedCharset(self) -> ghidra.util.charset.CharsetInfo:
        ...

    @selectedCharset.setter
    def selectedCharset(self, value: ghidra.util.charset.CharsetInfo):
        ...


class CharsetPickerDialog(docking.DialogComponentProvider):
    """
    Dialog that displays a charset picker table and lets the user press ok or cancel.
     
    
    Call :meth:`getSelectedCharset() <.getSelectedCharset>` after the dialog closes to get the selected value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def getSelectedCharset(self) -> ghidra.util.charset.CharsetInfo:
        ...

    @staticmethod
    def pickCharset(defaultCSI: ghidra.util.charset.CharsetInfo) -> ghidra.util.charset.CharsetInfo:
        """
        Allows user to pick a charset from a table in a modal dialog.
        
        :param ghidra.util.charset.CharsetInfo defaultCSI: default charset to initially select in the table
        :return: selected charset, or null if canceled
        :rtype: ghidra.util.charset.CharsetInfo
        """

    def setSelectedCharset(self, csi: ghidra.util.charset.CharsetInfo) -> None:
        ...

    @property
    def selectedCharset(self) -> ghidra.util.charset.CharsetInfo:
        ...

    @selectedCharset.setter
    def selectedCharset(self, value: ghidra.util.charset.CharsetInfo):
        ...


@typing.type_check_only
class CharsetTableModel(docking.widgets.table.AbstractSortedTableModel[CharsetTableRow]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def findCharset(self, csi: ghidra.util.charset.CharsetInfo) -> int:
        ...


class CharsetInfoPanel(javax.swing.JPanel):
    """
    A JPanel that displays the details about a :obj:`CharsetInfo` object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def setCharset(self, csi: ghidra.util.charset.CharsetInfo) -> None:
        ...


@typing.type_check_only
class CharsetTableRow(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def csi(self) -> ghidra.util.charset.CharsetInfo:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def scripts(self) -> str:
        ...

    def toString(self) -> str:
        ...



__all__ = ["CharsetPickerPanel", "CharsetPickerDialog", "CharsetTableModel", "CharsetInfoPanel", "CharsetTableRow"]
