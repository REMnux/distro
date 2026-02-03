from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.internal
import docking.widgets.fieldpanel.support
import ghidra.program.model.address
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


class DebuggerTrackedRegisterBackgroundColorModel(docking.widgets.fieldpanel.support.BackgroundColorModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MultiSelectionBlendedLayoutBackgroundColorManager(docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager):

    class ColoredFieldSelection(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, selection: docking.widgets.fieldpanel.support.FieldSelection, color: java.awt.Color):
            ...

        def contains(self, loc: docking.widgets.fieldpanel.support.FieldLocation) -> bool:
            ...

        def containsEntirely(self, range: docking.widgets.fieldpanel.support.FieldRange) -> bool:
            ...

        def excludesEntirely(self, range: docking.widgets.fieldpanel.support.FieldRange) -> bool:
            ...

        def intersect(self, index: java.math.BigInteger) -> MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection:
            ...

        def isEmpty(self) -> bool:
            ...

        def isTotal(self, index: java.math.BigInteger) -> bool:
            ...

        @property
        def total(self) -> jpype.JBoolean:
            ...

        @property
        def empty(self) -> jpype.JBoolean:
            ...


    class MultiSelectionBlendedFieldBackgroundColorManager(docking.widgets.fieldpanel.internal.FieldBackgroundColorManager):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], layoutSelection: MultiSelectionBlendedLayoutBackgroundColorManager, selections: java.util.List[MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection], backgroundColor: java.awt.Color):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, index: java.math.BigInteger, selections: java.util.List[MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection], backgroundColor: java.awt.Color, leftBorderColor: java.awt.Color, rightBorderColor: java.awt.Color):
        ...

    @staticmethod
    def getLayoutColorMap(index: java.math.BigInteger, selections: collections.abc.Sequence, backgroundColor: java.awt.Color, isBackgroundDefault: typing.Union[jpype.JBoolean, bool]) -> docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager:
        ...


class SelectionTranslator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def convertAddressToField(self, addresses: ghidra.program.model.address.AddressSetView) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @typing.overload
    def convertAddressToField(self, range: ghidra.program.model.address.AddressRange) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @typing.overload
    def convertAddressToField(self, address: ghidra.program.model.address.Address) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    def convertFieldToAddress(self, fieldSelection: docking.widgets.fieldpanel.support.FieldSelection) -> ghidra.program.model.address.AddressSetView:
        ...


class SelectionGenerator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addSelections(self, layoutIndex: java.math.BigInteger, translator: SelectionTranslator, selections: java.util.List[MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection]):
        ...



__all__ = ["DebuggerTrackedRegisterBackgroundColorModel", "MultiSelectionBlendedLayoutBackgroundColorManager", "SelectionTranslator", "SelectionGenerator"]
