from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.app.plugin.core.debug
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.trace.model.program
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DebuggerCopyPlan(java.lang.Object):

    class Copier(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def copy(self, from_: ghidra.trace.model.program.TraceProgramView, fromRange: ghidra.program.model.address.AddressRange, into: ghidra.program.model.listing.Program, intoAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
            ...

        def getName(self) -> str:
            ...

        def getRequiredBy(self) -> java.util.Collection[DebuggerCopyPlan.Copier]:
            ...

        def getRequires(self) -> java.util.Collection[DebuggerCopyPlan.Copier]:
            ...

        def isAvailable(self, from_: ghidra.trace.model.program.TraceProgramView, into: ghidra.program.model.listing.Program) -> bool:
            ...

        def isRequiresInitializedMemory(self) -> bool:
            ...

        @property
        def requiredBy(self) -> java.util.Collection[DebuggerCopyPlan.Copier]:
            ...

        @property
        def requiresInitializedMemory(self) -> jpype.JBoolean:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def requires(self) -> java.util.Collection[DebuggerCopyPlan.Copier]:
            ...


    class AllCopiers(java.lang.Enum[DebuggerCopyPlan.AllCopiers], DebuggerCopyPlan.Copier):

        class_: typing.ClassVar[java.lang.Class]
        BYTES: typing.Final[DebuggerCopyPlan.AllCopiers]
        STATE: typing.Final[DebuggerCopyPlan.AllCopiers]
        INSTRUCTIONS: typing.Final[DebuggerCopyPlan.AllCopiers]
        DATA: typing.Final[DebuggerCopyPlan.AllCopiers]
        DYNAMIC_DATA: typing.Final[DebuggerCopyPlan.AllCopiers]
        LABELS: typing.Final[DebuggerCopyPlan.AllCopiers]
        BREAKPOINTS: typing.Final[DebuggerCopyPlan.AllCopiers]
        BOOKMARKS: typing.Final[DebuggerCopyPlan.AllCopiers]
        REFERENCES: typing.Final[DebuggerCopyPlan.AllCopiers]
        COMMENTS: typing.Final[DebuggerCopyPlan.AllCopiers]
        VALUES: typing.Final[java.util.List[DebuggerCopyPlan.Copier]]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerCopyPlan.AllCopiers:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerCopyPlan.AllCopiers]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def execute(self, from_: ghidra.trace.model.program.TraceProgramView, fromRange: ghidra.program.model.address.AddressRange, into: ghidra.program.model.listing.Program, intoAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        ...

    def getAllCopiers(self) -> java.util.Collection[DebuggerCopyPlan.Copier]:
        ...

    def getCheckBox(self, copier: DebuggerCopyPlan.Copier) -> javax.swing.JCheckBox:
        ...

    def isRequiresInitializedMemory(self, from_: ghidra.trace.model.program.TraceProgramView, dest: ghidra.program.model.listing.Program) -> bool:
        ...

    def selectAll(self):
        ...

    def selectNone(self):
        ...

    def syncCopiersEnabled(self, from_: ghidra.trace.model.program.TraceProgramView, dest: ghidra.program.model.listing.Program):
        ...

    @property
    def allCopiers(self) -> java.util.Collection[DebuggerCopyPlan.Copier]:
        ...

    @property
    def checkBox(self) -> javax.swing.JCheckBox:
        ...


class DebuggerCopyActionsPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerCopyIntoProgramDialog(docking.ReusableDialogComponentProvider):

    @typing.type_check_only
    class RangeEntry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getBlockName(self) -> str:
            ...

        def getDstMaxAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getDstMinAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getDstRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        def getModuleNames(self) -> str:
            ...

        def getRegionName(self) -> str:
            ...

        def getSectionNames(self) -> str:
            ...

        def getSrcMaxAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getSrcMinAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getSrcRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        def isCreate(self) -> bool:
            ...

        def isOverlay(self) -> bool:
            ...

        def setBlockName(self, blockName: typing.Union[java.lang.String, str]):
            ...

        @property
        def dstMinAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def overlay(self) -> jpype.JBoolean:
            ...

        @property
        def srcMinAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def blockName(self) -> java.lang.String:
            ...

        @blockName.setter
        def blockName(self, value: java.lang.String):
            ...

        @property
        def srcRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @property
        def regionName(self) -> java.lang.String:
            ...

        @property
        def create(self) -> jpype.JBoolean:
            ...

        @property
        def dstMaxAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def moduleNames(self) -> java.lang.String:
            ...

        @property
        def dstRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @property
        def sectionNames(self) -> java.lang.String:
            ...

        @property
        def srcMaxAddress(self) -> ghidra.program.model.address.Address:
            ...


    @typing.type_check_only
    class RangeTableColumns(java.lang.Enum[DebuggerCopyIntoProgramDialog.RangeTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerCopyIntoProgramDialog.RangeTableColumns, DebuggerCopyIntoProgramDialog.RangeEntry]):

        class_: typing.ClassVar[java.lang.Class]
        REMOVE: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        REGION: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        MODULES: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        SECTIONS: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        SRC_MIN: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        SRC_MAX: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        BLOCK: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        OVERLAY: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        DST_MIN: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]
        DST_MAX: typing.Final[DebuggerCopyIntoProgramDialog.RangeTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerCopyIntoProgramDialog.RangeTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerCopyIntoProgramDialog.RangeTableColumns]:
            ...


    @typing.type_check_only
    class RangeTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerCopyIntoProgramDialog.RangeTableColumns, DebuggerCopyIntoProgramDialog.RangeEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class CopyDestination(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getExistingProgram(self) -> ghidra.program.model.listing.Program:
            ...

        def getOrCreateProgram(self, source: ghidra.trace.model.program.TraceProgramView, consumer: java.lang.Object) -> ghidra.program.model.listing.Program:
            ...

        def isExisting(self) -> bool:
            ...

        def saveIfApplicable(self, program: ghidra.program.model.listing.Program):
            ...

        @property
        def existing(self) -> jpype.JBoolean:
            ...

        @property
        def existingProgram(self) -> ghidra.program.model.listing.Program:
            ...


    @typing.type_check_only
    class OpenProgramDestination(DebuggerCopyIntoProgramDialog.CopyDestination):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getDestination(self) -> DebuggerCopyIntoProgramDialog.CopyDestination:
        ...

    def isCapture(self) -> bool:
        ...

    def isRelocate(self) -> bool:
        ...

    def isUseOverlays(self) -> bool:
        ...

    def reset(self):
        """
        Re-populate the table based on destination and relocation settings
        """

    def setCapture(self, capture: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def setDestination(self, program: ghidra.program.model.listing.Program):
        ...

    @typing.overload
    def setDestination(self, dest: DebuggerCopyIntoProgramDialog.CopyDestination):
        ...

    def setProgramManager(self, programManager: ghidra.app.services.ProgramManager):
        ...

    def setRelocate(self, relocate: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSource(self, source: ghidra.trace.model.program.TraceProgramView, set: ghidra.program.model.address.AddressSetView):
        ...

    def setStaticMappingService(self, staticMappingService: ghidra.app.services.DebuggerStaticMappingService):
        ...

    def setTargetService(self, targetService: ghidra.app.services.DebuggerTargetService):
        ...

    def setUseOverlays(self, useOverlays: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def relocate(self) -> jpype.JBoolean:
        ...

    @relocate.setter
    def relocate(self, value: jpype.JBoolean):
        ...

    @property
    def destination(self) -> DebuggerCopyIntoProgramDialog.CopyDestination:
        ...

    @destination.setter
    def destination(self, value: DebuggerCopyIntoProgramDialog.CopyDestination):
        ...

    @property
    def capture(self) -> jpype.JBoolean:
        ...

    @capture.setter
    def capture(self, value: jpype.JBoolean):
        ...

    @property
    def useOverlays(self) -> jpype.JBoolean:
        ...

    @useOverlays.setter
    def useOverlays(self, value: jpype.JBoolean):
        ...



__all__ = ["DebuggerCopyPlan", "DebuggerCopyActionsPlugin", "DebuggerCopyIntoProgramDialog"]
