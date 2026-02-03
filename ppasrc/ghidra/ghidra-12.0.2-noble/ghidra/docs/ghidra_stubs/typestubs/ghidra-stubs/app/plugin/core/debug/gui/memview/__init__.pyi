from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.filter
import docking.widgets.table
import ghidra.app.plugin.core.debug
import ghidra.app.services
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.trace.model
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class MemviewProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: DebuggerMemviewPlugin):
        ...

    def addBox(self, box: MemoryBox):
        ...

    def addBoxes(self, blist: java.util.List[MemoryBox]):
        ...

    def applyFilter(self):
        ...

    def changeZoomA(self, changeAmount: typing.Union[jpype.JInt, int]):
        ...

    def changeZoomT(self, changeAmount: typing.Union[jpype.JInt, int]):
        ...

    def getZoomAmountA(self) -> float:
        ...

    def getZoomAmountT(self) -> float:
        ...

    @typing.overload
    def goTo(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def goTo(self, box: MemoryBox):
        ...

    def initViews(self):
        ...

    def isApplyFilter(self) -> bool:
        ...

    def refresh(self):
        ...

    def reset(self):
        ...

    def selectPanelPosition(self, boxes: java.util.Set[MemoryBox]):
        ...

    def selectTableEntry(self, boxes: java.util.Set[MemoryBox]):
        ...

    def setBoxes(self, blist: java.util.List[MemoryBox]):
        ...

    def setBoxesInPanel(self, blist: java.util.List[MemoryBox]):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    @property
    def zoomAmountT(self) -> jpype.JDouble:
        ...

    @property
    def zoomAmountA(self) -> jpype.JDouble:
        ...


class DebuggerMemviewPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin, MemviewService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def toggleTrackTrace(self):
        ...


@typing.type_check_only
class MemviewMapModel(docking.widgets.table.AbstractSortedTableModel[MemoryBox]):

    @typing.type_check_only
    class MemoryMapComparator(java.util.Comparator[MemoryBox]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, sortColumn: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: MemviewProvider):
        ...

    def addBoxes(self, boxes: collections.abc.Sequence):
        ...

    def findColumn(self, columnName: typing.Union[java.lang.String, str]) -> int:
        """
        Convenience method for locating columns by name. Implementation is naive so this should be
        overridden if this method is to be called often. This method is not in the TableModel
        interface and is not used by the JTable.
        """

    def getBoxAt(self, rowIndex: typing.Union[jpype.JInt, int]) -> MemoryBox:
        ...

    def getBoxes(self) -> java.util.List[MemoryBox]:
        ...

    def getColumnClass(self, columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Class[typing.Any]:
        """
        Returns Object.class by default
        """

    def getIndexForBox(self, box: MemoryBox) -> int:
        ...

    def getRowCount(self) -> int:
        """
        Returns the number of records managed by the data source object. A **JTable** uses this
        method to determine how many rows it should create and display. This method should be quick,
        as it is call by **JTable** quite frequently.
        
        :return: the number or rows in the model
        :rtype: int
        
        .. seealso::
        
            | :obj:`.getColumnCount`
        """

    def isCellEditable(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return whether this column is editable.
        """

    def reset(self):
        ...

    def setBoxes(self, boxes: collections.abc.Sequence):
        ...

    @property
    def boxes(self) -> java.util.List[MemoryBox]:
        ...

    @property
    def columnClass(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def boxAt(self) -> MemoryBox:
        ...

    @property
    def indexForBox(self) -> jpype.JInt:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...


class MemoryBox(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, trace: ghidra.trace.model.Trace, id: typing.Union[java.lang.String, str], type: MemviewBoxType, range: ghidra.program.model.address.AddressRange, tick: typing.Union[jpype.JLong, int], color: java.awt.Color):
        ...

    @typing.overload
    def __init__(self, trace: ghidra.trace.model.Trace, id: typing.Union[java.lang.String, str], type: MemviewBoxType, range: ghidra.program.model.address.AddressRange, tick: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, trace: ghidra.trace.model.Trace, id: typing.Union[java.lang.String, str], type: MemviewBoxType, range: ghidra.program.model.address.AddressRange, trange: ghidra.trace.model.Lifespan):
        ...

    def formatEnd(self) -> str:
        ...

    def formatStart(self) -> str:
        ...

    def getAddressPixelStart(self) -> int:
        ...

    def getAddressPixelWidth(self) -> int:
        ...

    def getAttributeMap(self) -> java.util.Map[java.lang.String, java.lang.Object]:
        ...

    def getColor(self) -> java.awt.Color:
        ...

    def getEnd(self) -> int:
        ...

    def getId(self) -> str:
        ...

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    def getSpan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getStart(self) -> int:
        ...

    def getStartAddress(self) -> int:
        ...

    def getStartTime(self) -> int:
        ...

    def getStopAddress(self) -> int:
        ...

    def getStopTime(self) -> int:
        ...

    def getTimePixelStart(self) -> int:
        ...

    def getTimePixelWidth(self) -> int:
        ...

    def getType(self) -> MemviewBoxType:
        ...

    def getX(self, vertical: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def getY(self, vertical: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    def inPixelRange(self, pos: typing.Union[jpype.JLong, int]) -> bool:
        ...

    def isCurrent(self) -> bool:
        ...

    def render(self, g: java.awt.Graphics, vertical: typing.Union[jpype.JBoolean, bool]):
        ...

    def renderBA(self, g: java.awt.Graphics, vertical: typing.Union[jpype.JBoolean, bool], sz: typing.Union[jpype.JInt, int]):
        ...

    def renderBT(self, g: java.awt.Graphics, vertical: typing.Union[jpype.JBoolean, bool], sz: typing.Union[jpype.JInt, int], bound: typing.Union[jpype.JInt, int]):
        ...

    def setAddressBounds(self, map: MemviewMap, bound: typing.Union[jpype.JInt, int]):
        ...

    def setColor(self, color: java.awt.Color):
        ...

    def setCurrent(self, current: typing.Union[jpype.JBoolean, bool]):
        ...

    def setEnd(self, tick: typing.Union[jpype.JLong, int]):
        ...

    def setStartAddress(self, val: typing.Union[jpype.JLong, int]):
        ...

    def setStartTime(self, val: typing.Union[jpype.JLong, int]):
        ...

    def setStopAddress(self, val: typing.Union[jpype.JLong, int]):
        ...

    def setStopTime(self, val: typing.Union[jpype.JLong, int]):
        ...

    def setTimeBounds(self, map: MemviewMap, bound: typing.Union[jpype.JInt, int]):
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @color.setter
    def color(self, value: java.awt.Color):
        ...

    @property
    def timePixelWidth(self) -> jpype.JInt:
        ...

    @property
    def startAddress(self) -> jpype.JLong:
        ...

    @startAddress.setter
    def startAddress(self, value: jpype.JLong):
        ...

    @property
    def start(self) -> jpype.JLong:
        ...

    @property
    def attributeMap(self) -> java.util.Map[java.lang.String, java.lang.Object]:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def type(self) -> MemviewBoxType:
        ...

    @property
    def addressPixelWidth(self) -> jpype.JInt:
        ...

    @property
    def stopAddress(self) -> jpype.JLong:
        ...

    @stopAddress.setter
    def stopAddress(self, value: jpype.JLong):
        ...

    @property
    def current(self) -> jpype.JBoolean:
        ...

    @current.setter
    def current(self, value: jpype.JBoolean):
        ...

    @property
    def addressPixelStart(self) -> jpype.JInt:
        ...

    @property
    def x(self) -> jpype.JInt:
        ...

    @property
    def y(self) -> jpype.JInt:
        ...

    @property
    def stopTime(self) -> jpype.JLong:
        ...

    @stopTime.setter
    def stopTime(self, value: jpype.JLong):
        ...

    @property
    def startTime(self) -> jpype.JLong:
        ...

    @startTime.setter
    def startTime(self, value: jpype.JLong):
        ...

    @property
    def end(self) -> jpype.JLong:
        ...

    @end.setter
    def end(self, value: jpype.JLong):
        ...

    @property
    def id(self) -> java.lang.String:
        ...

    @property
    def timePixelStart(self) -> jpype.JInt:
        ...

    @property
    def span(self) -> ghidra.trace.model.Lifespan:
        ...


class DebuggerMemviewTraceListener(ghidra.trace.model.TraceDomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: MemviewProvider):
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def getProvider(self) -> MemviewProvider:
        ...

    def setCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def toggleTrackTrace(self):
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def provider(self) -> MemviewProvider:
        ...


class MemviewService(java.lang.Object):
    """
    The MemviewService provides a general service for displaying objects
    on time vs. memory axes (a la Boxes)
    """

    class_: typing.ClassVar[java.lang.Class]

    def getProvider(self) -> MemviewProvider:
        ...

    def initViews(self):
        ...

    def setBoxes(self, boxList: java.util.List[MemoryBox]):
        ...

    def setProgram(self, currentProgram: ghidra.program.model.listing.Program):
        ...

    @property
    def provider(self) -> MemviewProvider:
        ...


class MemviewBoxType(java.lang.Enum[MemviewBoxType]):

    class_: typing.ClassVar[java.lang.Class]
    INSTRUCTIONS: typing.Final[MemviewBoxType]
    PROCESS: typing.Final[MemviewBoxType]
    THREAD: typing.Final[MemviewBoxType]
    MODULE: typing.Final[MemviewBoxType]
    REGION: typing.Final[MemviewBoxType]
    IMAGE: typing.Final[MemviewBoxType]
    VIRTUAL_ALLOC: typing.Final[MemviewBoxType]
    HEAP_CREATE: typing.Final[MemviewBoxType]
    HEAP_ALLOC: typing.Final[MemviewBoxType]
    POOL: typing.Final[MemviewBoxType]
    STACK: typing.Final[MemviewBoxType]
    PERFINFO: typing.Final[MemviewBoxType]
    READ_MEMORY: typing.Final[MemviewBoxType]
    WRITE_MEMORY: typing.Final[MemviewBoxType]
    BREAKPOINT: typing.Final[MemviewBoxType]

    def getColor(self) -> java.awt.Color:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MemviewBoxType:
        ...

    @staticmethod
    def values() -> jpype.JArray[MemviewBoxType]:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...


class MemviewMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, elems: typing.Union[jpype.JLong, int], pixels: typing.Union[jpype.JLong, int]):
        ...

    def createMapping(self, mult: typing.Union[jpype.JDouble, float]):
        ...

    def getMultiplier(self) -> float:
        ...

    def getOffset(self, pixel: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getOriginalElemPerPixel(self) -> float:
        ...

    def getPixel(self, offset: typing.Union[jpype.JLong, int]) -> int:
        ...

    def getSize(self) -> int:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def multiplier(self) -> jpype.JDouble:
        ...

    @property
    def originalElemPerPixel(self) -> jpype.JDouble:
        ...

    @property
    def pixel(self) -> jpype.JInt:
        ...


class MemviewTable(java.lang.Object):

    @typing.type_check_only
    class FilterActionFilterListener(docking.widgets.filter.FilterListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ICON_TABLE: typing.Final[javax.swing.Icon]

    def __init__(self, provider: MemviewProvider):
        ...

    def addBoxes(self, blist: collections.abc.Sequence):
        ...

    def applyFilter(self):
        ...

    def getBoxes(self) -> java.util.List[MemoryBox]:
        ...

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def getPrincipalComponent(self) -> javax.swing.JComponent:
        ...

    def reset(self):
        ...

    def setBoxes(self, blist: collections.abc.Sequence):
        ...

    def setListingService(self, listingService: ghidra.app.services.DebuggerListingService):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setSelection(self, set: java.util.Set[MemoryBox]):
        ...

    @property
    def boxes(self) -> java.util.List[MemoryBox]:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def principalComponent(self) -> javax.swing.JComponent:
        ...


class MemviewPanel(javax.swing.JPanel, java.awt.event.MouseListener, java.awt.event.MouseMotionListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: MemviewProvider):
        ...

    def addBoxes(self, boxes: java.util.List[MemoryBox]):
        ...

    def getAddr(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getBoxes(self) -> java.util.List[MemoryBox]:
        ...

    def getBoxesAt(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> java.util.Set[MemoryBox]:
        ...

    def getBoxesIn(self, r: java.awt.Rectangle) -> java.util.Set[MemoryBox]:
        ...

    def getTagForAddr(self, addr: typing.Union[jpype.JLong, int]) -> str:
        ...

    def getTagForTick(self, tick: typing.Union[jpype.JLong, int]) -> str:
        ...

    def getTick(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getTitleAnnotation(self) -> str:
        ...

    def getVerticalMode(self) -> bool:
        ...

    def refresh(self):
        ...

    def reset(self):
        ...

    def scaleCurrentPixelAddr(self, changeAmount: typing.Union[jpype.JDouble, float]):
        ...

    def scaleCurrentPixelTime(self, changeAmount: typing.Union[jpype.JDouble, float]):
        ...

    def setBoxes(self, boxes: java.util.List[MemoryBox]):
        ...

    def setSelection(self, boxes: java.util.Set[MemoryBox]):
        ...

    def setVerticalMode(self, vertical: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def boxes(self) -> java.util.List[MemoryBox]:
        ...

    @boxes.setter
    def boxes(self, value: java.util.List[MemoryBox]):
        ...

    @property
    def tagForAddr(self) -> java.lang.String:
        ...

    @property
    def tagForTick(self) -> java.lang.String:
        ...

    @property
    def titleAnnotation(self) -> java.lang.String:
        ...

    @property
    def boxesIn(self) -> java.util.Set[MemoryBox]:
        ...

    @property
    def verticalMode(self) -> jpype.JBoolean:
        ...

    @verticalMode.setter
    def verticalMode(self, value: jpype.JBoolean):
        ...



__all__ = ["MemviewProvider", "DebuggerMemviewPlugin", "MemviewMapModel", "MemoryBox", "DebuggerMemviewTraceListener", "MemviewService", "MemviewBoxType", "MemviewMap", "MemviewTable", "MemviewPanel"]
