from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import generic
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.trace.model
import ghidra.trace.model.target.schema
import ghidra.util.table.column
import java.awt # type: ignore
import java.lang # type: ignore


COLUMN_TYPE = typing.TypeVar("COLUMN_TYPE")
DATA_SOURCE = typing.TypeVar("DATA_SOURCE")
ROW_TYPE = typing.TypeVar("ROW_TYPE")
T = typing.TypeVar("T")


class TracePathLastLifespanPlotColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow, generic.Span[java.lang.Long, typing.Any], ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addSeekListener(self, listener: docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener):
        ...

    def setFullRange(self, fullRange: ghidra.trace.model.Lifespan):
        ...

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        ...


class TraceValueObjectAttributeColumn(TraceValueObjectPropertyColumn[T], typing.Generic[T]):
    """
    A column which displays the object's value for a given attribute
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, attributeName: typing.Union[java.lang.String, str], attributeType: java.lang.Class[T]):
        """
        Construct an attribute-value column
        
        :param java.lang.String or str attributeName: the name of the attribute
        :param java.lang.Class[T] attributeType: the type of the attribute (see
                    :meth:`computeAttributeType(SchemaContext, AttributeSchema) <.computeAttributeType>`)
        """

    @staticmethod
    def computeAttributeType(ctx: ghidra.trace.model.target.schema.SchemaContext, attributeSchema: ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema) -> java.lang.Class[typing.Any]:
        """
        Get the type of a given attribute for the model schema
        
        :param ghidra.trace.model.target.schema.SchemaContext ctx: the schema context
        :param ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema attributeSchema: the attribute entry from the schema
        :return: the type, as a Java class
        :rtype: java.lang.Class[typing.Any]
        """


class AbstractTraceValueObjectAddressColumn(TraceValueObjectPropertyColumn[ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, attributeName: typing.Union[java.lang.String, str]):
        ...


class AbstractTraceValueObjectLengthColumn(TraceValueObjectPropertyColumn[java.lang.Long]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, attributeName: typing.Union[java.lang.String, str]):
        ...


class TracePathStringColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow, java.lang.String, ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceValueValColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, ghidra.trace.model.Trace]):

    @typing.type_check_only
    class ValRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow], ghidra.app.plugin.core.debug.gui.model.ColorsModified.InTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setDiffColor(self, diffColor: java.awt.Color):
        ...

    def setDiffColorSel(self, diffColorSel: java.awt.Color):
        ...


class TraceValueKeyColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, java.lang.String, ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TracePathLastKeyColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow, java.lang.String, ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceValueColumnRenderer(ghidra.util.table.column.AbstractGColumnRenderer[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceValueLifePlotColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, generic.Span.SpanSet[java.lang.Long, typing.Any], ghidra.trace.model.Trace]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addSeekListener(self, listener: docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener):
        ...

    def getFullRange(self) -> generic.Span[java.lang.Long, typing.Any]:
        ...

    def setFullRange(self, fullRange: ghidra.trace.model.Lifespan):
        ...

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        ...

    @property
    def fullRange(self) -> generic.Span[java.lang.Long, typing.Any]:
        ...


class TracePathValueColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow, ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow, ghidra.trace.model.Trace]):

    @typing.type_check_only
    class ValueRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow], ghidra.app.plugin.core.debug.gui.model.ColorsModified.InTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setDiffColor(self, diffColor: java.awt.Color):
        ...

    def setDiffColorSel(self, diffColorSel: java.awt.Color):
        ...


class TracePathLastLifespanColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow, TracePathLastLifespanColumn.SpanAndRadix, ghidra.trace.model.Trace]):

    @typing.type_check_only
    class SpanAndRadix(java.lang.Record, java.lang.Comparable[TracePathLastLifespanColumn.SpanAndRadix]):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def radix(self) -> ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix:
            ...

        def span(self) -> ghidra.trace.model.Lifespan:
            ...


    @typing.type_check_only
    class LastLifespanRenderer(ghidra.util.table.column.AbstractGColumnRenderer[TracePathLastLifespanColumn.SpanAndRadix]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceValueObjectEditableAttributeColumn(TraceValueObjectAttributeColumn[T], EditableColumn[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty[T], ghidra.trace.model.Trace], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, attributeName: typing.Union[java.lang.String, str], attributeType: java.lang.Class[T]):
        ...


class EditableColumn(docking.widgets.table.DynamicTableColumn[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE], typing.Generic[ROW_TYPE, COLUMN_TYPE, DATA_SOURCE]):

    class_: typing.ClassVar[java.lang.Class]

    def isEditable(self, row: ROW_TYPE, settings: ghidra.docking.settings.Settings, dataSource: DATA_SOURCE, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        ...

    def setValue(self, row: ROW_TYPE, value: COLUMN_TYPE, settings: ghidra.docking.settings.Settings, dataSource: DATA_SOURCE, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...


class TraceValueLifeColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, TraceValueLifeColumn.SetAndRadix, ghidra.trace.model.Trace]):

    @typing.type_check_only
    class SetAndRadix(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def radix(self) -> ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix:
            ...

        def set(self) -> ghidra.trace.model.Lifespan.LifeSet:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceValueObjectPropertyColumn(docking.widgets.table.AbstractDynamicTableColumn[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty[T], ghidra.trace.model.Trace], typing.Generic[T]):

    class PropertyRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty[T]], ghidra.app.plugin.core.debug.gui.model.ColorsModified.InTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class BooleanPropertyRenderer(TraceValueObjectPropertyColumn.PropertyRenderer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, propertyType: java.lang.Class[T]):
        ...

    def createRenderer(self) -> ghidra.util.table.column.GColumnRenderer[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty[T]]:
        ...

    def getProperty(self, row: ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow) -> ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty[T]:
        ...

    def setDiffColor(self, diffColor: java.awt.Color):
        ...

    def setDiffColorSel(self, diffColorSel: java.awt.Color):
        ...


class TracePathColumnRenderer(ghidra.util.table.column.AbstractGColumnRenderer[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["TracePathLastLifespanPlotColumn", "TraceValueObjectAttributeColumn", "AbstractTraceValueObjectAddressColumn", "AbstractTraceValueObjectLengthColumn", "TracePathStringColumn", "TraceValueValColumn", "TraceValueKeyColumn", "TracePathLastKeyColumn", "TraceValueColumnRenderer", "TraceValueLifePlotColumn", "TracePathValueColumn", "TracePathLastLifespanColumn", "TraceValueObjectEditableAttributeColumn", "EditableColumn", "TraceValueLifeColumn", "TraceValueObjectPropertyColumn", "TracePathColumnRenderer"]
