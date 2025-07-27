from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.support
import docking.widgets.indexedscrollpane
import ghidra.app.util
import ghidra.app.util.template
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.proxy
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import org.jdom # type: ignore


class FieldFactoryNameMapper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getFactoryPrototype(fieldName: typing.Union[java.lang.String, str], prototypeFactories: jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]) -> ghidra.app.util.viewer.field.FieldFactory:
        ...


class FieldHeader(javax.swing.JTabbedPane, javax.swing.event.ChangeListener):
    """
    Class to manage the tabbed panel for field formats.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, formatMgr: FormatManager, scroller: docking.widgets.indexedscrollpane.IndexedScrollPane, panel: docking.widgets.fieldpanel.FieldPanel):
        """
        Constructs a new FieldHeaderPanel
        
        :param FormatManager formatMgr: the format manager to display tabbed panels for.
        :param docking.widgets.indexedscrollpane.IndexedScrollPane scroller: the scroll model to coordinate the view for.
        :param docking.widgets.fieldpanel.FieldPanel panel: the field panel to use.
        """

    def getActions(self, ownerName: typing.Union[java.lang.String, str]) -> java.util.List[docking.action.DockingActionIf]:
        ...

    def getCurrentModel(self) -> FieldFormatModel:
        """
        Returns the currently tabbed model.
        """

    def getFieldHeaderLocation(self, p: java.awt.Point) -> FieldHeaderLocation:
        """
        Returns the a FieldHeaderLocation for the given point within the header.
        """

    def getFormatManager(self) -> FormatManager:
        ...

    def getHeaderTab(self) -> FieldHeaderComp:
        """
        Returns the field header tab component.
        """

    def getSelectedFieldFactory(self) -> ghidra.app.util.viewer.field.FieldFactory:
        ...

    def resetAllFormats(self):
        """
        Resets all the format models to their default formats
        """

    def resetFormat(self):
        """
        Resets the currently tabbed model to its default format.
        """

    def setSelectedFieldFactory(self, factory: ghidra.app.util.viewer.field.FieldFactory):
        """
        Sets the current tab to the given model.
        
        :param ghidra.app.util.viewer.field.FieldFactory factory: the format model to make the current tab.
        """

    def setTabLock(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the tab lock so the tab won't reposition.
        
        :param jpype.JBoolean or bool b: true to set the lock, false to release the lock.
        """

    def setViewComponent(self, centerComponent: javax.swing.JComponent):
        ...

    @property
    def headerTab(self) -> FieldHeaderComp:
        ...

    @property
    def formatManager(self) -> FormatManager:
        ...

    @property
    def selectedFieldFactory(self) -> ghidra.app.util.viewer.field.FieldFactory:
        ...

    @selectedFieldFactory.setter
    def selectedFieldFactory(self, value: ghidra.app.util.viewer.field.FieldFactory):
        ...

    @property
    def fieldHeaderLocation(self) -> FieldHeaderLocation:
        ...

    @property
    def currentModel(self) -> FieldFormatModel:
        ...

    @property
    def actions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...


class FormatModelListener(java.lang.Object):
    """
    Interface for listeners to format model changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @deprecated("not used")
    def formatModelAdded(self, model: FieldFormatModel):
        """
        Format model added. Not used.
        
        :param FieldFormatModel model: the model that was added
        
        .. deprecated::
        
        not used
        """

    def formatModelChanged(self, model: FieldFormatModel):
        """
        Notifies that the given format model was changed.
        
        :param FieldFormatModel model: the model that was changed.
        """

    @deprecated("not used")
    def formatModelRemoved(self, model: FieldFormatModel):
        """
        Format model removed. Not used.
        
        :param FieldFormatModel model: the model that was added
        
        .. deprecated::
        
        not used
        """


class FieldHeaderLocation(java.lang.Object):
    """
    Class used to represent a location within the field header component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: FieldFormatModel, factory: ghidra.app.util.viewer.field.FieldFactory, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        """
        Construct a new FieldHeaderLocation
        
        :param FieldFormatModel model: the model containing this location
        :param ghidra.app.util.viewer.field.FieldFactory factory: the factory the containing this location.
        :param jpype.JInt or int row: the row containing the factory in the header
        :param jpype.JInt or int col: the column containing the factory in the header.
        """

    def getColumn(self) -> int:
        """
        Returns the header column for this location.
        """

    def getFieldFactory(self) -> ghidra.app.util.viewer.field.FieldFactory:
        """
        Returns the field factory for this location.
        """

    def getModel(self) -> FieldFormatModel:
        """
        Returns the FieldFormatModel for this location.
        """

    def getRow(self) -> int:
        """
        Returns the header row for this location.
        """

    @property
    def fieldFactory(self) -> ghidra.app.util.viewer.field.FieldFactory:
        ...

    @property
    def column(self) -> jpype.JInt:
        ...

    @property
    def model(self) -> FieldFormatModel:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...


class FieldFormatModel(java.lang.Object):
    """
    Maintains the size and ordering for a layout of fields.
    """

    @typing.type_check_only
    class FieldFactoryComparator(java.util.Comparator[ghidra.app.util.viewer.field.FieldFactory]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DIVIDER: typing.Final = 0
    PLATE: typing.Final = 1
    FUNCTION: typing.Final = 2
    FUNCTION_VARS: typing.Final = 3
    INSTRUCTION_OR_DATA: typing.Final = 4
    OPEN_DATA: typing.Final = 5
    ARRAY: typing.Final = 6

    def addAllFactories(self):
        """
        Adds all unused fields to this model.
        """

    def addFactory(self, factory: ghidra.app.util.viewer.field.FieldFactory, rowIndex: typing.Union[jpype.JInt, int], colIndex: typing.Union[jpype.JInt, int]):
        """
        Adds a new field to this format.
        
        :param ghidra.app.util.viewer.field.FieldFactory factory: the FieldFactory to add
        :param jpype.JInt or int rowIndex: the row to add the field to
        :param jpype.JInt or int colIndex: the position in the row for the new field.
        """

    def addLayouts(self, list: java.util.List[docking.widgets.fieldpanel.support.RowLayout], index: typing.Union[jpype.JInt, int], proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any]):
        """
        Generates the layout objects for the given index and proxy object
        
        :param java.util.List[docking.widgets.fieldpanel.support.RowLayout] list: the list to add layouts to
        :param jpype.JInt or int index: the index (represents address)
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object to get layouts for.
        """

    def addRow(self, index: typing.Union[jpype.JInt, int]):
        """
        Adds new empty row at the given position.  The position must be in the
        interval [0,numRows].
        
        :raises IllegalArgumentException: thrown if the position is outside the
        interval [0,numRows].
        """

    def displayOptionsChanged(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notifies that the field display options have changed.
        
        :param ghidra.framework.options.Options options: the Options object that changed.
        :param java.lang.String or str optionName: the name of the property that changed.
        :param java.lang.Object oldValue: the old value of the property.
        :param java.lang.Object newValue: the new value of the property.
        """

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notifies that the field options have changed.
        
        :param ghidra.framework.options.Options options: the Options object that changed.
        :param java.lang.String or str optionName: the name of the property that changed.
        :param java.lang.Object oldValue: the old value of the property.
        :param java.lang.Object newValue: the new value of the property.
        """

    def getAllFactories(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        ...

    @typing.overload
    def getFactorys(self, row: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        """
        Returns the FieldFactorys on a given row.
        """

    @typing.overload
    def getFactorys(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        """
        Returns the list factories valid for this format.
        """

    def getFormatManager(self) -> FormatManager:
        """
        Returns the formatMgr that is managing this model.
        """

    def getName(self) -> str:
        """
        Returns the name of this format model.
        """

    def getNumFactorys(self, row: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the number of FieldFactorys on any given row.
        """

    def getNumRows(self) -> int:
        """
        Returns the number of rows in the model.
        """

    def getUnusedFactories(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        """
        Returns a list of unused valid fields for this model
        
        :return: a list of unused valid fields for this model
        :rtype: jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]
        """

    def getWidth(self) -> int:
        """
        Returns the width of this model
        """

    def modelChanged(self):
        """
        Notifies the formatMgr that this format model has changed.
        """

    def moveFactory(self, oldRowIndex: typing.Union[jpype.JInt, int], oldColIndex: typing.Union[jpype.JInt, int], newRowIndex: typing.Union[jpype.JInt, int], newColIndex: typing.Union[jpype.JInt, int]):
        """
        Moves the Field at (oldrow,oldCol) to (row,col)
        
        :param jpype.JInt or int oldRowIndex: the row containing the field to be moved.
        :param jpype.JInt or int oldColIndex: the column index of the field to be moved.
        :param jpype.JInt or int newRowIndex: the row to move to.
        :param jpype.JInt or int newColIndex: the column to move to.
        :raises IllegalArgumentException: thrown if any of the parameters don't
        map to a valid grid position.
        """

    def removeAllFactories(self):
        """
        Removes all fields from this model.
        """

    def removeFactory(self, rowIndex: typing.Union[jpype.JInt, int], colIndex: typing.Union[jpype.JInt, int]):
        """
        Removes a field from the format.
        
        :param jpype.JInt or int rowIndex: the row index of the field to remove.
        :param jpype.JInt or int colIndex: the column index of the field to remove.
        """

    def removeRow(self, index: typing.Union[jpype.JInt, int]):
        """
        Removes the row currently at the given position.
        
        :param jpype.JInt or int index: the index of the row to remove.
        """

    def restoreFromXml(self, root: org.jdom.Element):
        """
        Restores the format for this model from XML.
        
        :param org.jdom.Element root: the root XML element from which to get the format information.
        """

    def saveToXml(self) -> org.jdom.Element:
        """
        Saves this format to XML.
        """

    def servicesChanged(self):
        """
        Notifies each row that the services have changed.
        """

    def setBaseRowID(self, id: typing.Union[jpype.JInt, int]):
        """
        Sets the base id for this model. Each row in a model gets an id which must
        be unique across all models.
        
        :param jpype.JInt or int id: the base id for this format.
        """

    def update(self):
        """
        Updates users of the formatMgr to indicate the format has changed.
        """

    def updateRow(self, index: typing.Union[jpype.JInt, int]):
        """
        Updates the fields on the given row.
        
        :param jpype.JInt or int index: the row to update.
        """

    @property
    def unusedFactories(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        ...

    @property
    def numFactorys(self) -> jpype.JInt:
        ...

    @property
    def factorys(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        ...

    @property
    def numRows(self) -> jpype.JInt:
        ...

    @property
    def formatManager(self) -> FormatManager:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def allFactories(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        ...


class FieldHeaderComp(javax.swing.JPanel):
    """
    Class manage a header for the FieldViewer.
    """

    @typing.type_check_only
    class CursorState(java.lang.Enum[FieldHeaderComp.CursorState]):

        class_: typing.ClassVar[java.lang.Class]
        NOWHERE: typing.Final[FieldHeaderComp.CursorState]
        NEAR_EDGE: typing.Final[FieldHeaderComp.CursorState]
        OVER_FIELD: typing.Final[FieldHeaderComp.CursorState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FieldHeaderComp.CursorState:
            ...

        @staticmethod
        def values() -> jpype.JArray[FieldHeaderComp.CursorState]:
            ...


    @typing.type_check_only
    class MovingField(java.lang.Object):
        """
        Class for keeping track of a field that is the process of being dragged.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, headerPanel: FieldHeader, modelNumber: typing.Union[jpype.JInt, int]):
        """
        Constructs a new FieldHeader for the given model.
        
        :param FieldHeader headerPanel: the headerPanel containing this component.
        :param jpype.JInt or int modelNumber: the model number for this component.
        """

    def getCol(self, row: typing.Union[jpype.JInt, int], x: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the index of the field on the given row containing the give x position.
        
        :param jpype.JInt or int row: the row on which to find the index of the field containing the x coordinate.
        :param jpype.JInt or int x: the horizontal coordinate (in pixels)
        :return: the column
        :rtype: int
        """

    def getFieldHeaderLocation(self, p: java.awt.Point) -> FieldHeaderLocation:
        """
        Returns a FieldHeaderLocation for the given point
        
        :param java.awt.Point p: the point to get a location for
        :return: the location
        :rtype: FieldHeaderLocation
        """

    def getModel(self) -> FieldFormatModel:
        """
        Returns the currently displayed model.
        
        :return: the currently displayed model.
        :rtype: FieldFormatModel
        """

    def getRow(self, p: java.awt.Point) -> int:
        """
        Returns the row in the model that the point is over.
        
        :param java.awt.Point p: the point for which to find its corresponding row
        :return: the row
        :rtype: int
        """

    def update(self):
        """
        Called when the model's layout changes.
        """

    @property
    def model(self) -> FieldFormatModel:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @property
    def fieldHeaderLocation(self) -> FieldHeaderLocation:
        ...


@typing.type_check_only
class Row(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addField(self, ff: ghidra.app.util.viewer.field.FieldFactory):
        ...

    def displayOptionsChanged(self, options: ghidra.framework.options.Options, name: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        ...

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, name: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        ...

    def getFactorys(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        ...

    def getLayout(self, index: typing.Union[jpype.JInt, int], proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], id: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowLayout:
        ...

    def insertField(self, ff: ghidra.app.util.viewer.field.FieldFactory, colIndex: typing.Union[jpype.JInt, int]):
        ...

    def layoutFields(self):
        ...

    def removeField(self, colIndex: typing.Union[jpype.JInt, int]) -> ghidra.app.util.viewer.field.FieldFactory:
        ...

    def servicesChanged(self):
        ...

    def size(self) -> int:
        ...

    @property
    def factorys(self) -> jpype.JArray[ghidra.app.util.viewer.field.FieldFactory]:
        ...


class FormatManager(ghidra.framework.options.OptionsChangeListener):
    """
    Class to manage the set of format models.
    """

    @typing.type_check_only
    class MultipleHighlighterProvider(ghidra.app.util.ListingHighlightProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ARRAY_OPTIONS_GROUP: typing.Final = "Array Options"
    HIGHLIGHT_COLOR_NAME: typing.Final = "Cursor Text Highlight.Highlight Color"
    HIGHLIGHT_ALT_COLOR_NAME: typing.Final = "Cursor Text Highlight.Alternate Highlight Color"
    ARRAY_DISPLAY_OPTIONS: typing.Final = "Array Options.Array Display Options"
    ARRAY_DISPLAY_DESCRIPTION: typing.Final = "Adjusts the Array Field display"

    def __init__(self, displayOptions: ghidra.framework.options.ToolOptions, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructs a new FormatManager.
        
        :param ghidra.framework.options.ToolOptions displayOptions: the Options containing display options (color, fonts, etc)
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options contains specific field options.
        """

    def addFormatModelListener(self, listener: FormatModelListener):
        """
        Adds a listener to be notified when a format changes.
        
        :param FormatModelListener listener: the listener to be added
        """

    def addHighlightProvider(self, provider: ghidra.app.util.ListingHighlightProvider):
        """
        Adds a HighlightProvider
        
        :param ghidra.app.util.ListingHighlightProvider provider: the provider to use.
        
        .. seealso::
        
            | :obj:`.removeHighlightProvider(ListingHighlightProvider)`
        
            | :obj:`.getHighlightProviders()`
        """

    def createClone(self) -> FormatManager:
        ...

    def dispose(self):
        ...

    def getCodeUnitFormat(self) -> FieldFormatModel:
        """
        Returns the format model for a code unit.
        
        :return: the format model for a code unit
        :rtype: FieldFormatModel
        """

    def getDisplayOptions(self) -> ghidra.framework.options.ToolOptions:
        """
        Returns the Options used for display properties.
        
        :return: the Options used for display properties.
        :rtype: ghidra.framework.options.ToolOptions
        """

    def getDividerModel(self) -> FieldFormatModel:
        """
        Returns the format model for the address break (divider).
        
        :return: the format model for the address break (divider)
        :rtype: FieldFormatModel
        """

    def getFieldOptions(self) -> ghidra.framework.options.ToolOptions:
        """
        Returns the Options used for field specific properties.
        
        :return: the Options used for field specific properties
        :rtype: ghidra.framework.options.ToolOptions
        """

    def getFormatHighlightProvider(self) -> ghidra.app.util.ListingHighlightProvider:
        """
        Returns the :obj:`ListingHighlightProvider` that should be used when creating :obj:`FieldFactory`
        objects.
        """

    def getFunctionFormat(self) -> FieldFormatModel:
        """
        Returns the format model for the function signature.
        
        :return: the format model for the function signature
        :rtype: FieldFormatModel
        """

    def getFunctionVarFormat(self) -> FieldFormatModel:
        """
        Returns the format model for the function variables.
        
        :return: the format model for the function variables
        :rtype: FieldFormatModel
        """

    def getHighlightProviders(self) -> java.util.List[ghidra.app.util.ListingHighlightProvider]:
        """
        Gets all :obj:`ListingHighlightProvider`s installed on this FormatManager via the
        :meth:`addHighlightProvider(ListingHighlightProvider) <.addHighlightProvider>`.
        
        :return: all :obj:`ListingHighlightProvider`s installed on this FormatManager.
        :rtype: java.util.List[ghidra.app.util.ListingHighlightProvider]
        """

    def getMaxNumRows(self) -> int:
        """
        Returns the maximum number of possible rows in a layout. This would only
        occur if some address had every possible type of information to be displayed.
        """

    def getMaxRowCount(self) -> int:
        ...

    def getMaxWidth(self) -> int:
        """
        Returns the width of the widest model in this manager.
        """

    def getModel(self, index: typing.Union[jpype.JInt, int]) -> FieldFormatModel:
        """
        Returns the format model for the given index.
        
        :param jpype.JInt or int index: the index of the format model to return.
        :return: the format model for the given index
        :rtype: FieldFormatModel
        """

    def getNumModels(self) -> int:
        """
        Returns the total number of model in the format manager.
        
        :return: the total number of model in the format manager
        :rtype: int
        """

    def getOpenDataFormat(self, data: ghidra.program.model.listing.Data) -> FieldFormatModel:
        """
        Returns the format model to use for the internals of open structures.
        
        :param ghidra.program.model.listing.Data data: the data code unit to get the format model for.
        """

    def getPlateFormat(self) -> FieldFormatModel:
        """
        Returns the format model for the plate field.
        
        :return: the format model for the plate field
        :rtype: FieldFormatModel
        """

    def getServiceProvider(self) -> ghidra.framework.plugintool.ServiceProvider:
        ...

    def getTemplateSimplifier(self) -> ghidra.app.util.template.TemplateSimplifier:
        """
        Returns the template simplifier.
        
        :return: the template simplifier.
        :rtype: ghidra.app.util.template.TemplateSimplifier
        """

    def modelChanged(self, model: FieldFormatModel):
        """
        Notifies listeners that the given model has changed.
        
        :param FieldFormatModel model: the format model that changed.
        """

    def readState(self, saveState: ghidra.framework.options.SaveState):
        """
        Restores the state of this LayoutController from the given SaveState
        object.
        
        :param ghidra.framework.options.SaveState saveState: the SaveState to read from.
        """

    def removeFormatModleListener(self, listener: FormatModelListener):
        """
        Removes the given listener from the list of listeners to be notified of a
        format change.
        
        :param FormatModelListener listener: the listener to be removed.
        """

    def removeHighlightProvider(self, provider: ghidra.app.util.ListingHighlightProvider):
        """
        Removes the provider
        
        :param ghidra.app.util.ListingHighlightProvider provider: the provider to remove.
        
        .. seealso::
        
            | :obj:`.addHighlightProvider(ListingHighlightProvider)`
        """

    def saveState(self, saveState: ghidra.framework.options.SaveState):
        """
        Saves the state of this LayoutManager to the SaveState object.
        
        :param ghidra.framework.options.SaveState saveState: the SaveState object to write to.
        """

    def setDefaultFormat(self, modelID: typing.Union[jpype.JInt, int]):
        """
        Resets the model with the given id to its default format.
        
        :param jpype.JInt or int modelID: the id of the model to reset.
        """

    def setDefaultFormats(self):
        """
        Resets all format models to their default format.
        """

    def setServiceProvider(self, provider: ghidra.framework.plugintool.ServiceProvider):
        """
        Sets the service provider used by the field factory objects.
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider
        """

    def update(self):
        """
        update all listeners that a model has changed.
        """

    @property
    def highlightProviders(self) -> java.util.List[ghidra.app.util.ListingHighlightProvider]:
        ...

    @property
    def formatHighlightProvider(self) -> ghidra.app.util.ListingHighlightProvider:
        ...

    @property
    def fieldOptions(self) -> ghidra.framework.options.ToolOptions:
        ...

    @property
    def templateSimplifier(self) -> ghidra.app.util.template.TemplateSimplifier:
        ...

    @property
    def maxRowCount(self) -> jpype.JInt:
        ...

    @property
    def maxNumRows(self) -> jpype.JInt:
        ...

    @property
    def displayOptions(self) -> ghidra.framework.options.ToolOptions:
        ...

    @property
    def dividerModel(self) -> FieldFormatModel:
        ...

    @property
    def functionVarFormat(self) -> FieldFormatModel:
        ...

    @property
    def plateFormat(self) -> FieldFormatModel:
        ...

    @property
    def serviceProvider(self) -> ghidra.framework.plugintool.ServiceProvider:
        ...

    @serviceProvider.setter
    def serviceProvider(self, value: ghidra.framework.plugintool.ServiceProvider):
        ...

    @property
    def numModels(self) -> jpype.JInt:
        ...

    @property
    def openDataFormat(self) -> FieldFormatModel:
        ...

    @property
    def codeUnitFormat(self) -> FieldFormatModel:
        ...

    @property
    def model(self) -> FieldFormatModel:
        ...

    @property
    def functionFormat(self) -> FieldFormatModel:
        ...

    @property
    def maxWidth(self) -> jpype.JInt:
        ...



__all__ = ["FieldFactoryNameMapper", "FieldHeader", "FormatModelListener", "FieldHeaderLocation", "FieldFormatModel", "FieldHeaderComp", "Row", "FormatManager"]
