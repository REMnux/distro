from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets
import docking.widgets.list
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.util
import ghidra.util.exception
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore


class DataTypeUrl(java.lang.Object):
    """
    A class to produce and parse URLs of the form:
        datatype:/12345678?uid=12345678&name=Bob
    where the first number is the ID of the :obj:`DataTypeManager` and the second number is 
    the :obj:`DataType` ID.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dt: ghidra.program.model.data.DataType):
        """
        Constructs a url from the given data type
        
        :param ghidra.program.model.data.DataType dt: the data type; cannot be null
        """

    @typing.overload
    def __init__(self, url: typing.Union[java.lang.String, str]):
        """
        Constructs a url from the given url string
        
        :param java.lang.String or str url: the url
        :raises java.lang.IllegalArgumentException: if the url does not match the expected :obj:`.URL_PATTERN`
                or if there is an issue parsing the id within the given url
        """

    def getDataType(self, service: ghidra.app.services.DataTypeManagerService) -> ghidra.program.model.data.DataType:
        """
        Uses the given service and its :obj:`DataTypeManager`s to find the data type 
        represented by this url
        
        :param ghidra.app.services.DataTypeManagerService service: the service
        :return: the data type; null if there was an error restoring the type, such as if the
                parent :obj:`DataTypeManager` has been closed
        :rtype: ghidra.program.model.data.DataType
        """

    def getDataTypeId(self) -> ghidra.util.UniversalID:
        ...

    def getDataTypeManagerId(self) -> ghidra.util.UniversalID:
        ...

    def getDataTypeName(self) -> str:
        ...

    @property
    def dataTypeName(self) -> java.lang.String:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def dataTypeId(self) -> ghidra.util.UniversalID:
        ...

    @property
    def dataTypeManagerId(self) -> ghidra.util.UniversalID:
        ...


class EmptyCompositeException(ghidra.util.exception.UsrException):
    """
    Exception thrown if the composite data type is empty.
    Typically this will be thrown if the user tries to save or apply a
    composite with no components.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, composite: ghidra.program.model.data.Composite):
        """
        Constructor
        
        :param ghidra.program.model.data.Composite composite: the structure data type that is empty.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str message: detailed message explaining exception
        """


class DataTypeSelectionDialog(docking.DialogComponentProvider):
    """
    A dialog that allows the user to choose from available data types or create new ones.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pluginTool: ghidra.framework.plugintool.PluginTool, dtm: ghidra.program.model.data.DataTypeManager, maxSize: typing.Union[jpype.JInt, int], allowedTypes: ghidra.util.data.DataTypeParser.AllowedDataTypes):
        ...

    def clearUserChosenDataType(self):
        """
        Clears the last user selection.  This is useful if this dialog is reused and the call
        wants to make sure that old selections do not appear later.
        """

    def getEditor(self) -> DataTypeSelectionEditor:
        ...

    def getUserChosenDataType(self) -> ghidra.program.model.data.DataType:
        """
        The data type choice of the user or null if the dialog was cancelled.
        
        :return: The data type choice of the user or null if the dialog was cancelled.
        :rtype: ghidra.program.model.data.DataType
        """

    def setInitialDataType(self, dataType: ghidra.program.model.data.DataType):
        """
        Sets the value that this dialog will display in it's editor when initially shown.
        
        :param ghidra.program.model.data.DataType dataType: The initial data type to use for editing.
        """

    def setTabCommitsEdit(self, doesCommit: typing.Union[jpype.JBoolean, bool]):
        """
        If true then a Tab key press will work the same as pressing the Enter key.  If false, then
        a Tab key press will trigger navigation, as is normally done in Java.
         
        
        This method is useful for widgets that have embedded editors that launch this dialog.  For
        these editors, like tables, it is nice to be able to tab through various editors.  This
        method allows these editors to keep this functionality, even though a new dialog was shown.
        
        :param jpype.JBoolean or bool doesCommit: true commits edits on Tab press
        """

    @property
    def editor(self) -> DataTypeSelectionEditor:
        ...

    @property
    def userChosenDataType(self) -> ghidra.program.model.data.DataType:
        ...


class DataTypeSelectionEditor(javax.swing.AbstractCellEditor):
    """
    An editor that is used to show the :obj:`DropDownSelectionTextField` for the entering of
    data types by name and offers the user of a completion window.  This editor also provides a
    browse button that when pressed will show a data type tree so that the user may browse a tree
    of known data types.
     
    
    The typical usage of this class is in conjunction with the :obj:`DataTypeChooserDialog`.   The
    dialog uses this editor as part of its DataType selection process.  Users seeking a dialog
    that allows users to choose DataTypes are encouraged to use that dialog.  If you wish to add
    this editor to a widget directly, then see below.
     
    
    Stand Alone Usage
    
    In order to use this component directly you need to call :meth:`getEditorComponent() <.getEditorComponent>`.  This
    will give you a Component for editing.
     
    
    In order to know when changes are made to the component you need to add a DocumentListener
    via the :meth:`addDocumentListener(DocumentListener) <.addDocumentListener>` method.  The added listener will be
    notified as the user enters text into the editor's text field.  Then, to determine when there
    is as valid DataType in the field you may call :meth:`validateUserSelection() <.validateUserSelection>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager, serviceProvider: ghidra.framework.plugintool.ServiceProvider, allowedDataTypes: ghidra.util.data.DataTypeParser.AllowedDataTypes):
        """
        Creates a new instance.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the preferred :obj:`DataTypeManager`.  Extra copies of data types that are 
        already in the preferred DTM will be suppressed.
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: :obj:`ServiceProvider`
        :param ghidra.util.data.DataTypeParser.AllowedDataTypes allowedDataTypes: :obj:`AllowedDataTypes` option enum, controls what kind of
        data types that will be shown
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager, service: ghidra.app.services.DataTypeManagerService, allowedDataTypes: ghidra.util.data.DataTypeParser.AllowedDataTypes):
        """
        Creates a new instance.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the preferred :obj:`DataTypeManager`.  Extra copies of data types that are 
        already in the preferred DTM will be suppressed.
        :param ghidra.app.services.DataTypeManagerService service: :obj:`DataTypeManagerService`
        :param ghidra.util.data.DataTypeParser.AllowedDataTypes allowedDataTypes: :obj:`AllowedDataTypes` option enum, controls what kind of
        data types that will be shown
        """

    def addDocumentListener(self, listener: javax.swing.event.DocumentListener):
        """
        Adds a document listener to the text field editing component of this editor so that users
        can be notified when the text contents of the editor change.  You may verify whether the
        text changes represent a valid DataType by calling :meth:`validateUserSelection() <.validateUserSelection>`.
        
        :param javax.swing.event.DocumentListener listener: the listener to add.
        
        .. seealso::
        
            | :obj:`.validateUserSelection()`
        """

    def addFocusListener(self, listener: java.awt.event.FocusListener):
        ...

    def containsValidDataType(self) -> bool:
        ...

    def getBrowseButton(self) -> javax.swing.JButton:
        ...

    def getCellEditorValueAsDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getCellEditorValueAsText(self) -> str:
        """
        Returns the text value of the editor's text field.
        
        :return: the text value of the editor's text field.
        :rtype: str
        """

    def getDropDownTextField(self) -> docking.widgets.DropDownSelectionTextField[ghidra.program.model.data.DataType]:
        ...

    def getEditorComponent(self) -> javax.swing.JComponent:
        """
        Returns the component that allows the user to edit.
        
        :return: the component that allows the user to edit.
        :rtype: javax.swing.JComponent
        """

    def getNavigationDirection(self) -> NavigationDirection:
        """
        Returns the direction of the user triggered navigation; null if the user did not trigger
        navigation out of this component.
        
        :return: the direction
        :rtype: NavigationDirection
        """

    def removeDocumentListener(self, listener: javax.swing.event.DocumentListener):
        """
        Removes a previously added document listener.
        
        :param javax.swing.event.DocumentListener listener: the listener to remove.
        """

    def removeFocusListener(self, listener: java.awt.event.FocusListener):
        ...

    def requestFocus(self):
        ...

    def setCellEditorValue(self, dataType: ghidra.program.model.data.DataType):
        """
        Sets the value to be edited on this cell editor.
        
        :param ghidra.program.model.data.DataType dataType: The data type which is to be edited.
        """

    def setCellEditorValueAsText(self, text: typing.Union[java.lang.String, str]):
        ...

    def setConsumeEnterKeyPress(self, consume: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether this editor should consumer Enter key presses
        
        :param jpype.JBoolean or bool consume: true to consume
        
        .. seealso::
        
            | :obj:`DropDownSelectionTextField.setConsumeEnterKeyPress(boolean)`
        """

    def setDefaultSelectedTreePath(self, path: javax.swing.tree.TreePath):
        """
        Sets the initially selected node in the data type tree that the user can choose to
        show.
        
        :param javax.swing.tree.TreePath path: The path to set
        """

    def setTabCommitsEdit(self, doesCommit: typing.Union[jpype.JBoolean, bool]):
        ...

    def validateUserSelection(self) -> bool:
        """
        Returns true if the current value of the data type editor is a know data type.
        
        :return: true if the current value of the data type editor is a know data type.
        :rtype: bool
        :raises InvalidDataTypeException: If the current text in the editor's text field could not
                be parsed into a valid DataType
        """

    @property
    def cellEditorValueAsText(self) -> java.lang.String:
        ...

    @cellEditorValueAsText.setter
    def cellEditorValueAsText(self, value: java.lang.String):
        ...

    @property
    def cellEditorValueAsDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def browseButton(self) -> javax.swing.JButton:
        ...

    @property
    def dropDownTextField(self) -> docking.widgets.DropDownSelectionTextField[ghidra.program.model.data.DataType]:
        ...

    @property
    def navigationDirection(self) -> NavigationDirection:
        ...

    @property
    def editorComponent(self) -> javax.swing.JComponent:
        ...


class DataTypeDropDownSelectionDataModel(docking.widgets.DropDownTextFieldDataModel[ghidra.program.model.data.DataType]):
    """
    The data model for :obj:`DropDownSelectionTextField` that allows the text field to work with
    :obj:`DataType`s.
    """

    @typing.type_check_only
    class DataTypeDropDownRenderer(docking.widgets.list.GListCellRenderer[ghidra.program.model.data.DataType]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        ...

    @typing.overload
    def __init__(self, preferredDtm: ghidra.program.model.data.DataTypeManager, dataTypeService: ghidra.app.services.DataTypeManagerService):
        """
        Creates a new instance.
        
        :param ghidra.program.model.data.DataTypeManager preferredDtm: the preferred :obj:`DataTypeManager`.  Data types that are found in 
        multiple data type managers will be pruned to just the ones already in the preferred data 
        type manager.
        :param ghidra.app.services.DataTypeManagerService dataTypeService: :obj:`DataTypeManagerService`
        """


class ApplyEnumDialog(DataTypeSelectionDialog):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pluginTool: ghidra.framework.plugintool.PluginTool, dtm: ghidra.program.model.data.DataTypeManager):
        ...

    def shouldApplyOnSubOps(self) -> bool:
        ...


class NavigationDirection(java.lang.Enum[NavigationDirection]):

    class_: typing.ClassVar[java.lang.Class]
    FORWARD: typing.Final[NavigationDirection]
    BACKWARD: typing.Final[NavigationDirection]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> NavigationDirection:
        ...

    @staticmethod
    def values() -> jpype.JArray[NavigationDirection]:
        ...



__all__ = ["DataTypeUrl", "EmptyCompositeException", "DataTypeSelectionDialog", "DataTypeSelectionEditor", "DataTypeDropDownSelectionDataModel", "ApplyEnumDialog", "NavigationDirection"]
