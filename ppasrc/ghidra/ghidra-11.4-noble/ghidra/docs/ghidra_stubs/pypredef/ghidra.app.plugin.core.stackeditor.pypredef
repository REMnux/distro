from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.context
import ghidra.app.plugin.core.compositeeditor
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang # type: ignore


class EditStackAction(ghidra.app.context.ListingContextAction):
    """
    ``EditStackAction`` allows the user to edit a function's stack frame.
    """

    class_: typing.ClassVar[java.lang.Class]


class StackEditorModel(ghidra.app.plugin.core.compositeeditor.CompositeEditorModel[StackFrameDataType]):

    @typing.type_check_only
    class OffsetPairs(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class XYPair(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    OFFSET: typing.Final = 0
    LENGTH: typing.Final = 1
    DATATYPE: typing.Final = 2
    NAME: typing.Final = 3
    COMMENT: typing.Final = 4

    def add(self, index: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds the specified data type at the specified component index. Whether
        an insert or replace occurs depends on whether the indicated index is
        in a selection and whether in locked or unlocked mode.
        
        :param jpype.JInt or int index: the component index of where to add the data type.
        :param ghidra.program.model.data.DataType dt: the data type to add
        :return: true if the component is added, false if it doesn't.
        :rtype: ghidra.program.model.data.DataTypeComponent
        :raises UsrException: if add fails
        """

    def isAddAllowed(self, currentIndex: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType) -> bool:
        """
        Returns whether or not addition of the specified component is allowed
        at the specified index. the addition could be an insert or replace as
        determined by the state of the edit model.
        
        :param jpype.JInt or int currentIndex: index of the component in the structure.
        :param ghidra.program.model.data.DataType dataType: the data type to be inserted.
        """

    def setComponentOffset(self, rowIndex: typing.Union[jpype.JInt, int], value: typing.Union[java.lang.String, str]):
        ...

    def setValueAt(self, aValue: java.lang.Object, rowIndex: typing.Union[jpype.JInt, int], modelColumnIndex: typing.Union[jpype.JInt, int]):
        """
        This updates one of the values for a component that is a field of
        this data structure.
        
        :param java.lang.Object aValue: the new value for the field
        :param jpype.JInt or int rowIndex: the component index
        :param jpype.JInt or int modelColumnIndex: the model field index within the component
        """


class StackEditorProvider(ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider[StackFrameDataType, StackEditorModel], ghidra.framework.model.DomainObjectListener):
    """
    Editor for a Function Stack.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, function: ghidra.program.model.listing.Function):
        ...


class StackEditorManagerPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.options.OptionsChangeListener, StackEditorOptionManager):
    """
    Plugin to popup edit sessions for function stack frames.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        """

    def dispose(self):
        """
        Tells a plugin that it is no longer needed.  The plugin should remove itself
        from anything that it is registered to and release any resources.
        """

    def edit(self, function: ghidra.program.model.listing.Function):
        ...

    def optionsChanged(self, options: ghidra.framework.options.ToolOptions, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        ...

    def showStackNumbersInHex(self) -> bool:
        ...

    def updateOptions(self):
        ...


class StackEditorPanel(ghidra.app.plugin.core.compositeeditor.CompositeEditorPanel[StackFrameDataType, StackEditorModel]):
    """
    Panel for editing a function stack.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, model: StackEditorModel, provider: StackEditorProvider):
        ...


class StackEditorOptionManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def showStackNumbersInHex(self) -> bool:
        ...


@typing.type_check_only
class StackFrameDataType(ghidra.program.model.data.Structure):
    """
    :obj:`StackFrameDataType` provides a :obj:`Structure` representation of a :obj:`StackFrame`
    for use by the Stack Frame Editor.  Any other use is not supported since only those methods
    required by the editor have been implemented.  This datatype is not intended to ever get
    resolved directly into a datatype manager.  This implementation wraps a real :obj:`Structure`
    which may be resolved for the purpose of tracking datatype dependencies within the editor's
    dedicated datatype manager.
     
    
    NOTE: The :obj:`BadDataType` is utilized within the wrapped structure to preserve stack
    stack variables which have been defined with the :obj:`default datatype <DataType.DEFAULT>`
    since the wrapped structure would otherwise be unable to preserve a variable name or comment.
    """

    @typing.type_check_only
    class StackComponentWrapper(ghidra.program.model.data.DataTypeComponent):
        """
        :obj:`StackComponentWrapper` wraps and standard :obj:`Structure`
        :obj:`DataTypeComponent` and provides the neccessary stack offset 
        translation.
        """

        class_: typing.ClassVar[java.lang.Class]

        def setComment(self, comment: typing.Union[java.lang.String, str]):
            """
            Unsupported method.  Must use :meth:`StackFrameDataType.setComment(int, String) <StackFrameDataType.setComment>`.
            """

        def setFieldName(self, fieldName: typing.Union[java.lang.String, str]):
            """
            Unsupported method.  Must use :meth:`StackFrameDataType.setName(int, String) <StackFrameDataType.setName>`.
            """


    class_: typing.ClassVar[java.lang.Class]

    def getDefaultName(self, stackComponent: StackFrameDataType.StackComponentWrapper) -> str:
        """
        Returns the default name for the indicated stack offset.
        
        :param StackFrameDataType.StackComponentWrapper stackComponent: stack element
        :return: the default stack variable name.
        :rtype: str
        """

    def getDefinedComponentAtOffset(self, stackOffset: typing.Union[jpype.JInt, int]) -> StackFrameDataType.StackComponentWrapper:
        """
        If a stack variable is defined in the editor at the specified offset, this retrieves the
        editor element containing that stack variable 
        
        Note: if a stack variable isn't defined at the indicated offset then null is returned.
        
        :param jpype.JInt or int stackOffset: the stack offset
        :return: the stack editor's element at the stackOffset. Otherwise, null.
        :rtype: StackFrameDataType.StackComponentWrapper
        """

    def getDefinedComponentAtOrdinal(self, ordinal: typing.Union[jpype.JInt, int]) -> StackFrameDataType.StackComponentWrapper:
        """
        If a stack variable is defined in the editor at the specified ordinal, this retrieves the
        editor element containing that stack variable. 
        
        
        :param jpype.JInt or int ordinal: the ordinal
        :return: the stack editor's element at the ordinal or null if an undefined location within
        the bounds of the stack.
        :rtype: StackFrameDataType.StackComponentWrapper
        :raises java.lang.IndexOutOfBoundsException: if the ordinal is out of bounds
        """

    def getFrameSize(self) -> int:
        ...

    @staticmethod
    def getHexString(offset: typing.Union[jpype.JInt, int], showPrefix: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get a formatted signed-hex value
        
        :param jpype.JInt or int offset: the value to be formatted
        :param jpype.JBoolean or bool showPrefix: if true the "0x" hex prefix will be included
        :return: formatted signed-hex value
        :rtype: str
        """

    def getLocalSize(self) -> int:
        ...

    def getMaxLength(self, stackOffset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the maximum variable size that will fit at the indicated offset if a replace is done.
        
        :param jpype.JInt or int stackOffset: stack offset
        :return: the maximum size
        :rtype: int
        """

    def getNegativeLength(self) -> int:
        ...

    def getParameterOffset(self) -> int:
        ...

    def getParameterSize(self) -> int:
        ...

    def getPositiveLength(self) -> int:
        ...

    def getReturnAddressOffset(self) -> int:
        ...

    def growsNegative(self) -> bool:
        ...

    def isStackVariable(self, ordinal: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if a stack variable is defined at the specified ordinal.
        
        :param jpype.JInt or int ordinal: stack frame ordinal
        :return: true if variable is defined at ordinal or false if undefined.
        :rtype: bool
        """

    def setComment(self, ordinal: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets the comment at the specified ordinal.
        
        :param jpype.JInt or int ordinal: the ordinal
        :param java.lang.String or str comment: the new comment.
        :return: true if comment change was successful, else false
        :rtype: bool
        :raises java.lang.IndexOutOfBoundsException: if specified ordinal is out of range
        """

    def setDataType(self, ordinal: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]) -> StackFrameDataType.StackComponentWrapper:
        """
        Sets a stack component/variable data type
        
        :param jpype.JInt or int ordinal: the ordinal
        :param ghidra.program.model.data.DataType dataType: the data type
        :param jpype.JInt or int length: the length or size of this variable.
        :return: the component representing this stack variable.
        :rtype: StackFrameDataType.StackComponentWrapper
        :raises java.lang.IndexOutOfBoundsException: if specified ordinal is out of range
        """

    def setLocalSize(self, size: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def setName(self, ordinal: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets the name of the component at the specified ordinal.
        
        :param jpype.JInt or int ordinal: the ordinal
        :param java.lang.String or str name: the new name. Null indicates the default name.
        :return: true if name change was successful, else false
        :rtype: bool
        :raises java.lang.IndexOutOfBoundsException: if specified ordinal is out of range
        :raises IllegalArgumentException: if name is invalid
        """

    def setOffset(self, ordinal: typing.Union[jpype.JInt, int], newOffset: typing.Union[jpype.JInt, int]) -> StackFrameDataType.StackComponentWrapper:
        """
        Effectively moves a component for a defined stack variable if it will fit where it is being
        moved to in the stack frame.
        
        :param jpype.JInt or int ordinal: the ordinal of the component to move by changing its offset.
        :param jpype.JInt or int newOffset: the offset to move the variable to.
        :return: the component representing the stack variable at the new offset.
        :rtype: StackFrameDataType.StackComponentWrapper
        :raises InvalidInputException: if it can't be moved.
        :raises java.lang.IndexOutOfBoundsException: if the ordinal is out of bounds
        """

    def setParameterSize(self, newParamSize: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @property
    def negativeLength(self) -> jpype.JInt:
        ...

    @property
    def returnAddressOffset(self) -> jpype.JInt:
        ...

    @property
    def positiveLength(self) -> jpype.JInt:
        ...

    @property
    def frameSize(self) -> jpype.JInt:
        ...

    @property
    def localSize(self) -> jpype.JInt:
        ...

    @property
    def stackVariable(self) -> jpype.JBoolean:
        ...

    @property
    def parameterSize(self) -> jpype.JInt:
        ...

    @property
    def definedComponentAtOrdinal(self) -> StackFrameDataType.StackComponentWrapper:
        ...

    @property
    def parameterOffset(self) -> jpype.JInt:
        ...

    @property
    def defaultName(self) -> java.lang.String:
        ...

    @property
    def maxLength(self) -> jpype.JInt:
        ...

    @property
    def definedComponentAtOffset(self) -> StackFrameDataType.StackComponentWrapper:
        ...


class StackEditorManager(ghidra.app.plugin.core.compositeeditor.EditorListener):
    """
    Manages edit sessions of function stack frames for multiple open programs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: StackEditorManagerPlugin):
        """
        Constructor
        
        :param StackEditorManagerPlugin plugin: the plugin that owns this manager.
        """

    def dispose(self):
        """
        Tells a plugin that it is no longer needed.  The plugin should remove itself
        from anything that it is registered to and release any resources.
        """

    def edit(self, function: ghidra.program.model.listing.Function):
        """
        Pop up the editor dialog for the given stack frame.
        
        :param ghidra.program.model.listing.Function function: function whose stack frame is to be edited
        """



__all__ = ["EditStackAction", "StackEditorModel", "StackEditorProvider", "StackEditorManagerPlugin", "StackEditorPanel", "StackEditorOptionManager", "StackFrameDataType", "StackEditorManager"]
