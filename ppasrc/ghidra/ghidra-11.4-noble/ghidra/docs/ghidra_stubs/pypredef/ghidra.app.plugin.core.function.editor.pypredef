from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets
import docking.widgets.table
import ghidra.app.services
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore


class RegisterDropDownSelectionDataModel(docking.widgets.DropDownTextFieldDataModel[ghidra.program.model.lang.Register]):
    """
    The data model for :obj:`DropDownSelectionTextField` that allows the text field to work with
    :obj:`Register`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, registers: java.util.List[ghidra.program.model.lang.Register]):
        ...


@typing.type_check_only
class StorageTableCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: FunctionEditorModel):
        ...


@typing.type_check_only
class FunctionDataView(java.lang.Object):
    """
    :obj:`FunctionDataView` provides an immutable view of function data used by the 
    Function Editor model.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


@typing.type_check_only
class VarnodeTableModel(docking.widgets.table.AbstractGTableModel[VarnodeInfo]):

    @typing.type_check_only
    class VarnodeCol(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], preferredSize: typing.Union[jpype.JInt, int], classType: java.lang.Class[typing.Any], isEditable: typing.Union[jpype.JBoolean, bool]):
            ...

        def getColumnClass(self) -> java.lang.Class[typing.Any]:
            ...

        def getName(self) -> str:
            ...

        def getPreferredSize(self) -> int:
            ...

        def getValueForRow(self, varnode: VarnodeInfo) -> java.lang.Object:
            ...

        def isCellEditable(self, rowIndex: typing.Union[jpype.JInt, int]) -> bool:
            ...

        def setValue(self, varnode: VarnodeInfo, aValue: java.lang.Object):
            ...

        @property
        def valueForRow(self) -> java.lang.Object:
            ...

        @property
        def columnClass(self) -> java.lang.Class[typing.Any]:
            ...

        @property
        def cellEditable(self) -> jpype.JBoolean:
            ...

        @property
        def preferredSize(self) -> jpype.JInt:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class TypeColumn(VarnodeTableModel.VarnodeCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class LocationColumn(VarnodeTableModel.VarnodeCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SizeColumn(VarnodeTableModel.VarnodeCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionData(FunctionDataView):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function):
        ...


@typing.type_check_only
class FunctionSignatureTextField(javax.swing.JTextPane):

    @typing.type_check_only
    class ColorField(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def length(self) -> int:
            ...


    @typing.type_check_only
    class SubString(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def charAt(self, i: typing.Union[jpype.JInt, int]) -> str:
            ...

        def getEnd(self) -> int:
            ...

        def getStart(self) -> int:
            ...

        def lastIndexOf(self, c: typing.Union[jpype.JChar, int, str]) -> int:
            ...

        def length(self) -> int:
            ...

        def substring(self, start: typing.Union[jpype.JInt, int]) -> FunctionSignatureTextField.SubString:
            ...

        def trim(self) -> FunctionSignatureTextField.SubString:
            ...

        @property
        def start(self) -> jpype.JInt:
            ...

        @property
        def end(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_COLOR: typing.ClassVar[java.awt.Color]
    PARAMETER_NAME_COLOR: typing.ClassVar[java.awt.Color]
    FUNCTION_NAME_COLOR: typing.ClassVar[java.awt.Color]
    ERROR_NAME_COLOR: typing.ClassVar[java.awt.Color]

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class ParamInfo(java.lang.Comparable[ParamInfo]):

    class_: typing.ClassVar[java.lang.Class]

    def getFormalDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @typing.overload
    def getName(self, returnNullForDefault: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @typing.overload
    def getName(self) -> str:
        ...

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    def isSame(self, otherParam: ParamInfo) -> bool:
        ...

    @property
    def same(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def formalDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def storage(self) -> ghidra.program.model.listing.VariableStorage:
        ...


@typing.type_check_only
class ParameterTableModel(docking.widgets.table.AbstractGTableModel[FunctionVariableData]):

    @typing.type_check_only
    class ParamCol(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], preferredSize: typing.Union[jpype.JInt, int], classType: java.lang.Class[typing.Any], isEditable: typing.Union[jpype.JBoolean, bool]):
            ...

        def getColumnClass(self) -> java.lang.Class[typing.Any]:
            ...

        def getName(self) -> str:
            ...

        def getPreferredSize(self) -> int:
            ...

        def getValueForRow(self, rowDatas: FunctionVariableData) -> java.lang.Object:
            ...

        def isCellEditable(self, rowIndex: typing.Union[jpype.JInt, int]) -> bool:
            ...

        def setValue(self, rowData: FunctionVariableData, aValue: java.lang.Object):
            ...

        @property
        def valueForRow(self) -> java.lang.Object:
            ...

        @property
        def columnClass(self) -> java.lang.Class[typing.Any]:
            ...

        @property
        def cellEditable(self) -> jpype.JBoolean:
            ...

        @property
        def preferredSize(self) -> jpype.JInt:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class ParameterIndexColumn(ParameterTableModel.ParamCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class DataTypeColumn(ParameterTableModel.ParamCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class NameColumn(ParameterTableModel.ParamCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class StorageColumn(ParameterTableModel.ParamCol):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ParameterRowData(FunctionVariableData):

        class_: typing.ClassVar[java.lang.Class]

        def getParamInfo(self) -> ParamInfo:
            ...

        @property
        def paramInfo(self) -> ParamInfo:
            ...


    @typing.type_check_only
    class ReturnRowData(FunctionVariableData):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getParameters(self) -> java.util.List[ParamInfo]:
        ...

    def setAllowStorageEditing(self, canCustomizeStorage: typing.Union[jpype.JBoolean, bool]):
        ...

    def setParameters(self, parameterList: java.util.List[ParamInfo], returnDataType: ghidra.program.model.data.DataType, returnStorage: ghidra.program.model.listing.VariableStorage):
        ...

    @property
    def parameters(self) -> java.util.List[ParamInfo]:
        ...


@typing.type_check_only
class VarnodeSizeCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VarnodeInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    @typing.overload
    def getRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @staticmethod
    @typing.overload
    def getRegister(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, size: typing.Union[java.lang.Integer, int]) -> ghidra.program.model.lang.Register:
        ...

    def getSize(self) -> int:
        ...

    def getType(self) -> VarnodeType:
        ...

    @typing.overload
    def setVarnode(self, address: ghidra.program.model.address.Address, size: typing.Union[java.lang.Integer, int]):
        ...

    @typing.overload
    def setVarnode(self, varnode: ghidra.program.model.pcode.Varnode):
        ...

    def setVarnodeType(self, type: VarnodeType):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> VarnodeType:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


@typing.type_check_only
class VarnodeLocationCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, docking.widgets.table.FocusableEditor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VarnodeType(java.lang.Enum[VarnodeType]):

    class_: typing.ClassVar[java.lang.Class]
    Register: typing.Final[VarnodeType]
    Stack: typing.Final[VarnodeType]
    Memory: typing.Final[VarnodeType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> VarnodeType:
        ...

    @staticmethod
    def values() -> jpype.JArray[VarnodeType]:
        ...


class StorageAddressEditorDialog(docking.DialogComponentProvider, ModelChangeListener):

    @typing.type_check_only
    class ReadOnlyVariableData(FunctionVariableData):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, service: ghidra.app.services.DataTypeManagerService, storage: ghidra.program.model.listing.VariableStorage, variableData: FunctionVariableData):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.app.services.DataTypeManagerService service: the data type manager service
        :param ghidra.program.model.listing.VariableStorage storage: the variable storage
        :param FunctionVariableData variableData: the variable data
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, service: ghidra.app.services.DataTypeManagerService, var: ghidra.program.model.listing.Variable, ordinal: typing.Union[jpype.JInt, int]):
        """
        Read-only use constructor for Help screenshot
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.app.services.DataTypeManagerService service: the data type manager service
        :param ghidra.program.model.listing.Variable var: function parameter to be displayed in editor dialog
        :param jpype.JInt or int ordinal: parameter ordinal (-1 for return)
        """

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    def wasCancelled(self) -> bool:
        ...

    @property
    def storage(self) -> ghidra.program.model.listing.VariableStorage:
        ...


@typing.type_check_only
class FunctionVariableData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFormalDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getIndex(self) -> int:
        """
        :return: parameter ordinal or null for return variable.
        :rtype: int
        """

    def getName(self) -> str:
        ...

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    def hasStorageConflict(self) -> bool:
        ...

    def setFormalDataType(self, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setStorage(self, storage: ghidra.program.model.listing.VariableStorage):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def formalDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def storage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    @storage.setter
    def storage(self, value: ghidra.program.model.listing.VariableStorage):
        ...


@typing.type_check_only
class VarnodeLocationTableCellRenderer(docking.widgets.table.GTableCellRenderer):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FunctionEditorModel(java.lang.Object):

    @typing.type_check_only
    class DummyModelChangedListener(ModelChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    PARSING_MODE_STATUS_TEXT: typing.Final[java.lang.String]

    def __init__(self, service: ghidra.app.services.DataTypeManagerService, function: ghidra.program.model.listing.Function):
        ...

    def canUseCustomStorage(self) -> bool:
        ...

    def getParameters(self) -> java.util.List[ParamInfo]:
        ...

    def hasChanged(self) -> bool:
        ...

    def removeParameters(self):
        ...

    def setCallingConventionName(self, callingConventionName: typing.Union[java.lang.String, str]):
        ...

    def setFormalReturnType(self, formalReturnType: ghidra.program.model.data.DataType) -> bool:
        ...

    def setFunctionData(self, functionDefinition: ghidra.program.model.data.FunctionDefinitionDataType):
        ...

    def setModelUnchanged(self):
        """
        Sets the change state of the model to unchanged. Normally, the model sets the modelChanged 
        variable to true every time something is changed. This provides a way to for applications 
        to make some initial changes but make the dialog think that nothing has changed.
        """

    def setParameterStorage(self, param: ParamInfo, storage: ghidra.program.model.listing.VariableStorage):
        ...

    def setReturnStorage(self, storage: ghidra.program.model.listing.VariableStorage):
        ...

    def setSelectedParameterRows(self, selectedRows: jpype.JArray[jpype.JInt]):
        ...

    def setUseCustomizeStorage(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Change custom storage enablement
        
        :param jpype.JBoolean or bool b: enablement state
        """

    @property
    def parameters(self) -> java.util.List[ParamInfo]:
        ...


class FunctionEditorDialog(docking.DialogComponentProvider, ModelChangeListener):

    @typing.type_check_only
    class ParameterDataTypeCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TableCell(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def col(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def row(self) -> int:
            ...

        def table(self) -> docking.widgets.table.GTable:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ParameterTable(docking.widgets.table.GTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VariableStorageCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VariableStringCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VerticalScrollablePanel(javax.swing.JPanel, javax.swing.Scrollable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class MyGlassPane(javax.swing.JComponent):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GlassPaneMouseListener(java.awt.event.MouseListener, java.awt.event.MouseMotionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, service: ghidra.app.services.DataTypeManagerService, function: ghidra.program.model.listing.Function):
        """
        Construct Function Editor dialog for a specified Function and associated DataType service.
        
        :param ghidra.app.services.DataTypeManagerService service: DataType service
        :param ghidra.program.model.listing.Function function: Function to be modified
        """

    @typing.overload
    def __init__(self, model: FunctionEditorModel, hasOptionalSignatureCommit: typing.Union[jpype.JBoolean, bool]):
        """
        Construct Function Editor dialog using a specified model
        
        :param FunctionEditorModel model: function detail model
        :param jpype.JBoolean or bool hasOptionalSignatureCommit: if true an optional control will be included which 
        controls commit of parameter/return details, including Varargs and use of custom storage.
        """


@typing.type_check_only
class VarnodeTypeCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ModelChangeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dataChanged(self):
        ...

    def tableRowsChanged(self):
        ...


@typing.type_check_only
class StorageAddressModel(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ParameterDataTypeCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, docking.widgets.table.FocusableEditor):

    class_: typing.ClassVar[java.lang.Class]

    def getChooserButton(self) -> javax.swing.JButton:
        """
        
        
        :return: chooser button '...' associated with the generated component.  Null will 
        be returned if getTableCellEditorComponent method has not yet been invoked.
        :rtype: javax.swing.JButton
        """

    def getTextField(self) -> docking.widgets.DropDownSelectionTextField[ghidra.program.model.data.DataType]:
        """
        
        
        :return: text field associated with the generated component.  Null will 
        be returned if getTableCellEditorComponent method has not yet been invoked.
        :rtype: docking.widgets.DropDownSelectionTextField[ghidra.program.model.data.DataType]
        """

    @property
    def chooserButton(self) -> javax.swing.JButton:
        ...

    @property
    def textField(self) -> docking.widgets.DropDownSelectionTextField[ghidra.program.model.data.DataType]:
        ...



__all__ = ["RegisterDropDownSelectionDataModel", "StorageTableCellEditor", "FunctionDataView", "VarnodeTableModel", "FunctionData", "FunctionSignatureTextField", "ParamInfo", "ParameterTableModel", "VarnodeSizeCellEditor", "VarnodeInfo", "VarnodeLocationCellEditor", "VarnodeType", "StorageAddressEditorDialog", "FunctionVariableData", "VarnodeLocationTableCellRenderer", "FunctionEditorModel", "FunctionEditorDialog", "VarnodeTypeCellEditor", "ModelChangeListener", "StorageAddressModel", "ParameterDataTypeCellEditor"]
