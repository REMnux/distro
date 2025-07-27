from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.textfield
import ghidra.docking.settings
import ghidra.util
import ghidra.util.datastruct
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.table # type: ignore
import javax.swing.text # type: ignore


T = typing.TypeVar("T")


class ObjectChooserDialog(docking.DialogComponentProvider, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], objectClass: java.lang.Class[T], choosableObjects: java.util.List[T], *methodsForColumns: typing.Union[java.lang.String, str]):
        ...

    def getSelectedObject(self) -> T:
        ...

    def getTable(self) -> docking.widgets.table.GTableWidget[T]:
        ...

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def selectedObject(self) -> T:
        ...

    @property
    def table(self) -> docking.widgets.table.GTableWidget[T]:
        ...


class NumberInputDialog(AbstractNumberInputDialog):
    """
    
    DialogComponentProvider that provides information to create a modal dialog
    to prompt for a number (int) to be input by the user.</P>
    
     
    If an initial value is specified it is not in the range of min,max, it will be set to the 
    min.</P>
    
     
    If the maximum value indicated is less than the minimum then the max
    is the largest positive integer. Otherwise the maximum valid value is
    as indicated.</P>
    
     
    This dialog component provider class can be used by various classes and
    therefore should not have its size or position remembered by the
    tool.showDialog() call parameters.</P>
     
    To display the dialog call:
     
    ``
        String entryType = "items";
        int initial = 5; // initial value in text field.
        int min = 1;     // minimum valid value in text field.
        int max = 10;    // maximum valid value in text field.
    
        NumberInputDialog numInputProvider = new NumberInputProvider(entryType, initial, min, max);
        if (numInputProvider.show()) {
                // not cancelled
                int result = numInputProvider.getValue();
        }
    ``
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entryType: typing.Union[java.lang.String, str], initial: typing.Union[jpype.JInt, int], min: typing.Union[jpype.JInt, int]):
        """
        Constructs a new NumberInputDialog
        
        :param java.lang.String or str entryType: item type the number indicates
                        (i.e. "duplicates", "items", or "elements")
        :param jpype.JInt or int initial: default value displayed in the text field
        :param jpype.JInt or int min: minimum value allowed
        """

    @typing.overload
    def __init__(self, entryType: typing.Union[java.lang.String, str], initial: typing.Union[jpype.JInt, int], min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        Constructs a new NumberInputDialog
        
        :param java.lang.String or str entryType: item type the number indicates
                        (i.e. "duplicates", "items", or "elements")
        :param jpype.JInt or int initial: default value displayed in the text field
        :param jpype.JInt or int min: minimum value allowed
        :param jpype.JInt or int max: maximum value allowed
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.Integer, int], min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int], showAsHex: typing.Union[jpype.JBoolean, bool]):
        """
        Show a number input dialog
        
        :param java.lang.String or str title: The title of the dialog
        :param java.lang.String or str prompt: the prompt to display before the number input field
        :param java.lang.Integer or int initialValue: the default value to display, null will leave the field blank
        :param jpype.JInt or int min: the minimum allowed value of the field
        :param jpype.JInt or int max: the maximum allowed value of the field
        :param jpype.JBoolean or bool showAsHex: if true, the initial value will be displayed as hex
        """

    def getValue(self) -> int:
        """
        Convert the input to an int value
        
        :return: the int value
        :rtype: int
        :raises NumberFormatException: if entered value cannot be parsed
        :raises IllegalStateException: if the dialog was cancelled
        """

    @property
    def value(self) -> jpype.JInt:
        ...


class NumberRangeInputDialog(docking.DialogComponentProvider):
    """
    An input dialog that accepts number input as discrete values or a range of values using 
    ':' as the range separator.
    """

    @typing.type_check_only
    class MyHintTextField(docking.widgets.textfield.HintTextField):

        @typing.type_check_only
        class MyDocument(javax.swing.text.PlainDocument):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str]):
        ...

    def getValue(self) -> ghidra.util.datastruct.SortedRangeList:
        """
        Return the value of the first (and maybe only) text field
        
        :return: the text field value
        :rtype: ghidra.util.datastruct.SortedRangeList
        """

    def setValue(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text of the primary text field
        
        :param java.lang.String or str text: the text
        """

    def show(self) -> bool:
        """
        ``show`` displays the dialog, gets the user input
        
        :return: false if the user cancelled the operation
        :rtype: bool
        """

    def wasCancelled(self) -> bool:
        """
        Returns if this dialog is cancelled
        
        :return: true if cancelled
        :rtype: bool
        """

    @property
    def value(self) -> ghidra.util.datastruct.SortedRangeList:
        ...


@deprecated("This class has been replaced by TableSelectionDialog.   At the time of\n writing, both classes are identical.   This version introduced a naming conflict with another\n API.   Thus, the new version better matches the existing dialog choosing API.")
class TableChooserDialog(docking.DialogComponentProvider, typing.Generic[T]):
    """
    
    
    
    .. deprecated::
    
    This class has been replaced by :obj:`TableSelectionDialog`.   At the time of
    writing, both classes are identical.   This version introduced a naming conflict with another
    API.   Thus, the new version better matches the existing dialog choosing API.
    """

    class_: typing.ClassVar[java.lang.Class]

    @deprecated("see the class header")
    def __init__(self, title: typing.Union[java.lang.String, str], model: docking.widgets.table.RowObjectTableModel[T], allowMultipleSelection: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new Dialog for displaying and choosing table row items
        
        :param java.lang.String or str title: The title for the dialog
        :param docking.widgets.table.RowObjectTableModel[T] model: a :obj:`RowObjectTableModel` that has the tRable data
        :param jpype.JBoolean or bool allowMultipleSelection: if true, the dialog allows the user to select more
        than one row; otherwise, only single selection is allowed
        
        .. deprecated::
        
        see the class header
        """

    @deprecated("see the class header")
    def getSelectionItems(self) -> java.util.List[T]:
        """
        Returns the list of selected items or null if the dialog was cancelled.
        
        :return: the list of selected items or null if the dialog was cancelled.
        :rtype: java.util.List[T]
        
        .. deprecated::
        
        see the class header
        """

    @property
    def selectionItems(self) -> java.util.List[T]:
        ...


class InputDialog(docking.DialogComponentProvider):
    """
    A dialog that has text fields to get user input.
    """

    @typing.type_check_only
    class MyTextField(javax.swing.JTextField):

        @typing.type_check_only
        class MyDocument(javax.swing.text.PlainDocument):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str]):
        """
        Creates a provider for a generic input dialog with the specified title, a text field, labeled
        by the specified label. The user should check the value of "isCanceled()" to know whether or
        not the user canceled the operation. Otherwise, use the "getValue()" or "getValues()" to get
        the value(s) entered by the user. Use the tool's "showDialog()" to display the dialog.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param java.lang.String or str label: value to use for the label of the text field
        """

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.String, str]):
        """
        Creates a generic input dialog with the specified title, a text field, labeled by the
        specified label. The user should check the value of "isCanceled()" to know whether or not the
        user canceled the operation. Otherwise, use the "getValue()" or "getValues()" to get the
        value(s) entered by the user. Use the tool's "showDialog()" to display the dialog.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param java.lang.String or str label: value to use for the label of the text field
        :param java.lang.String or str initialValue: initial value to use for the text field
        """

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.String, str], listener: InputDialogListener):
        """
        Creates a generic input dialog with the specified title, a text field, labeled by the
        specified label. The user should check the value of "isCanceled()" to know whether or not the
        user canceled the operation. Otherwise, use the "getValue()" or "getValues()" to get the
        value(s) entered by the user. Use the tool's "showDialog()" to display the dialog.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param java.lang.String or str label: value to use for the label of the text field
        :param java.lang.String or str initialValue: initial value to use for the text field
        :param InputDialogListener listener: the dialog listener (may be null)
        """

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.String, str], isModal: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a generic input dialog with the specified title, a text field, labeled by the
        specified label. The user should check the value of "isCanceled()" to know whether or not the
        user canceled the operation. Otherwise, use the "getValue()" or "getValues()" to get the
        value(s) entered by the user. Use the tool's "showDialog()" to display the dialog.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param java.lang.String or str label: value to use for the label of the text field
        :param java.lang.String or str initialValue: initial value to use for the text field
        :param jpype.JBoolean or bool isModal: whether or not the dialog is to be modal
        """

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], labels: jpype.JArray[java.lang.String], initialValues: jpype.JArray[java.lang.String]):
        """
        Creates a generic input dialog with the specified title, a text field, labeled by the
        specified label. The user should check the value of "isCanceled()" to know whether or not the
        user canceled the operation. Otherwise, use the "getValue()" or "getValues()" to get the
        value(s) entered by the user. Use the tool's "showDialog()" to display the dialog.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param jpype.JArray[java.lang.String] labels: values to use for the labels of the text fields
        :param jpype.JArray[java.lang.String] initialValues: initial values to use for the text fields
        """

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], labels: jpype.JArray[java.lang.String], initialValues: jpype.JArray[java.lang.String], listener: InputDialogListener):
        """
        Creates a generic input dialog with the specified title, a text field, labeled by the
        specified label. The user should check the value of "isCanceled()" to know whether or not the
        user canceled the operation. Otherwise, use the "getValue()" or "getValues()" to get the
        value(s) entered by the user. Use the tool's "showDialog()" to display the dialog.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param jpype.JArray[java.lang.String] labels: values to use for the labels of the text fields
        :param jpype.JArray[java.lang.String] initialValues: initial values to use for the text fields
        :param InputDialogListener listener: listener that is called when the OK button is hit
        """

    def getValue(self) -> str:
        """
        Return the value of the first (and maybe only) text field
        
        :return: the text field value
        :rtype: str
        """

    def getValues(self) -> jpype.JArray[java.lang.String]:
        """
        Return the values for all the text field(s)
        
        :return: the text field values
        :rtype: jpype.JArray[java.lang.String]
        """

    def isCanceled(self) -> bool:
        """
        Returns if this dialog is cancelled
        
        :return: true if cancelled
        :rtype: bool
        """

    @typing.overload
    def setValue(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text of the primary text field
        
        :param java.lang.String or str text: the text
        """

    @typing.overload
    def setValue(self, text: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]):
        """
        Sets the text of the text field at the given index
        
        :param java.lang.String or str text: the text
        :param jpype.JInt or int index: the index of the text field
        """

    @property
    def canceled(self) -> jpype.JBoolean:
        ...

    @property
    def values(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def value(self) -> java.lang.String:
        ...

    @value.setter
    def value(self, value: java.lang.String):
        ...


class BigIntegerNumberInputDialog(AbstractNumberInputDialog):
    """
    
    DialogComponentProvider that provides information to create a modal dialog
    to prompt for a number larger than an ``int`` or ``long`` to be input by the user.</P>
    
     
    Note: if you intend to only work with number values less than :obj:`Integer.MAX_VALUE`, 
    then you should use the :obj:`NumberInputDialog`.
    
     
    If an initial value is specified it is not in the range of min,max, it will be set to the min.</P>
    
     
    If the maximum value indicated is less than the minimum then the max
    is the largest positive integer. Otherwise the maximum valid value is
    as indicated.</P>
    
     
    This dialog component provider class can be used by various classes and
    therefore should not have its size or position remembered by the
    tool.showDialog() call parameters.</P>
     
    To display the dialog call:
     
    ``
        String entryType = "items";
        BigInteger initial = 5; // initial value in text field
        BigInteger min = BigInteger.valueOf(1);     // minimum valid value in text field
        BigInteger max = BigInteger.valueOf(10);    // maximum valid value in text field
    
        BigIntegerNumberInputDialog provider = 
            new BigIntegerNumberInputDialog("Title", entryType, initial, min, max);
        if (numInputProvider.show()) {
                // not cancelled
                BigInteger result = provider.getValue();
                long longResult = provider.getLongValue();
        }
    ``
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], initialValue: java.math.BigInteger, min: java.math.BigInteger, max: java.math.BigInteger, showAsHex: typing.Union[jpype.JBoolean, bool]):
        ...

    def getValue(self) -> java.math.BigInteger:
        """
        Get the current input value
        
        :return: the value
        :rtype: java.math.BigInteger
        :raises NumberFormatException: if entered value cannot be parsed
        :raises IllegalStateException: if the dialog was cancelled
        """

    @property
    def value(self) -> java.math.BigInteger:
        ...


class SettingsDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class SettingsRowObject(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getName(self) -> str:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class SettingsTableModel(docking.widgets.table.AbstractSortedTableModel[SettingsDialog.SettingsRowObject]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SettingsEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, javax.swing.event.PopupMenuListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, help: ghidra.util.HelpLocation):
        ...

    def getTable(self) -> docking.widgets.table.GTable:
        ...

    def show(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], newSettingsDefs: jpype.JArray[ghidra.docking.settings.SettingsDefinition], newSettings: ghidra.docking.settings.Settings):
        ...

    @property
    def table(self) -> docking.widgets.table.GTable:
        ...


class TableSelectionDialog(docking.DialogComponentProvider, typing.Generic[T]):
    """
    Dialog for displaying table data in a dialog for the purpose of the user selecting one or
    more items from the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], model: docking.widgets.table.RowObjectTableModel[T], allowMultipleSelection: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new Dialog for displaying and choosing table row items
        
        :param java.lang.String or str title: The title for the dialog
        :param docking.widgets.table.RowObjectTableModel[T] model: a :obj:`RowObjectTableModel` that has the tRable data
        :param jpype.JBoolean or bool allowMultipleSelection: if true, the dialog allows the user to select more
        than one row; otherwise, only single selection is allowed
        """

    def getSelectionItems(self) -> java.util.List[T]:
        """
        Returns the list of selected items or null if the dialog was cancelled.
        
        :return: the list of selected items or null if the dialog was cancelled.
        :rtype: java.util.List[T]
        """

    @property
    def selectionItems(self) -> java.util.List[T]:
        ...


class InputWithChoicesDialog(docking.DialogComponentProvider):
    """
    A dialog that has text fields to get user input.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], optionValues: jpype.JArray[java.lang.String], initialValue: typing.Union[java.lang.String, str], messageIcon: javax.swing.Icon):
        """
        Creates a provider for a generic input dialog with the specified title, a label and a
        editable comboBox pre-populated with selectable values. The user can check the value of
        :meth:`isCanceled() <.isCanceled>` to know whether or not the user canceled the operation. To get the
        user selected value use the :meth:`getValue() <.getValue>` value(s) entered by the user.  If the user
        cancelled the operation, then null will be returned from :meth:`getValue() <.getValue>`.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param java.lang.String or str label: value to use for the label of the text field
        :param jpype.JArray[java.lang.String] optionValues: values to populate the combo box
        :param java.lang.String or str initialValue: the initial value; may be null
        :param javax.swing.Icon messageIcon: the icon to display on the dialog; may be null
        """

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], optionValues: jpype.JArray[java.lang.String], initialValue: typing.Union[java.lang.String, str], allowEdits: typing.Union[jpype.JBoolean, bool], messageIcon: javax.swing.Icon):
        """
        Creates a provider for a generic input dialog with the specified title, a label and a
        editable comboBox pre-populated with selectable values. The user can check the value of
        :meth:`isCanceled() <.isCanceled>` to know whether or not the user canceled the operation. To get the
        user selected value use the :meth:`getValue() <.getValue>` value(s) entered by the user.  If the user
        cancelled the operation, then null will be returned from :meth:`getValue() <.getValue>`.
        
        :param java.lang.String or str dialogTitle: used as the name of the dialog's title bar
        :param java.lang.String or str label: value to use for the label of the text field
        :param jpype.JArray[java.lang.String] optionValues: values to populate the combo box
        :param java.lang.String or str initialValue: the initial value; may be null
        :param jpype.JBoolean or bool allowEdits: true allows the user to add custom entries by entering text
        :param javax.swing.Icon messageIcon: the icon to display on the dialog; may be null
        """

    def getValue(self) -> str:
        """
        Return the value of the first combo box.
        
        :return: the value
        :rtype: str
        """

    def isCanceled(self) -> bool:
        """
        Returns if this dialog is canceled.
        
        :return: true if canceled
        :rtype: bool
        """

    def setValue(self, value: typing.Union[java.lang.String, str]):
        """
        Set the current choice to value.
        
        :param java.lang.String or str value: updated choice
        :raises NoSuchElementException: if edits not permitted and value is not a valid choice
        """

    @property
    def canceled(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> java.lang.String:
        ...

    @value.setter
    def value(self, value: java.lang.String):
        ...


class MultiLineInputDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], messageText: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        ...

    def getValue(self) -> str:
        """
        return the value of the first combo box
        """

    def isCanceled(self) -> bool:
        """
        Returns if this dialog is canceled.
        """

    @property
    def canceled(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> java.lang.String:
        ...


class ReadTextDialog(docking.DialogComponentProvider):
    """
    General purpose modal dialog to display text in a text area.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], text: typing.Union[java.lang.String, str]):
        """
        Construct a new ReadTextDialog
        
        :param java.lang.String or str title: title for this dialog
        :param java.lang.String or str text: text to display in the text area
        """

    def getText(self) -> str:
        """
        Get the text displayed in the text area.
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Set the text in the text area.
        """

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...


class AbstractNumberInputDialog(docking.DialogComponentProvider):
    """
    A base class for prompting users to enter a number into this dialog
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.Integer, int], min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int], showAsHex: typing.Union[jpype.JBoolean, bool]):
        """
        Show a number input dialog
        
        :param java.lang.String or str title: The title of the dialog
        :param java.lang.String or str prompt: the prompt to display before the number input field
        :param java.lang.Integer or int initialValue: the default value to display, null will leave the field blank
        :param jpype.JInt or int min: the minimum allowed value of the field
        :param jpype.JInt or int max: the maximum allowed value of the field
        :param jpype.JBoolean or bool showAsHex: if true, the initial value will be displayed as hex
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], initialValue: java.math.BigInteger, min: java.math.BigInteger, max: java.math.BigInteger, showAsHex: typing.Union[jpype.JBoolean, bool]):
        """
        Show a number input dialog
        
        :param java.lang.String or str title: The title of the dialog
        :param java.lang.String or str prompt: the prompt to display before the number input field
        :param java.math.BigInteger initialValue: the default value to display, null will leave the field blank
        :param java.math.BigInteger min: the minimum allowed value of the field
        :param java.math.BigInteger max: the maximum allowed value of the field
        :param jpype.JBoolean or bool showAsHex: if true, the initial value will be displayed as hex
        """

    def getBigIntegerValue(self) -> java.math.BigInteger:
        """
        Get the current input value
        
        :return: the value
        :rtype: java.math.BigInteger
        :raises NumberFormatException: if entered value cannot be parsed
        :raises IllegalStateException: if the dialog was cancelled
        """

    def getIntValue(self) -> int:
        """
        Get the current input value as an int
        
        :return: the value
        :rtype: int
        :raises NumberFormatException: if entered value cannot be parsed
        :raises IllegalStateException: if the dialog was cancelled
        :raises ArithmeticException: if the value in this field will not fit into an int
        """

    def getLongValue(self) -> int:
        """
        Get the current input value as a long
        
        :return: the value
        :rtype: int
        :raises NumberFormatException: if entered value cannot be parsed
        :raises IllegalStateException: if the dialog was cancelled
        :raises ArithmeticException: if the value in this field will not fit into a long
        """

    def getMax(self) -> int:
        """
        Return the maximum acceptable value.
        
        :return: the max
        :rtype: int
        """

    def getMin(self) -> int:
        """
        Return the minimum acceptable value.
        
        :return: the min
        :rtype: int
        """

    def setDefaultMessage(self, defaultMessage: typing.Union[java.lang.String, str]):
        """
        Sets the default message to be displayed when valid values are in the text fields.
        
        :param java.lang.String or str defaultMessage: the message to be displayed when valid values are in the text fields.
        """

    def setInput(self, value: typing.Union[jpype.JInt, int]):
        """
        Sets the value in the input field to the indicated value.
        
        :param jpype.JInt or int value: the value
        """

    def show(self) -> bool:
        """
        ``show`` displays the dialog, gets the user input
        
        :return: false if the user cancelled the operation
        :rtype: bool
        """

    def wasCancelled(self) -> bool:
        """
        Return whether the user cancelled the input dialog
        
        :return: true if cancelled
        :rtype: bool
        """

    @property
    def bigIntegerValue(self) -> java.math.BigInteger:
        ...

    @property
    def min(self) -> jpype.JInt:
        ...

    @property
    def max(self) -> jpype.JInt:
        ...

    @property
    def intValue(self) -> jpype.JInt:
        ...

    @property
    def longValue(self) -> jpype.JLong:
        ...


class MultiLineMessageDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]
    ERROR_MESSAGE: typing.Final = 0
    """
    Used for error messages.
    """

    INFORMATION_MESSAGE: typing.Final = 1
    """
    Used for information messages.
    """

    WARNING_MESSAGE: typing.Final = 2
    """
    Used for warning messages.
    """

    QUESTION_MESSAGE: typing.Final = 3
    """
    Used for questions.
    """

    PLAIN_MESSAGE: typing.Final = -1
    """
    No icon is used.
    """


    def __init__(self, title: typing.Union[java.lang.String, str], shortMessage: typing.Union[java.lang.String, str], detailedMessage: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int], modal: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a multi-line popup dialog.
        
        :param java.lang.String or str title: the dialog title
        :param java.lang.String or str shortMessage: a short message to display at the top of the dialog
        :param java.lang.String or str detailedMessage: the detailed message
        :param jpype.JInt or int messageType: the message type (warning, error, info, etc)
        :param jpype.JBoolean or bool modal: true if the dialog should be modal
        """

    @staticmethod
    def showMessageDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], shortMessage: typing.Union[java.lang.String, str], detailedMessage: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def showModalMessageDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], shortMessage: typing.Union[java.lang.String, str], detailedMessage: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]):
        """
        Static helper method to easily display a modal message dialog showing a text string
        with an "OK" button.
         
        
        If the text is too long to fit, a scroll bar will be used.
         
        
        The text string can be plain text (with \n line breaks) or HTML (if the first
        6 characters of the string are ``<html>``).
         
        
        This method will not return until the user presses the OK button.
        
        :param java.awt.Component parent: - parent component or null
        :param java.lang.String or str title: - dialog title
        :param java.lang.String or str shortMessage: - short message that appears above the main message.
        :param java.lang.String or str detailedMessage: - long scrollable message.
        :param jpype.JInt or int messageType: - see :obj:`.ERROR_MESSAGE`, :obj:`.INFORMATION_MESSAGE`,
        :obj:`.WARNING_MESSAGE`, :obj:`.QUESTION_MESSAGE`, :obj:`.PLAIN_MESSAGE`
        """


class StringChoices(java.lang.Object):
    """
    StringEnum objects represent a choice from a limited set of options.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, values: jpype.JArray[java.lang.String]):
        """
        Construct from an array of Strings.
        The order of Strings is preserved.
        """

    @typing.overload
    def __init__(self, strEnum: StringChoices):
        """
        Construct from another StringEnum instance.
        """

    def contains(self, value: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given value is contained in this StringEnum
        
        :param java.lang.String or str value: The value for which to search
        :return: true if the given value is contained in this StringEnum
        :rtype: bool
        """

    def getSelectedValue(self) -> str:
        """
        Returns the currently selected value.
        """

    def getSelectedValueIndex(self) -> int:
        """
        Returns the index of the currently selected value;
        """

    def getValues(self) -> jpype.JArray[java.lang.String]:
        """
        Returns a list of all allowed string values.
        """

    def indexOf(self, value: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the index of the given value in this StringEnum; -1 if the value is not contained
        herein.
        
        :param java.lang.String or str value: The value for which to search
        :return: the index of the given value in this StringEnum; -1 if the value is not contained
                herein.
        :rtype: int
        """

    @typing.overload
    def setSelectedValue(self, value: typing.Union[java.lang.String, str]):
        """
        Sets the currentValue to the given value.
        
        :raises IllegalArgumentException: thrown if the given value is not one
        of the set of allowed values.
        """

    @typing.overload
    def setSelectedValue(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the current value to the object at the given position as if indexed
        into the array returned by getValues().
        """

    @property
    def values(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def selectedValueIndex(self) -> jpype.JInt:
        ...

    @property
    def selectedValue(self) -> java.lang.String:
        ...

    @selectedValue.setter
    def selectedValue(self, value: java.lang.String):
        ...


class InputDialogListener(java.lang.Object):
    """
    Listener that is notified when the OK button is hit on the input dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    def inputIsValid(self, dialog: InputDialog) -> bool:
        """
        Return whether the input is accepted.
        
        :return: true if the input is valid; the dialog will be popped down;
        false means that the dialog will remain displayed.
        :rtype: bool
        """



__all__ = ["ObjectChooserDialog", "NumberInputDialog", "NumberRangeInputDialog", "TableChooserDialog", "InputDialog", "BigIntegerNumberInputDialog", "SettingsDialog", "TableSelectionDialog", "InputWithChoicesDialog", "MultiLineInputDialog", "ReadTextDialog", "AbstractNumberInputDialog", "MultiLineMessageDialog", "StringChoices", "InputDialogListener"]
