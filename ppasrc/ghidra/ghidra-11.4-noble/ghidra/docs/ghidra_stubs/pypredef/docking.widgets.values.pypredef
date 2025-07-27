from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.filechooser
import ghidra.util
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class StringValue(AbstractValue[java.lang.String]):
    """
    Value class for :obj:`String` values. 
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]):
        ...


class IntValue(AbstractValue[java.lang.Integer]):
    """
    Value class for :obj:`Integer` Value with an option for display the value as decimal or hex. The 
    editor component uses an :obj:`IntegerTextField` for display and editing the value. This
    value supports the concept of no value which is represented by the text field being empty. If
    the text field is not empty, then the field only allows valid numeric values.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs an IntValue that displays it value in decimal
        
        :param java.lang.String or str name: the name of the value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]):
        """
        Constructs an IntValue with a default value that displays it value in decimal
        
        :param java.lang.String or str name: the name of the value
        :param jpype.JInt or int defaultValue: the default value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.Integer, int], displayAsHex: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs an IntValue with a default value.
        
        :param java.lang.String or str name: the name of the value
        :param java.lang.Integer or int defaultValue: the default value
        :param jpype.JBoolean or bool displayAsHex: if true, the value will be displayed as hex, otherwise it will display
        as decimal.
        """


class LongValue(AbstractValue[java.lang.Long]):
    """
    Value class for Long Values with an option for display the value as decimal or hex. The 
    editor component uses an :obj:`IntegerTextField` for display and editing the value. This
    value supports the concept of no value which is represented by the text field being empty. If
    the text field is not empty, then the field only allows valid numeric values.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.Long, int]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], displayAsHex: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.Long, int], displayAsHex: typing.Union[jpype.JBoolean, bool]):
        ...


class ChoiceValue(AbstractValue[java.lang.String]):
    """
    Value class for selecting from a restricted set of :obj:`String`s. ChoiceValues uses a 
    :obj:`GComboBox` for the editor component.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]


class ValuesMapParseException(java.lang.Exception):
    """
    Exception thrown when processing/parsing ValuesMap values. Mostly exists so that the exception
    message is uniform throught the types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, valueName: typing.Union[java.lang.String, str], type: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str valueName: the name of the value that was being processed
        :param java.lang.String or str type: the type name of the value that was being processed
        :param java.lang.String or str message: the detail message of what went wrong
        """


class ValuesMapDialog(docking.DialogComponentProvider):
    """
    Dialog for displaying and editing values defined in a :obj:`GValuesMap`. The dialog consists
    of an option message, followed by a list of name / value pairs. The name / value pairs will
    be display in the order they were defined in the ValuesMap.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Creates the dialog with the given title and optional message. The message will be display
        at the top of the dialog before the list of name / value pairs. This form of the dialog
        requires that the :meth:`addValue(AbstractValue) <.addValue>` method be called to populate the
        ValuesMap.
        
        :param java.lang.String or str title: the title for the dialog
        :param java.lang.String or str message: the optional message to display before the list of name value pairs
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], valuesMap: GValuesMap):
        """
        Creates the dialog with the given title and optional message. The message will be display
        at the top of the dialog before the list of name / value pairs. The values are provided
        at construction time.
        
        :param java.lang.String or str title: the title for the dialog
        :param java.lang.String or str message: the optional message to display before the list of name value pairs
        :param GValuesMap valuesMap: the ValuesMap whose values are to be displayed.
        """

    def addValue(self, value: AbstractValue[typing.Any]) -> AbstractValue[typing.Any]:
        """
        Adds a new value to the ValuesMap being edited by this dialog.
        
        :param AbstractValue[typing.Any] value: the new AbstractValue to be added
        :return: the value that was added
        :rtype: AbstractValue[typing.Any]
        """

    def getValues(self) -> GValuesMap:
        """
        Returns the ValuesMap being edited.
        
        :return: the ValuesMap being edited.
        :rtype: GValuesMap
        """

    def isCancelled(self) -> bool:
        """
        Returns true if the dialog was cancelled.
        
        :return: true if the dialog was cancelled.
        :rtype: bool
        """

    def setValidator(self, validator: ValuesMapValidator):
        """
        Sets the :obj:`ValuesMapValidator` on the ValuesMap being edited. This is usually set on the
        ValuesMap before the dialog is constructed. This method is for uses where it wasn't 
        constructed with a ValueMap, but values were added directly to the dialog after dialog
        construction.
        
        :param ValuesMapValidator validator: the ValuesMapValidator
        """

    @property
    def values(self) -> GValuesMap:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...


class GValuesMap(java.lang.Object):
    """
    Class for defining, storing, and retrieving groups of values of various types. The intended use
    is to create a ValuesMap, define some named values, and then invoke the ValuesMapDialog to allow
    the user to fill in values for the defined values. It also has a rich set of convenience methods
    for adding predefined value types to the map. Users can also directly add custom value types by
    using the :meth:`addValue(AbstractValue) <.addValue>` method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addValue(self, value: AbstractValue[typing.Any]) -> AbstractValue[typing.Any]:
        """
        Adds an AbstractValue to this ValuesMap. This is a way to add a custom AbstractValue that
        doesn't have a convenience method for a predefine value type.
        
        :param AbstractValue[typing.Any] value: the AbstractValue to add to this ValuesMap
        :return: returns the added value
        :rtype: AbstractValue[typing.Any]
        """

    def copyValues(self, otherMap: GValuesMap):
        """
        Copies the values (not the AbstractValues objects, but the T values of each AbstractValue)
        from the given map into this map. The given map must have exactly the same name and
        AbstractValue types as this map.
        
        :param GValuesMap otherMap: The GValuesMap to copy values from
        :raises IllegalArgumentException: if the given map does not have exactly the same set of
        names and types as this map
        """

    def defineBoolean(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> BooleanValue:
        """
        Defines a value of type Boolean.
        
        :param java.lang.String or str name: the name for this value
        :param jpype.JBoolean or bool defaultValue: the default value for this boolean value.
        :return: the new BooleanValue that was defined.
        :rtype: BooleanValue
        """

    def defineChoice(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str], *choices: typing.Union[java.lang.String, str]) -> ChoiceValue:
        """
        Defines a value of type String, but with a restricted set of valid string values.
        
        :param java.lang.String or str name: the name for this value.
        :param java.lang.String or str defaultValue: an optional (can be null) initial value
        :param jpype.JArray[java.lang.String] choices: varargs list of valid string choices
        :return: the new ChoiceValue that was defined
        :rtype: ChoiceValue
        """

    def defineDirectory(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath) -> FileValue:
        """
        Defines a value of type File, but is restricted to directories.
        
        :param java.lang.String or str name: the name for this value
        :param jpype.protocol.SupportsPath defaultValue: an optional initial value
        :return: the new FileValue that was defined
        :rtype: FileValue
        """

    @typing.overload
    def defineDouble(self, name: typing.Union[java.lang.String, str]) -> DoubleValue:
        """
        Defines a value of type Double with no initial default value.
        
        :param java.lang.String or str name: the name for this value
        :return: the new DoubleValue that was defined
        :rtype: DoubleValue
        """

    @typing.overload
    def defineDouble(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JDouble, float]) -> DoubleValue:
        """
        Defines a value of type Double with an initial value
        
        :param java.lang.String or str name: the name for this value
        :param jpype.JDouble or float defaultValue: the initial value
        :return: the new DoubleValue that was defined
        :rtype: DoubleValue
        """

    @typing.overload
    def defineFile(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath) -> FileValue:
        """
        Defines a value of type File
        
        :param java.lang.String or str name: the name for this value
        :param jpype.protocol.SupportsPath defaultValue: an optional initial value
        :return: the new FileValue that was defined
        :rtype: FileValue
        """

    @typing.overload
    def defineFile(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath, startingDir: jpype.protocol.SupportsPath) -> FileValue:
        """
        Defines a value of type File
        
        :param java.lang.String or str name: the name for this value
        :param jpype.protocol.SupportsPath defaultValue: an optional initial value
        :param jpype.protocol.SupportsPath startingDir: specifies the starting directory when the FileChooser is invoked
        :return: the new FileValue that was defined
        :rtype: FileValue
        """

    @typing.overload
    def defineHexInt(self, name: typing.Union[java.lang.String, str]) -> IntValue:
        """
        Defines a value of type Integer that displays as a hex value.
        
        :param java.lang.String or str name: the name for this value
        :return: the new IntValue that was defined
        :rtype: IntValue
        """

    @typing.overload
    def defineHexInt(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> IntValue:
        """
        Defines a value of type Integer with an initial value and displays as a hex value.
        
        :param java.lang.String or str name: the name for this value
        :param jpype.JInt or int defaultValue: the initial value
        :return: the new IntValue that was defined
        :rtype: IntValue
        """

    @typing.overload
    def defineHexLong(self, name: typing.Union[java.lang.String, str]) -> LongValue:
        """
        Defines a value of type Long that displays as a hex value.
        
        :param java.lang.String or str name: the name for this value
        :return: the new LongValue that was defined
        :rtype: LongValue
        """

    @typing.overload
    def defineHexLong(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int]) -> LongValue:
        """
        Defines a value of type Long with an initial value and displays as a hex value.
        
        :param java.lang.String or str name: the name for this value
        :param jpype.JLong or int defaultValue: the initial value
        :return: the new LongValue that was defined
        :rtype: LongValue
        """

    @typing.overload
    def defineInt(self, name: typing.Union[java.lang.String, str]) -> IntValue:
        """
        Defines a value of type Integer with no initial value.
        
        :param java.lang.String or str name: the name for this value
        :return: the new IntValue that was defined
        :rtype: IntValue
        """

    @typing.overload
    def defineInt(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> IntValue:
        """
        Defines a value of type Integer with an initial value.
        
        :param java.lang.String or str name: the name for this value
        :param jpype.JInt or int defaultValue: the initial value
        :return: the new IntValue that was defined
        :rtype: IntValue
        """

    @typing.overload
    def defineLong(self, name: typing.Union[java.lang.String, str]) -> LongValue:
        """
        Defines a value of type Long with an initial value.
        
        :param java.lang.String or str name: the name for this value
        :return: the new LongValue that was defined
        :rtype: LongValue
        """

    @typing.overload
    def defineLong(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int]) -> LongValue:
        """
        Defines a value of type Long with an initial value.
        
        :param java.lang.String or str name: the name for this value
        :param jpype.JLong or int defaultValue: the initial value
        :return: the new LongValue that was defined
        :rtype: LongValue
        """

    @typing.overload
    def defineString(self, name: typing.Union[java.lang.String, str]) -> StringValue:
        """
        Defines a value of type String.
        
        :param java.lang.String or str name: the name for this value
        :return: the new StringValue that was defined
        :rtype: StringValue
        """

    @typing.overload
    def defineString(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> StringValue:
        """
        Defines a value of type String with an optional initial value
        
        :param java.lang.String or str name: the name for this value
        :param java.lang.String or str defaultValue: the initial value (can be null)
        :return: the new StringValue that was defined
        :rtype: StringValue
        """

    def getAbstractValue(self, name: typing.Union[java.lang.String, str]) -> AbstractValue[typing.Any]:
        """
        Returns the AbstractValue for the given value name.
        
        :param java.lang.String or str name: the name for which to get the AbstractValue
        :return: the AbstractValue for the given value name.
        :rtype: AbstractValue[typing.Any]
        """

    def getBoolean(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Gets the boolean value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined boolean value
        :return: the boolean value
        :rtype: bool
        :raises IllegalArgumentException: if the name hasn't been defined as a boolean type
        """

    def getChoice(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the Choice (String) value for the given name. The value will be either null or one of
        the strings that were defined as valid choices.
        
        :param java.lang.String or str name: the name of a previously defined Choice value
        :return: the Choice value
        :rtype: str
        :raises IllegalArgumentException: if the name hasn't been defined as a Choice type
        """

    def getDouble(self, name: typing.Union[java.lang.String, str]) -> float:
        """
        Gets the double value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined double value
        :return: the double value
        :rtype: float
        :raises IllegalArgumentException: if the name hasn't been defined as a double type
        """

    def getFile(self, name: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Gets the :obj:`File` value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined File value
        :return: the File value
        :rtype: java.io.File
        :raises IllegalArgumentException: if the name hasn't been defined as a File type
        """

    def getInt(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Gets the int value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined int value
        :return: the int value
        :rtype: int
        :raises IllegalArgumentException: if the name hasn't been defined as a int type
        """

    def getLong(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Gets the long value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined long value
        :return: the long value
        :rtype: int
        :raises IllegalArgumentException: if the name hasn't been defined as a long type
        """

    def getString(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the String value for the given name.
        
        :param java.lang.String or str name: the name of a previously defined String value
        :return: the String value
        :rtype: str
        :raises IllegalArgumentException: if the name hasn't been defined as a String type
        """

    def getValues(self) -> java.util.Collection[AbstractValue[typing.Any]]:
        """
        Returns a collection of the AbstractValues defined in this ValuesMap.
        
        :return: a collection of the AbstractValues defined in this ValuesMap.
        :rtype: java.util.Collection[AbstractValue[typing.Any]]
        """

    def hasValue(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the value defined for the given name has a non-null value.
        
        :param java.lang.String or str name: the name of the value
        :return: true if the value defined for the given name has a non-null value.
        :rtype: bool
        """

    def isDefined(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if there is a defined value for the given name.
        
        :param java.lang.String or str name: the name of the value to check for
        :return: true if there is a defined value for the given name.
        :rtype: bool
        """

    def isValid(self, listener: ghidra.util.StatusListener) -> bool:
        """
        The call to validate the data using the :obj:`ValuesMapValidator` set in the
        :meth:`setValidator(ValuesMapValidator) <.setValidator>` method. If no validator has been set,
        this method will return true.
        
        :param ghidra.util.StatusListener listener: The :obj:`StatusListener` for reporting an error message.
        :return: true if the validator passes or no validator has been set.
        :rtype: bool
        """

    def setBoolean(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the boolean value for the given name.
        
        :param java.lang.String or str name: the name of the boolean value that was previously defined
        :param jpype.JBoolean or bool value: the boolean to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a boolean type
        """

    def setChoice(self, name: typing.Union[java.lang.String, str], choice: typing.Union[java.lang.String, str]):
        """
        Sets the Choice (String) value for the given name.
        
        :param java.lang.String or str name: the name of the Choice value that was previously defined
        :param java.lang.String or str choice: the string to set as the value. This String must be one of the defined choices
        :raises IllegalArgumentException: if the name hasn't been defined as a choice type
        """

    def setDouble(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JDouble, float]):
        """
        Sets the double value for the given name.
        
        :param java.lang.String or str name: the name of the double value that was previously defined
        :param jpype.JDouble or float value: the double to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a double type
        """

    def setFile(self, name: typing.Union[java.lang.String, str], value: jpype.protocol.SupportsPath):
        """
        Sets the :obj:`File` value for the given name.
        
        :param java.lang.String or str name: the name of the File value that was previously defined
        :param jpype.protocol.SupportsPath value: the File to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a File type
        """

    def setInt(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Sets the int value for the given name.
        
        :param java.lang.String or str name: the name of the int value that was previously defined
        :param jpype.JInt or int value: the int to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a int type
        """

    def setLong(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Sets the long value for the given name.
        
        :param java.lang.String or str name: the name of the long value that was previously defined
        :param jpype.JLong or int value: the long to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a long type
        """

    def setString(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Sets the String value for the given name.
        
        :param java.lang.String or str name: the name of the String value that was previously defined
        :param java.lang.String or str value: the String to set as the value
        :raises IllegalArgumentException: if the name hasn't been defined as a String type
        """

    def setValidator(self, validator: ValuesMapValidator):
        """
        Sets a :obj:`ValuesMapValidator`. If set, this will be called when the user presses the 
        "Ok" button on the :obj:`ValuesMapDialog`. If the validator passes (returns true), then 
        the dialog will close and return the user values. Otherwise, the dialog will display the
        error message (via the :obj:`StatusListener` in the 
        :meth:`ValuesMapValidator.validate(GValuesMap, StatusListener) <ValuesMapValidator.validate>` call) and remain open.
        
        :param ValuesMapValidator validator: the validator to be called before returning from the dialog
        """

    def updateFromComponents(self):
        """
        Updates each value in this ValuesMap from its corresponding JComponent.
        
        :raises ValuesMapParseException: if any value encountered an error trying to update its
        value from the editor component.
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def boolean(self) -> jpype.JBoolean:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def abstractValue(self) -> AbstractValue[typing.Any]:
        ...

    @property
    def double(self) -> jpype.JDouble:
        ...

    @property
    def values(self) -> java.util.Collection[AbstractValue[typing.Any]]:
        ...

    @property
    def choice(self) -> java.lang.String:
        ...

    @property
    def defined(self) -> jpype.JBoolean:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...


class AbstractValue(java.lang.Object, typing.Generic[T]):
    """
    Abstract base class for defined name/values in a :obj:`GValuesMap` and whose values can be
    edited in the :obj:`ValuesMapDialog`. Its main purpose is to provide a JComponent for
    editing the value. Generally, objects of this type can be in one of two states: having a value
    or not. This can be useful for validating the dialog input values to ensure the user enters
    a value.
     
    
    There are two situations where parse/conversion exceptions can occur in subclass implementations.
    One is the :meth:`setAsText(String) <.setAsText>` method. The subclass should catch any specific  expected 
    exception when parsing the string and convert it to an IllegalArgumentException. The other method
    is the :meth:`updateValueFromComponent() <.updateValueFromComponent>` method which may also need to parse string data. In 
    this case any expected exception should be converted to :obj:`ValuesMapParseException`. This 
    is the only exception type the dialog will be trapping and displaying error messages for in the 
    :obj:`ValuesMapDialog`. Any other type of exception will be considered unexpected and a
    programing error and will be eventally be handled by the default application error handler.
    """

    class_: typing.ClassVar[java.lang.Class]

    def copyValue(self, other: AbstractValue[T]):
        """
        Copies the T value from the given AbstractValue to this AbstractValue.
        
        :param AbstractValue[T] other: the AbstractValue to copy from
        """

    def getAsText(self) -> str:
        """
        Returns a string representation for the value. It is expected that the string returned
        from this method can be parsed by the corresponding :meth:`setAsText(String) <.setAsText>` method. If the
        value of this object is null, null will be returned.
        
        :return: a string representation for the value or null if the value is null
        :rtype: str
        """

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns a JComponent for entering or editing a value of this type.
        
        :return: a JComponent for entering or editing a value of this type.
        :rtype: javax.swing.JComponent
        """

    def getName(self) -> str:
        """
        Returns the name of this value object.
        
        :return: the name of this value object
        :rtype: str
        """

    def getValue(self) -> T:
        """
        Returns the value currently assigned to this object.
        
        :return: the value currently assigned to this object (may be null)
        :rtype: T
        """

    def hasValue(self) -> bool:
        """
        Returns true if the value is non-null.
        
        :return: true if the value is non-null
        :rtype: bool
        """

    def setAsText(self, valueString: typing.Union[java.lang.String, str]) -> T:
        """
        Sets the value for this object from the given string. If this object can not succesfully
        parse the string, an exception will be thrown.
        
        :param java.lang.String or str valueString: the string to be parsed into the type for this object
        :return: The value resulting from parsing the string value
        :rtype: T
        :raises IllegalArgumentException: if the string can not be parsed into a value of type T
        """

    def setValue(self, value: T):
        """
        Sets the value for this object.
        
        :param T value: the value to set for this object (may be null)
        """

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def value(self) -> T:
        ...

    @value.setter
    def value(self, value: T):
        ...

    @property
    def asText(self) -> java.lang.String:
        ...


class DoubleValue(AbstractValue[java.lang.Double]):
    """
    Value class for :obj:`Double` types. This value uses a :obj:`FloatingPointTextField` as it's
    editor component. It supports the concept of no value, if the text field is empty.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.Double, float]):
        ...


class BooleanValue(AbstractValue[java.lang.Boolean]):
    """
    Value class for :obj:`Boolean` types. Boolean types use a :obj:`JCheckBox` for displaying and
    modifying values. Because the checkBox is always either checked or unchecked, 
    BooleanValues don't support the concept of having no value.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    class_: typing.ClassVar[java.lang.Class]


class ValuesMapValidator(java.lang.Object):
    """
    Interface for validating values in a :obj:`GValuesMap`
    """

    class_: typing.ClassVar[java.lang.Class]

    def validate(self, values: GValuesMap, statusListener: ghidra.util.StatusListener) -> bool:
        """
        Validates one or more values in the given ValuesMap. This is used by the ValuesMapDialog
        to validate values when the user presses the "Ok" button. If it returns true, the dialog
        will close. Otherwise, the dialog will remain visible, displaying the error message that
        was reported to the given StatusListener.
        
        :param GValuesMap values: the ValuesMap whose values are to be validated
        :param ghidra.util.StatusListener statusListener: a :obj:`StatusListener` to report validation errors back to
        the dialog
        :return: true if the values pass the validation check.
        :rtype: bool
        """


class FileValue(AbstractValue[java.io.File]):
    """
    Value class for :obj:`File` types. FileValues can be used for either file or directory values,
    depending on the constructor options. The editor component uses a :obj:`JTextField` with
    a browse button for bringing up a :obj:`GhidraFileChooser` for picking files or directories.
     
    
    This class and other subclasses of :obj:`AbstractValue` are part of a subsystem for easily
    defining a set of values that can be displayed in an input dialog (:obj:`ValuesMapDialog`).
    Typically, these values are created indirectly using a :obj:`GValuesMap` which is then
    given to the constructor of the dialog. However, an alternate approach is to create the
    dialog without a ValuesMap and then use its :meth:`ValuesMapDialog.addValue(AbstractValue) <ValuesMapDialog.addValue>` 
    method directly.
    """

    @typing.type_check_only
    class FileValuePanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...

        def getFile(self) -> java.io.File:
            ...

        def setValue(self, value: jpype.protocol.SupportsPath):
            ...

        @property
        def file(self) -> java.io.File:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs a FileValue that expects its value to represent a file and not a directory.
        
        :param java.lang.String or str name: the name of the value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath):
        """
        Constructs a FileValue that expects its value to represent a file and not a directory.
        
        :param java.lang.String or str name: the name of the value
        :param jpype.protocol.SupportsPath defaultValue: the optional default File value.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath, startingDir: jpype.protocol.SupportsPath, mode: docking.widgets.filechooser.GhidraFileChooserMode):
        """
        Constructs a FileValue that could represent either a File or Directory, depending on the
        mode value.
        
        :param java.lang.String or str name: the name of the value
        :param jpype.protocol.SupportsPath defaultValue: the optional default File value. If non-null this can be either a
        file or directory, but it should match the given :obj:`GhidraFileChooserMode`
        :param jpype.protocol.SupportsPath startingDir: an optional directory specifying where the FileChooser should intialize
        its starting selected directory.
        :param docking.widgets.filechooser.GhidraFileChooserMode mode: the :obj:`GhidraFileChooserMode` used to indicate if this File represents a
        file or directory. It will put the GhidraFileChooser in a mode for choosing files or
        directories.
        """



__all__ = ["StringValue", "IntValue", "LongValue", "ChoiceValue", "ValuesMapParseException", "ValuesMapDialog", "GValuesMap", "AbstractValue", "DoubleValue", "BooleanValue", "ValuesMapValidator", "FileValue"]
