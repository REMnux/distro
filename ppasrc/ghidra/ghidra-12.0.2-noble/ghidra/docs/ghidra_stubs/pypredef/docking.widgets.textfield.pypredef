from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.text # type: ignore
import java.time # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import java.util.regex # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore


class DecimalFormatterFactory(javax.swing.JFormattedTextField.AbstractFormatterFactory):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, formatPattern: typing.Union[java.lang.String, str]):
        ...

    def getDecimalFormat(self) -> java.text.DecimalFormat:
        ...

    @property
    def decimalFormat(self) -> java.text.DecimalFormat:
        ...


class GFormattedTextField(javax.swing.JFormattedTextField):
    """
    :obj:`GFormattedTextField` provides an implementation of :obj:`JFormattedTextField` 
    which facilitates entry validation with an indication of its current status.
     
    
    When modified from its default value the field background will reflect its 
    current status.
    """

    class Status(java.lang.Enum[GFormattedTextField.Status]):

        class_: typing.ClassVar[java.lang.Class]
        UNCHANGED: typing.Final[GFormattedTextField.Status]
        CHANGED: typing.Final[GFormattedTextField.Status]
        INVALID: typing.Final[GFormattedTextField.Status]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GFormattedTextField.Status:
            ...

        @staticmethod
        def values() -> jpype.JArray[GFormattedTextField.Status]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: javax.swing.JFormattedTextField.AbstractFormatterFactory, defaultValue: java.lang.Object):
        ...

    def addTextEntryStatusListener(self, listener: TextEntryStatusListener):
        ...

    def disableFocusEventProcessing(self):
        ...

    def editingFinished(self):
        ...

    def getDefaultText(self) -> str:
        """
        Returns the default text.  This is useful to know what the original text is after the user
        has edited the text.
        
        :return: the default text
        :rtype: str
        """

    def getTextEntryStatus(self) -> GFormattedTextField.Status:
        ...

    def isChanged(self) -> bool:
        """
        Returns true if the contents of this field do not match the default.
        
        :return: true if the contents of this field do not match the default.
        :rtype: bool
        """

    def isInvalid(self) -> bool:
        """
        Returns true if the contents of this field are invalid, as determined by the InputValidator.
        
        :return: true if the contents of this field are invalid, as determined by the InputValidator.
        :rtype: bool
        """

    def reset(self):
        """
        Restores this field to its default text.
        """

    def setDefaultValue(self, defaultValue: java.lang.Object):
        """
        Establish default value.  Text field value should be set before invoking this method.
        
        :param java.lang.Object defaultValue: default value
        """

    def setIsError(self, isError: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def textEntryStatus(self) -> GFormattedTextField.Status:
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def defaultText(self) -> java.lang.String:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...


class GValidatedTextField(javax.swing.JTextField):

    class ValidatedDocument(javax.swing.text.PlainDocument):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, validators: java.util.List[GValidatedTextField.TextValidator]):
            ...

        @typing.overload
        def __init__(self):
            ...

        def addValidationMessageListener(self, listener: GValidatedTextField.ValidationMessageListener):
            ...

        def addValidator(self, validator: GValidatedTextField.TextValidator):
            ...

        def removeValidationMessageListener(self, listener: GValidatedTextField.ValidationMessageListener):
            ...

        def removeValidator(self, validator: GValidatedTextField.TextValidator):
            ...


    class TextValidator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def validate(self, oldText: typing.Union[java.lang.String, str], newText: typing.Union[java.lang.String, str]):
            ...


    class ValidationMessageListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def message(self, msg: typing.Union[java.lang.String, str]):
            ...


    class ValidationFailedException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, msg: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self, cause: java.lang.Throwable):
            ...

        @typing.overload
        def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
            ...


    class LongField(GValidatedTextField):

        class LongValidator(GValidatedTextField.TextValidator):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...

            def validateLong(self, oldLong: typing.Union[jpype.JLong, int], newLong: typing.Union[jpype.JLong, int]):
                ...


        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, validators: java.util.List[GValidatedTextField.TextValidator], value: typing.Union[java.lang.String, str], columns: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, value: typing.Union[java.lang.String, str], columns: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, value: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self, columns: typing.Union[jpype.JInt, int]):
            ...

        def getValue(self) -> int:
            ...

        @property
        def value(self) -> jpype.JLong:
            ...


    class MaxLengthField(GValidatedTextField):

        @typing.type_check_only
        class MaxLengthDocument(GValidatedTextField.ValidatedDocument):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, validators: java.util.List[GValidatedTextField.TextValidator]):
                ...


        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, validators: java.util.List[GValidatedTextField.TextValidator], value: typing.Union[java.lang.String, str], columns: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, value: typing.Union[java.lang.String, str], columns: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, columns: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, validators: java.util.List[GValidatedTextField.TextValidator], value: typing.Union[java.lang.String, str], columns: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, value: typing.Union[java.lang.String, str], columns: typing.Union[jpype.JInt, int]):
        ...

    def addValidationMessageListener(self, listener: GValidatedTextField.ValidationMessageListener):
        ...

    def addValidator(self, validator: GValidatedTextField.TextValidator):
        ...

    def removeValidationMessageListener(self, listener: GValidatedTextField.ValidationMessageListener):
        ...

    def removeValidator(self, validator: GValidatedTextField.TextValidator):
        ...


class HintTextField(javax.swing.JTextField):
    """
    Simple text field that shows a text hint when the field is empty.
    
     
    Hint text will be shown in light grey. Normal text will be plain black.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, hint: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str hint: the hint text
        """

    @typing.overload
    def __init__(self, hint: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param java.lang.String or str hint: the hint text
        :param jpype.JBoolean or bool required: true if the field should be marked as required
        """

    @typing.overload
    def __init__(self, hint: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool], verifier: javax.swing.InputVerifier):
        """
        Constructor
        
        :param java.lang.String or str hint: the hint text
        :param jpype.JBoolean or bool required: true, if the field should be marked as required
        :param javax.swing.InputVerifier verifier: input verifier, or null if none needed
        """

    def addListeners(self):
        """
        Key listener allows us to check field validity on every key typed
        """

    def isFieldValid(self) -> bool:
        """
        Returns true if the field contains valid input.
        
        :return: true if valid, false otherwise
        :rtype: bool
        """

    def paintComponent(self, g: java.awt.Graphics):
        """
        Overridden to paint the hint text over the field when it's empty
        """

    def setDefaultBackgroundColor(self, color: java.awt.Color):
        """
        Allows users to override the background color used by this field when the contents are
        valid.  The invalid color is currently set by this class.
        
        :param java.awt.Color color: the color
        """

    def setHint(self, hint: typing.Union[java.lang.String, str]):
        """
        Sets the hint for this text field
        
        :param java.lang.String or str hint: the hint text
        """

    def setRequired(self, required: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the field is required or not. If so, it will be rendered
        differently to indicate that to the user.
        
        :param jpype.JBoolean or bool required: true if required, false otherwise
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Overridden to check the field validity when text changes
        
        :param java.lang.String or str text: the text to fill
        """

    @property
    def fieldValid(self) -> jpype.JBoolean:
        ...


class HexDecimalModeTextField(javax.swing.JTextField):
    """
    Overrides the JTextField mainly to allow hint painting for the current radix mode.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], modeConsumer: java.util.function.Consumer[java.lang.Boolean]):
        ...

    def setHexMode(self, hexMode: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowNumberMode(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Turns on or off the faded text that displays the field's radix mode (hex or decimal).
        
        :param jpype.JBoolean or bool show: true to show the radix mode.
        """


class TextEntryStatusListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def statusChanged(self, textField: GFormattedTextField):
        ...


class HexOrDecimalInput(javax.swing.JTextField):

    @typing.type_check_only
    class MyDocument(javax.swing.text.PlainDocument):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, columns: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, initialValue: typing.Union[java.lang.Long, int]):
        ...

    def getIntValue(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    def setAllowNegative(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setDecimalMode(self):
        ...

    def setHexMode(self):
        ...

    @typing.overload
    def setValue(self, newValue: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def setValue(self, newValue: typing.Union[java.lang.Long, int]):
        ...

    @property
    def intValue(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @value.setter
    def value(self, value: jpype.JLong):
        ...


class TextFieldLinker(java.lang.Object):
    """
    A class that links text fields into a "formatted text field", separated by expressions.
     
     
    
    This fulfills a similar purpose to formatted text fields, except the individual parts may be
    placed independent of the other components. Granted, they ought to appear in an intuitive order.
    The input string is split among a collection of :obj:`JTextField`s each according to a given
    pattern -- excluding the final field. Cursor navigation, insertion, deletion, etc. are all
    applied as if the linked text fields were part of a single composite text field.
     
     
    
    The individual text fields must be constructed and added by the user, as in the example:
     
     
    Box hbox = Box.createHorizontalBox();
    TextFieldLinker linker = new TextFieldLinker();
     
    JTextField first = new JTextField();
    hbox.add(first);
    hbox.add(Box.createHorizontalStrut(10));
    linker.linkField(first, "\\s+", " ");
     
    JTextField second = new JTextField();
    hbox.add(second);
    hbox.add(new GLabel("-"));
    linker.linkField(second, "-", "-");
     
    JTextField third = new JTextField();
    hbox.add(third);
    linker.linkLastField(third);
     
    linker.setVisible(true);
    """

    @typing.type_check_only
    class LinkedField(java.lang.Object):
        """
        A field that has been added with its corresponding separator expression and replacement
        """

        class_: typing.ClassVar[java.lang.Class]

        def unregisterListener(self):
            ...


    @typing.type_check_only
    class FieldState(java.lang.Object):
        """
        The current state of a linked field, stored separately from the actual component
        """

        class_: typing.ClassVar[java.lang.Class]

        def clampedCaret(self) -> int:
            ...


    @typing.type_check_only
    class LinkerState(java.lang.Object):
        """
        A class to track the internal state gathered from the text fields
        """

        class_: typing.ClassVar[java.lang.Class]

        def copy(self) -> TextFieldLinker.LinkerState:
            """
            Copy the state
            
            :return: the copy
            :rtype: TextFieldLinker.LinkerState
            """

        @typing.overload
        def getGlobalCaret(self) -> int:
            """
            Get the composite caret location
            
            :return: the location (including separators)
            :rtype: int
            """

        @typing.overload
        def getGlobalCaret(self, omitSep: typing.Union[jpype.JInt, int]) -> int:
            """
            Get the composite caret location, omitting the given separator.
            
            :param jpype.JInt or int omitSep: the separator to omit, or -1 to omit nothing
            :return: the location
            :rtype: int
            """

        @typing.overload
        def getText(self) -> str:
            """
            Get the whole composite string
            
            :return: the text
            :rtype: str
            """

        @typing.overload
        def getText(self, omitSep: typing.Union[jpype.JInt, int]) -> str:
            """
            Get the composite string, omitting the given separator.
             
             
            
            This is used as a helper to delete the separator when backspace/delete is pressed at a
            boundary.
            
            :param jpype.JInt or int omitSep: the separator to omit, or -1 to omit nothing
            :return: the text
            :rtype: str
            """

        def getTextBeforeCursor(self, field: typing.Union[jpype.JInt, int]) -> str:
            """
            Get the composite text preceding the caret in the given field
            
            :param jpype.JInt or int field: the field whose caret to use
            :return: the text
            :rtype: str
            """

        def isAfterSep(self, field: typing.Union[jpype.JInt, int]) -> bool:
            """
            Figure out whether the caret in the given field immediately proceeds a separator.
             
             
            
            In other words, the caret must be to the far left (position 0), and the given field must
            not be the first field. If true, the caret immediately follows separator index
            ``field - 1``.
            
            :param jpype.JInt or int field: the field index to check
            :return: true if the caret immediately follows a separator.
            :rtype: bool
            """

        def isBeforeSep(self, field: typing.Union[jpype.JInt, int]) -> bool:
            """
            Figure out whether the caret in the given field immediately precedes a separator.
             
             
            
            In other words, the caret must be to the far right, and the given field must not be the
            last field. If true, the caret immediately precedes separator index ``field``.
            
            :param jpype.JInt or int field: the field index to check
            :return: true if the caret immediately precedes a separator.
            :rtype: bool
            """

        def navigateFieldLeft(self, field: typing.Union[jpype.JInt, int]):
            """
            Change focus to the given field as if navigating left.
             
             
            
            The caret will be moved to the rightmost position, because we're moving left from the
            leftmost position of the field to the right.
            
            :param jpype.JInt or int field: the field index to be given focus.
            """

        def navigateFieldRight(self, field: typing.Union[jpype.JInt, int]):
            """
            Change focus to the given field as if navigating right.
             
             
            
            The caret will be moved to the leftmost position, because we're moving right from the
            rightmost position of the field to the left.
            
            :param jpype.JInt or int field: the field index to be given focus.
            """

        def reformat(self):
            """
            Re-parse the composite string and place the components into their proper fields
            """

        def reset(self):
            """
            Erase the state
             
             
            
            Blank all the fields, and put the caret at the front of the first field.
            """

        def setGlobalCaret(self, caret: typing.Union[jpype.JInt, int]):
            """
            Set the composite caret location
            
            :param jpype.JInt or int caret: the new caret location
            :raises BadLocationException: if the location exceeds the text length
            """

        def setText(self, text: typing.Union[java.lang.String, str]) -> int:
            """
            Set the composite text
            
            :param java.lang.String or str text: the new text
            """

        @property
        def globalCaret(self) -> jpype.JInt:
            ...

        @globalCaret.setter
        def globalCaret(self, value: jpype.JInt):
            ...

        @property
        def afterSep(self) -> jpype.JBoolean:
            ...

        @property
        def textBeforeCursor(self) -> java.lang.String:
            ...

        @property
        def beforeSep(self) -> jpype.JBoolean:
            ...

        @property
        def text(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class DualFieldListener(java.awt.event.KeyAdapter, javax.swing.event.CaretListener, java.awt.event.FocusListener, javax.swing.event.DocumentListener):
        """
        A listener for all my callbacks
         
         
        
        A separate listener is constructed and installed on each field so that we have a reference to
        the field in every callback.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, linked: TextFieldLinker.LinkedField):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addFocusListener(self, listener: java.awt.event.FocusListener):
        """
        Add a focus listener
         
         
        
        The focus listener will receive a callback only when focus is passed completely outside the
        composite text field. No events are generated when focus passes from one field in the
        composite to another.
        
        :param java.awt.event.FocusListener listener: the focus listener to add
        """

    def clear(self):
        """
        Clear the composite field, i.e., clear all the linked fields
        """

    def getField(self, i: typing.Union[jpype.JInt, int]) -> javax.swing.JTextField:
        """
        Get an individual field in the composite
        
        :param jpype.JInt or int i: the index of the field
        :return: the field
        :rtype: javax.swing.JTextField
        """

    def getFocusedField(self) -> javax.swing.JTextField:
        """
        Get the individual field last having focus
         
         
        
        Effectively, this gives the field containing the composite caret
        
        :return: the last-focused field
        :rtype: javax.swing.JTextField
        """

    def getNumFields(self) -> int:
        """
        Get the number of fields in this composite
        
        :return: the field count
        :rtype: int
        """

    def getText(self) -> str:
        """
        Get the full composite text
        
        :return: the text, including separators
        :rtype: str
        """

    def getTextBeforeCursor(self, where: javax.swing.JTextField) -> str:
        """
        Get the text preceding the caret in the given field
        
        :param javax.swing.JTextField where: the field whose caret to consider
        :return: the text
        :rtype: str
        """

    def isVisible(self) -> bool:
        """
        Check if all component fields are visible
        
        :return: false if any component is not visible, true otherwise
        :rtype: bool
        """

    @typing.overload
    def linkField(self, field: javax.swing.JTextField, exp: typing.Union[java.lang.String, str], sep: typing.Union[java.lang.String, str]):
        """
        
        
        
        .. seealso::
        
            | :obj:`.linkField(JTextField, Pattern, String)`
        """

    @typing.overload
    def linkField(self, field: javax.swing.JTextField, pat: java.util.regex.Pattern, sep: typing.Union[java.lang.String, str]):
        """
        Add a new text field to this linker
         
         
        
        Links the given field with the others present in this linker, if any. ``pat`` is a
        regular expression that dictates where the given field ends, and the next field begins. When
        ``pat`` matches a part of the text in ``field``, the text is split and re-flowed so
        that the second part is moved into the next linked field. The separator is omitted from both
        fields. The fields should be positioned in order with labels between that display the
        expected separators, so that the user may understand what is happening. The
        :meth:`getText() <.getText>` and :meth:`getTextBeforeCursor(JTextField) <.getTextBeforeCursor>` methods will include
        ``sep`` between the fields.
         
         
        
        Any number of fields may be added in this fashion, but the last field -- having no associated
        pattern or separator -- must be added using :meth:`linkLastField(JTextField) <.linkLastField>`. Thus, before
        linking is actually activated, at least one field must be present. To be meaningful, at least
        two fields should be linked.
         
         
        
        **NOTE:** ``pat`` must accept ``sep``, otherwise calling :meth:`setText(String) <.setText>`
        with the results of :meth:`getText() <.getText>` will have unexpected effects.
        
        :param javax.swing.JTextField field: the field to link
        :param java.util.regex.Pattern pat: the regular expression to search for following the field
        :param java.lang.String or str sep: the separator that replaces ``pat`` when matched
        """

    def linkLastField(self, field: javax.swing.JTextField):
        """
        Add the final field, and actually link the fields
         
         
        
        The fields are not effectively linked until this method is called. Additionally, once this
        method is called, the linker cannot take any additional fields.
        
        :param javax.swing.JTextField field: the final field
        """

    def removeFocusListener(self, listener: java.awt.event.FocusListener):
        """
        Remove a focus listener
        
        :param java.awt.event.FocusListener listener: the focus listener to remove
        """

    def setCaretPosition(self, pos: typing.Union[jpype.JInt, int]):
        """
        Set the location of the caret among the composite text
        
        :param jpype.JInt or int pos: the position, including separators
        :raises BadLocationException: if the position is larger than the composite text
        """

    def setFont(self, font: java.awt.Font):
        """
        Set the font for all linked fields
        
        :param java.awt.Font font: the new font
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Set the full composite text
        
        :param java.lang.String or str text: the text, including separators
        """

    def setVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Set the visibility of all the component fields
        
        :param jpype.JBoolean or bool visible: true to show, false to hide
        """

    @staticmethod
    def twoSpacedFields() -> TextFieldLinker:
        """
        A convenient factory to build two fields separated by spaces
        
        :return: the linker containing two new linked :obj:`JTextField`s
        :rtype: TextFieldLinker
        """

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @visible.setter
    def visible(self, value: jpype.JBoolean):
        ...

    @property
    def field(self) -> javax.swing.JTextField:
        ...

    @property
    def focusedField(self) -> javax.swing.JTextField:
        ...

    @property
    def textBeforeCursor(self) -> java.lang.String:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...


class LocalDateTextField(java.lang.Object):
    """
    Text field for entering dates. Optionally, a minimum and maximum date value can be set on this
    text field.
    """

    @typing.type_check_only
    class MyTextField(javax.swing.JTextField):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dateFormatPattern: typing.Union[java.lang.String, str]):
        ...

    def addActionListener(self, listener: java.awt.event.ActionListener):
        ...

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a change listener that will be notified whenever the value changes.
        
        :param javax.swing.event.ChangeListener listener: the change listener to add.
        """

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def getMaximum(self) -> java.time.LocalDate:
        ...

    def getMinimum(self) -> java.time.LocalDate:
        ...

    def getTextField(self) -> javax.swing.JTextField:
        ...

    def getValue(self) -> java.time.LocalDate:
        ...

    def isShowingFieldMode(self) -> bool:
        ...

    def removeActionListener(self, listener: java.awt.event.ActionListener):
        ...

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes the changes listener.
        
        :param javax.swing.event.ChangeListener listener: the listener to be removed.
        """

    def requestFocus(self):
        ...

    def selectAll(self):
        ...

    def setDayMode(self):
        """
        Sets the mode to Day.
        """

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMaximum(self, maximum: java.time.LocalDate):
        """
        Sets the maximum allowed date. Can be null.
        
        :param java.time.LocalDate maximum: the minimum allowed date.
        """

    def setMinimum(self, minimum: java.time.LocalDate):
        """
        Sets the minimum allowed date. Can be null.
        
        :param java.time.LocalDate minimum: the minimum allowed date.
        """

    def setMonthMode(self):
        """
        Sets the mode to Month.
        """

    def setShowFieldMode(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Turns on or off the faded text that indicates if the field is in month or day mode
        
        :param jpype.JBoolean or bool show: true to show the mode.
        """

    def setValue(self, newDate: java.time.LocalDate):
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def maximum(self) -> java.time.LocalDate:
        ...

    @maximum.setter
    def maximum(self, value: java.time.LocalDate):
        ...

    @property
    def showingFieldMode(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> java.time.LocalDate:
        ...

    @value.setter
    def value(self, value: java.time.LocalDate):
        ...

    @property
    def minimum(self) -> java.time.LocalDate:
        ...

    @minimum.setter
    def minimum(self, value: java.time.LocalDate):
        ...

    @property
    def textField(self) -> javax.swing.JTextField:
        ...


class FloatingPointTextField(javax.swing.JTextField):
    """
    A simple text field for inputting floating point numbers. The field is continuously validated so 
    that only valid characters and values can be entered. If the text is blank or contains only "-",
    ".", or "-.", the value is considered to be 0. You can optionally set a min and max value. In 
    order for the continuous validation to work, the max must be a non-negative number and the min 
    must be a non-positive number.
    """

    @typing.type_check_only
    class FloatingPointDocumentFilter(javax.swing.text.DocumentFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, columns: typing.Union[jpype.JInt, int]):
        """
        Constructs a new empty FloatingPointTextField.
        
        :param jpype.JInt or int columns: the number of columns for determining the preferred width
        """

    @typing.overload
    def __init__(self, columns: typing.Union[jpype.JInt, int], initialValue: typing.Union[jpype.JDouble, float]):
        """
        Constructs a new FloatingPointTextField initialized with the given value.
        
        :param jpype.JInt or int columns: the number of columns for determining the preferred width
        :param jpype.JDouble or float initialValue: the initial value
        """

    def getValue(self) -> float:
        """
        Returns the value represented by the text in the field. If the field only contains "-",".",
        or "-.", the value returned will be 0.
        
        :return: the value represented by the text in the field
        :rtype: float
        """

    def setMaxValue(self, max: typing.Union[jpype.JDouble, float]):
        """
        Sets the maximum allowed value. The max must be 0 or positive so that continuous validation
        can work.
        
        :param jpype.JDouble or float max: the maximum allowed value.
        """

    def setMinValue(self, min: typing.Union[jpype.JDouble, float]):
        """
        Sets the minimum allowed value. The min must be 0 or negative so that continuous validation
        can work.
        
        :param jpype.JDouble or float min: the minimum allowed value.
        """

    def setValue(self, value: typing.Union[jpype.JDouble, float]):
        """
        Sets the text in the field to the given value.
        
        :param jpype.JDouble or float value: the value to display in the text field
        """

    @property
    def value(self) -> jpype.JDouble:
        ...

    @value.setter
    def value(self, value: jpype.JDouble):
        ...


class IntegerTextField(java.lang.Object):
    """
    TextField for entering integer numbers, either in decimal or hex.
    
     
    
    This field does continuous checking, so you can't enter a bad value.
    
     
    
    Internally, values are maintained using BigIntegers so this field can contain numbers as large as
    desired. There are convenience methods for getting the value as either an int or long. If using
    these convenience methods, you should also set the max allowed value so that users can't enter a
    value larger than can be represented by the :meth:`getIntValue() <.getIntValue>` or :meth:`getLongValue() <.getLongValue>`
    methods as appropriate.
    
     
    
    There are several configuration options as follows:
     
    * Allows negative numbers - either support all integer numbers or just non-negative numbers.
    See:meth:`setAllowNegativeValues(boolean) <.setAllowNegativeValues>`
    * Allows hex prefix - If this mode is on, then hex mode is turned on and off automatically
    depending whether or not the text starts with 0x. Otherwise, the hex/decimal mode is set
    externally (either programmatically or pressing<CTRL> M) and the user is restricted to the
    numbers/letters appropriate for that mode. See:meth:`setAllowsHexPrefix(boolean) <.setAllowsHexPrefix>`
    * Have a max value - a max value can be set (must be positive) such that the user can not type
    a number whose absolute value is greater than the max. Otherwise, the value is unlimited if max
    is null/unspecified. See:meth:`setMaxValue(BigInteger) <.setMaxValue>`
    * Show the number mode as hint text - If on either "Hex" or "Dec" is displayed lightly in the
    bottom right portion of the text field. See:meth:`setShowNumberMode(boolean) <.setShowNumberMode>`
    """

    @typing.type_check_only
    class HexDecimalDocumentFilter(javax.swing.text.DocumentFilter):
        """
        DocumentFilter that prevents users from entering invalid data into the field.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new IntegerTextField with 5 columns and no initial value
        """

    @typing.overload
    def __init__(self, columns: typing.Union[jpype.JInt, int]):
        """
        Creates a new IntegerTextField with the specified number of columns and no initial value
        
        :param jpype.JInt or int columns: the number of columns.
        """

    @typing.overload
    def __init__(self, columns: typing.Union[jpype.JInt, int], initialValue: typing.Union[jpype.JLong, int]):
        """
        Creates a new IntegerTextField with the specified number of columns and an initial value
        
        :param jpype.JInt or int columns: the number of columns to display in the JTextField.
        :param jpype.JLong or int initialValue: the initial value. This constructor takes an initialValue as a long. If
                    you need a value that is bigger (or smaller) than can be specified as a long, then
                    use the constructor that takes a BigInteger as an initial value.
        """

    @typing.overload
    def __init__(self, columns: typing.Union[jpype.JInt, int], initialValue: java.math.BigInteger):
        """
        Creates a new IntegerTextField with the specified number of columns and initial value
        
        :param jpype.JInt or int columns: the number of columns
        :param java.math.BigInteger initialValue: the initial value
        """

    def addActionListener(self, listener: java.awt.event.ActionListener):
        """
        Adds an ActionListener to the TextField.
        
        :param java.awt.event.ActionListener listener: the ActionListener to add.
        """

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a change listener that will be notified whenever the value changes.
        
        :param javax.swing.event.ChangeListener listener: the change listener to add.
        """

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the JTextField component that this class manages.
        
        :return: the JTextField component that this class manages.
        :rtype: javax.swing.JComponent
        """

    def getIntValue(self) -> int:
        """
        Returns the current value as an int.
        
         
        
        If the field has no current value, 0 will be returned. If the value is bigger (or smaller)
        than an int, it will be cast to an int.
        
         
        
        If using this method, it is highly recommended that you set the max value to
        :obj:`Integer.MAX_VALUE` or lower.
        
        :return: the current value as an int. Or 0 if there is no value
        :rtype: int
        :raises ArithmeticException: if the value in this field will not fit into an int
        """

    def getLongValue(self) -> int:
        """
        Returns the current value as a long.
        
         
        
        If the field has no current value, 0 will be returned. If the value is bigger (or smaller)
        than an long, it will be cast to a long.
        
         
        
        If using this method, it is highly recommended that you set the max value to
        :obj:`Long.MAX_VALUE` or lower.
        
        :return: the current value as a long. Or 0 if there is no value
        :rtype: int
        :raises ArithmeticException: if the value in this field will not fit into a long
        """

    def getMaxValue(self) -> java.math.BigInteger:
        """
        Returns the current maximum allowed value. Null indicates that there is no maximum value. If
        negative values are permitted (see :meth:`setAllowNegativeValues(boolean) <.setAllowNegativeValues>`) this value will
        establish the upper and lower limit of the absolute value.
        
        :return: the current maximum value allowed.
        :rtype: java.math.BigInteger
        """

    def getText(self) -> str:
        """
        Returns the current text displayed in the field.
        
        :return: the current text displayed in the field.
        :rtype: str
        """

    def getValue(self) -> java.math.BigInteger:
        """
        Returns the current value of the field or null if the field has no current value.
        
        :return: the current value of the field or null if the field has no current value.
        :rtype: java.math.BigInteger
        """

    def isHexMode(self) -> bool:
        """
        Returns true if in hex mode, false if in decimal mode.
        
        :return: true if in hex mode, false if in decimal mode.
        :rtype: bool
        """

    def removeActionListener(self, listener: java.awt.event.ActionListener):
        """
        Removes an ActionListener from the TextField.
        
        :param java.awt.event.ActionListener listener: the ActionListener to remove.
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes the changes listener.
        
        :param javax.swing.event.ChangeListener listener: the listener to be removed.
        """

    def requestFocus(self):
        """
        Requests focus to the JTextField
        """

    def selectAll(self):
        """
        Selects the text in the JTextField
        """

    def setAccessibleName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the accessible name for the component of this input field.
        
        :param java.lang.String or str name: the accessible name for this field
        """

    def setAllowNegativeValues(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not negative numbers are accepted.
        
        :param jpype.JBoolean or bool b: if true, negative numbers are allowed.
        """

    def setAllowsHexPrefix(self, allowsHexPrefix: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether on not the field supports the 0x prefix.
        
         
        
        If 0x is supported, hex numbers will be displayed with the 0x prefix. Also, when typing, you
        must type 0x first to enter a hex number, otherwise it will only allow digits 0-9. If the 0x
        prefix option is turned off, then hex numbers are displayed without the 0x prefix and you
        can't change the decimal/hex mode by typing 0x. The field will either be in decimal or hex
        mode and the typed text will be interpreted appropriately for the mode.
        
        :param jpype.JBoolean or bool allowsHexPrefix: true to use the 0x convention for hex.
        """

    def setDecimalMode(self):
        """
        Sets the mode to Decimal.
        
         
        
        If the field is currently in hex mode, the current text will be change from displaying the
        current value from hex to decimal.
        """

    def setEditable(self, editable: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the editable mode for the JTextField component
        
        :param jpype.JBoolean or bool editable: boolean flag, if true component is editable
        """

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the enablement on the JTextField component;
        
        :param jpype.JBoolean or bool enabled: true for enabled, false for disabled.
        """

    def setHexMode(self):
        """
        Sets the radix mode to Hex.
        
         
        
        If the field is currently in decimal mode, the current text will be change from displaying
        the current value from decimal to hex.
        """

    def setHorizontalAlignment(self, alignment: typing.Union[jpype.JInt, int]):
        """
        Sets the horizontal alignment of the JTextField
        
        :param jpype.JInt or int alignment: the alignment as in :meth:`JTextField.setHorizontalAlignment(int) <JTextField.setHorizontalAlignment>`
        """

    def setMaxValue(self, maxValue: java.math.BigInteger):
        """
        Sets the maximum allowed value. The maximum must be a positive number. Null indicates that
        there is no maximum value.
         
        
        If negative values are permitted (see :meth:`setAllowNegativeValues(boolean) <.setAllowNegativeValues>`) this value
        will establish the upper and lower limit of the absolute value.
        
        :param java.math.BigInteger maxValue: the maximum value to allow.
        """

    def setMinValue(self, minValue: java.math.BigInteger):
        """
        Sets the minimum allowed value.  The minimum must be a positive number.  Null indicates that
        there is no minimum value.
         
        
        If negative values are permitted (see :meth:`setAllowNegativeValues(boolean) <.setAllowNegativeValues>`) this value
        will establish the minimum limit of the absolute value.
        
        :param java.math.BigInteger minValue: the minimum value to allow.
        """

    def setShowNumberMode(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Turns on or off the faded text that displays the field's radix mode (hex or decimal).
        
        :param jpype.JBoolean or bool show: true to show the radix mode.
        """

    def setText(self, text: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets the field to the given text. The text must be a properly formated string that is a value
        that is valid for this field. If the field is set to not allow "0x" prefixes, then the input
        string cannot start with 0x and furthermore, if the field is in decimal mode, then input
        string cannot take in hex digits a-f. On the other hand, if "0x" prefixes are allowed, then
        the input string can be either a decimal number or a hex number depending on if the input
        string starts with "0x". In this case, the field's hex mode will be set to match the input
        text. If the text is not valid, the field will not change.
        
        :param java.lang.String or str text: the value as text to set on this field
        :return: true if the set was successful
        :rtype: bool
        """

    @typing.overload
    def setValue(self, newValue: typing.Union[jpype.JLong, int]):
        """
        Convenience method for setting the value to a long value;
        
        :param jpype.JLong or int newValue: the new value for the field.
        """

    @typing.overload
    def setValue(self, newValue: typing.Union[jpype.JInt, int]):
        """
        Convenience method for setting the value to an int value;
        
        :param jpype.JInt or int newValue: the new value for the field.
        """

    @typing.overload
    def setValue(self, newValue: java.math.BigInteger):
        """
        Sets the value of the field to the given value. A null value will clear the field.
        
        :param java.math.BigInteger newValue: the new value or null.
        """

    @property
    def maxValue(self) -> java.math.BigInteger:
        ...

    @maxValue.setter
    def maxValue(self, value: java.math.BigInteger):
        ...

    @property
    def intValue(self) -> jpype.JInt:
        ...

    @property
    def longValue(self) -> jpype.JLong:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...

    @value.setter
    def value(self, value: java.math.BigInteger):
        ...

    @property
    def hexMode(self) -> jpype.JBoolean:
        ...



__all__ = ["DecimalFormatterFactory", "GFormattedTextField", "GValidatedTextField", "HintTextField", "HexDecimalModeTextField", "TextEntryStatusListener", "HexOrDecimalInput", "TextFieldLinker", "LocalDateTextField", "FloatingPointTextField", "IntegerTextField"]
