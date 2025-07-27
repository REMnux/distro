from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import com.google.gson # type: ignore
import ghidra.util
import gui.event
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.text # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import org.jdom # type: ignore


T = typing.TypeVar("T")


class ThemeFontOption(Option):
    """
    Options implementation for theme font options. A ThemeFontOption is an option that, when
    changed, affects the current theme and is saved in the theme, instead of being saved with
    normal non-theme related options.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, optionName: typing.Union[java.lang.String, str], fontId: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], help: ghidra.util.HelpLocation):
        ...


class SubOptions(Options):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, options: AbstractOptions, name: typing.Union[java.lang.String, str], prefix: typing.Union[java.lang.String, str]):
        ...


class ThemeColorOption(Option):
    """
    Options implementation for theme color options. A ThemeColorOption is an option that, when
    changed, affects the current theme and is saved in the theme, instead of being saved with
    normal non-theme related options.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, optionName: typing.Union[java.lang.String, str], colorId: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], help: ghidra.util.HelpLocation):
        ...


class Options(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DELIMITER: typing.Final = '.'
    DELIMITER_STRING: typing.Final[java.lang.String]
    ILLEGAL_DELIMITER: typing.Final[java.lang.String]

    def contains(self, optionName: typing.Union[java.lang.String, str]) -> bool:
        """
        Return true if a option exists with the given name.
        
        :param java.lang.String or str optionName: option name
        :return: true if there exists an option with the given name
        :rtype: bool
        """

    def createAlias(self, aliasName: typing.Union[java.lang.String, str], options: Options, optionsName: typing.Union[java.lang.String, str]):
        """
        Create an alias in this options for an existing option in some other options object.
        
        :param java.lang.String or str aliasName: the name within this options object that will actually refer to some other
        options object.
        :param Options options: the options object that has the actual option.
        :param java.lang.String or str optionsName: the name within the given options object of the actual option.
        """

    def getActionTrigger(self, optionName: typing.Union[java.lang.String, str], defaultValue: ActionTrigger) -> ActionTrigger:
        """
        Get the :obj:`ActionTrigger` for the given full action name.
        
        :param java.lang.String or str optionName: the action name
        :param ActionTrigger defaultValue: value that is stored and returned if there is no
        option with the given name
        :return: the action trigger
        :rtype: ActionTrigger
        """

    def getBoolean(self, optionName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Get the boolean value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.JBoolean or bool defaultValue: value that is stored and returned if there
        is no option with the given name.
        :return: boolean option value
        :rtype: bool
        """

    def getByteArray(self, optionName: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Get the byte array for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.JArray[jpype.JByte] defaultValue: value that is stored and returned if there
        is no option with the given name
        :return: byte[] byte array value
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getChildOptions(self) -> java.util.List[Options]:
        """
        Returns a list of Options objects that are nested one level down from this Options object.
        
        :return: a list of Options objects that are nested one level down from this Options object.
        :rtype: java.util.List[Options]
        """

    def getColor(self, optionName: typing.Union[java.lang.String, str], defaultValue: java.awt.Color) -> java.awt.Color:
        """
        Get the Color for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param java.awt.Color defaultValue: value that is stored and returned if there is no
        option with the given name
        :return: Color option
        :rtype: java.awt.Color
        :raises IllegalArgumentException: is a option exists with the given
        name but it is not a Color
        """

    def getCustomOption(self, optionName: typing.Union[java.lang.String, str], defaultValue: CustomOption) -> CustomOption:
        """
        Get the custom option value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param CustomOption defaultValue: value that is stored and returned if there
        is no option with the given name
        :return: WrappedOption value for the option
        :rtype: CustomOption
        """

    def getDate(self, pName: typing.Union[java.lang.String, str], date: java.util.Date) -> java.util.Date:
        """
        Get the Date for the given option name.
        
        :param java.lang.String or str pName: the property name
        :param java.util.Date date: the default date that is stored and returned if there is no
        option with the given name
        :return: the Date for the option
        :rtype: java.util.Date
        :raises IllegalArgumentException: is a option exists with the given
        name but it is not a Date options
        """

    def getDefaultValue(self, optionName: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Returns the default value for the given option.
        
        :param java.lang.String or str optionName: the name of the option for which to retrieve the default value.
        :return: the default value for the given option.
        :rtype: java.lang.Object
        """

    def getDefaultValueAsString(self, optionName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the default value as a string for the given option.
        
        :param java.lang.String or str optionName: the name of the option for which to retrieve the default value as a string
        :return: the default value as a string for the given option.
        :rtype: str
        """

    def getDescription(self, optionName: typing.Union[java.lang.String, str]) -> str:
        """
        Get the description for the given option name.
        
        :param java.lang.String or str optionName: name of the option
        :return: null if the description or option name does not exist
        :rtype: str
        """

    def getDouble(self, optionName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JDouble, float]) -> float:
        """
        Get the double value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.JDouble or float defaultValue: value that is stored and returned if there
        is no option with the given name
        :return: double value for the option
        :rtype: float
        """

    def getEnum(self, optionName: typing.Union[java.lang.String, str], defaultValue: T) -> T:
        """
        Get the Enum value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param T defaultValue: default value that is stored and returned if there is
        no option with the given name
        :return: Enum value for the option
        :rtype: T
        """

    def getFile(self, optionName: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Get the File for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.protocol.SupportsPath defaultValue: value that is stored and returned if there is no
        option with the given name
        :return: File option
        :rtype: java.io.File
        :raises IllegalArgumentException: is a option exists with the given
        name but it is not a File options
        """

    def getFloat(self, optionName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JFloat, float]) -> float:
        """
        Get the float value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.JFloat or float defaultValue: value that is stored and returned if there
        is no option with the given name
        :return: float value for the option
        :rtype: float
        """

    def getFont(self, optionName: typing.Union[java.lang.String, str], defaultValue: java.awt.Font) -> java.awt.Font:
        """
        Get the Font for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param java.awt.Font defaultValue: value that is stored and returned if there is no
        option with the given name
        :return: Font option
        :rtype: java.awt.Font
        :raises IllegalArgumentException: is a option exists with the given
        name but it is not a Font
        """

    def getHelpLocation(self, optionName: typing.Union[java.lang.String, str]) -> ghidra.util.HelpLocation:
        """
        Get the location for where help can be found for the option with
        the given name.
        
        :param java.lang.String or str optionName: name of the option
        :return: null if the help location was not set on the option
        :rtype: ghidra.util.HelpLocation
        """

    def getID(self, optionName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a unique id for option in this options with the given name.  This will be the full
        path name to the root options object.
        
        :param java.lang.String or str optionName: the name of the option for which to get an ID;
        :return: the unique ID for the given option.
        :rtype: str
        """

    def getInt(self, optionName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the int value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.JInt or int defaultValue: value that is stored and returned if there
        is no option with the given name
        :return: int option value
        :rtype: int
        """

    @deprecated("use getActionTrigger(String, ActionTrigger) instead")
    def getKeyStroke(self, optionName: typing.Union[java.lang.String, str], defaultValue: javax.swing.KeyStroke) -> javax.swing.KeyStroke:
        """
        Get the KeyStroke for the given action name.
        
        :param java.lang.String or str optionName: the option name
        :param javax.swing.KeyStroke defaultValue: value that is stored and returned if there is no
        option with the given name
        :return: KeyStroke option
        :rtype: javax.swing.KeyStroke
        :raises IllegalArgumentException: is a option exists with the given
        name but it is not a KeyStroke
        
        .. deprecated::
        
        use :meth:`getActionTrigger(String, ActionTrigger) <.getActionTrigger>` instead
        """

    def getLeafOptionNames(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of option names that immediately fall under this options.  For example, if this options
        object had the following options named ("a", "b", "c.d"), only "a" and "b" would be returned.  The
        "c.d" leaf option name could be returned by getOptions("c").getLeafOptionNames()
        
        :return: the list of the names of the options that are immediate children of this options object.
        :rtype: java.util.List[java.lang.String]
        """

    def getLong(self, optionName: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Get the long value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param jpype.JLong or int defaultValue: value that is stored and returned if there
        is no option with the given name
        :return: long value for the option
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get the name of this options object.
        
        :return: String
        :rtype: str
        """

    def getObject(self, optionName: typing.Union[java.lang.String, str], defaultValue: java.lang.Object) -> java.lang.Object:
        """
        Get the object value; called when the options dialog is being
        populated.
        
        :param java.lang.String or str optionName: option name
        :param java.lang.Object defaultValue: default value
        :return: object with the given option name; if no option was found,
        return default value (this value is not stored in the option maps)
        :rtype: java.lang.Object
        """

    def getOptionNames(self) -> java.util.List[java.lang.String]:
        """
        Get the list of option names. This method will return the names (paths) of all options contained
        in this options object or below.  For example, if the options has ("aaa", "bbb", "ccc.ddd"),
        all three will be returned.  the :meth:`Options.getLeafOptionNames() <Options.getLeafOptionNames>` method will return only
        the "aaa" and "bbb" names.
        
        :return: the list of all option names(paths) under this options.
        :rtype: java.util.List[java.lang.String]
        """

    def getOptions(self, path: typing.Union[java.lang.String, str]) -> Options:
        """
        Returns a Options object that is a sub-options of this options.
        
         
        Note: the option path can have :obj:`Options.DELIMITER` characters which will be
        used to create a hierarchy with each element in the path resulting in sub-option of the
        previous path element.
        
        :param java.lang.String or str path: the path for the sub-options object
        :return: an Options object that is a sub-options of this options
        :rtype: Options
        """

    def getOptionsEditor(self) -> OptionsEditor:
        """
        Get the editor that will handle editing all the values in this options or sub group of options.
        
        :return: null if no options editor was registered
        :rtype: OptionsEditor
        """

    def getOptionsHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the HelpLocation for this entire Options object.
        
        :return: the HelpLocation for this entire Options object.
        :rtype: ghidra.util.HelpLocation
        """

    def getPropertyEditor(self, optionName: typing.Union[java.lang.String, str]) -> java.beans.PropertyEditor:
        """
        Get the property editor for the option with the given name. Note: This method must be called
        from the swing thread.
        
        :param java.lang.String or str optionName: the option name
        :return: either the PropertyEditor that was registered for this option or a default editor
        for the property type if one can be found; otherwise null.
        :rtype: java.beans.PropertyEditor
        :raises IllegalStateException: if not called from the swing thread.
        """

    def getRegisteredPropertyEditor(self, optionName: typing.Union[java.lang.String, str]) -> java.beans.PropertyEditor:
        """
        Get the property editor that was registered for the specific option with the given name.  Unlike
        the getPropertyEditor() method, this method does not have to be called from the swing thread
        
        :param java.lang.String or str optionName: the option name
        :return: the PropertyEditor that was registered for this option.
        :rtype: java.beans.PropertyEditor
        """

    def getString(self, optionName: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Get the string value for the given option name.
        
        :param java.lang.String or str optionName: option name
        :param java.lang.String or str defaultValue: value that is stored and returned if there is no
        option with the given name
        :return: String value for the option
        :rtype: str
        """

    def getType(self, optionName: typing.Union[java.lang.String, str]) -> OptionType:
        """
        Returns the OptionType of the given option.
        
        :param java.lang.String or str optionName: the name of the option for which to get the type.
        :return: the OptionType of option with the given name.
        :rtype: OptionType
        """

    def getValueAsString(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the value as a string for the given option.
        
        :param java.lang.String or str name: the name of the option for which to retrieve the value as a string
        :return: the value as a string for the given option.
        :rtype: str
        """

    @staticmethod
    def hasSameOptionsAndValues(options1: Options, options2: Options) -> bool:
        """
        Returns true if the two options objects have the same set of options and values
        
        :param Options options1: the first options object to test
        :param Options options2: the second options object to test
        :return: true if the two options objects have the same set of options and values
        :rtype: bool
        """

    def isAlias(self, aliasName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns
        
        :param java.lang.String or str aliasName: the name of the alias.
        :return: a Options object that is a sub-options of this options.
        :rtype: bool
        """

    def isDefaultValue(self, optionName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the option with the given name's current value is the default value.
        
        :param java.lang.String or str optionName: the name of the option.
        :return: true if the options has its current value equal to its default value.
        :rtype: bool
        """

    def isRegistered(self, optionName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the specified option has been registered.  Only registered names
        are saved.
        
        :param java.lang.String or str optionName: the option name
        :return: true if registered
        :rtype: bool
        """

    def putObject(self, optionName: typing.Union[java.lang.String, str], obj: java.lang.Object):
        """
        Put the object value.  If the option exists, the type must match the type of the existing
        object.
        
        :param java.lang.String or str optionName: the option name
        :param java.lang.Object obj: the option value
        :raises IllegalStateException: if the object does not match the existing type of the option.
        :raises IllegalArgumentException: if the object is null or not a supported type.
        """

    @typing.overload
    def registerOption(self, optionName: typing.Union[java.lang.String, str], defaultValue: java.lang.Object, help: ghidra.util.HelpLocation, description: typing.Union[java.lang.String, str]):
        """
        Registers an option with a description, help location, and a default value without specifying
        the option type.  This form requires that the default value not be null so that the option
        type can be inferred from the default value.
         
        
        Note, this method should not be used for
        colors and font as doing so will result in those colors and fonts becoming disconnected
        to the current theme. Instead use
        
        :meth:`registerThemeColorBinding(String, String, HelpLocation, String) <.registerThemeColorBinding>` or
        :meth:`registerThemeFontBinding(String, String, HelpLocation, String) <.registerThemeFontBinding>`.
        
        :param java.lang.String or str optionName: the name of the option being registered.
        :param java.lang.Object defaultValue: the defaultValue for the option. The default value must not be
        null so that the OptionType can be determined.  If the default value should be null, use
        :meth:`registerOption(String, OptionType, Object, HelpLocation, String) <.registerOption>`
        :param ghidra.util.HelpLocation help: the HelpLocation for this option.
        :param java.lang.String or str description: a description of the option.
        :raises IllegalArgumentException: if the defaultValue is null
        """

    @typing.overload
    def registerOption(self, optionName: typing.Union[java.lang.String, str], type: OptionType, defaultValue: java.lang.Object, help: ghidra.util.HelpLocation, description: typing.Union[java.lang.String, str]):
        """
        Registers an option with a description, help location, and a optional default value.  With an optional
        default value, an OptionType must be passed as it is otherwise derived from the default value.
         
        
        Note, this method should not be used for
        colors and font as doing so will result in those colors and fonts becoming disconnected
        to the current theme. Instead use
        :meth:`registerThemeColorBinding(String, String, HelpLocation, String) <.registerThemeColorBinding>` or
        :meth:`registerThemeFontBinding(String, String, HelpLocation, String) <.registerThemeFontBinding>`.
        
        :param java.lang.String or str optionName: the name of the option being registered.
        :param OptionType type: the OptionType for this options.
        :param java.lang.Object defaultValue: the defaultValue for the option. In this version of the method, the default
        value may be null.
        :param ghidra.util.HelpLocation help: the HelpLocation for this option.
        :param java.lang.String or str description: a description of the option.
        """

    @typing.overload
    def registerOption(self, optionName: typing.Union[java.lang.String, str], type: OptionType, defaultValue: java.lang.Object, help: ghidra.util.HelpLocation, description: typing.Union[java.lang.String, str], editor: java.util.function.Supplier[java.beans.PropertyEditor]):
        """
        Registers an option with a description, help location, and a optional default value.  With an optional
        default value, an OptionType must be passed as it is otherwise derived from the default value.
         
        
        Note, this method should not be used for
        colors and font as doing so will result in those colors and fonts becoming disconnected
        to the current theme. Instead use
        :meth:`registerThemeColorBinding(String, String, HelpLocation, String) <.registerThemeColorBinding>` or
        :meth:`registerThemeFontBinding(String, String, HelpLocation, String) <.registerThemeFontBinding>`.
         
        
        Note: we use a *supplier* of a custom editor, instead of a custom editor, to avoid
        creating :obj:`PropertyEditor`s until needed.  This allows us to use the same API in both
        GUI mode and headless mode.  If GUI property editors are created in headless mode, exceptions
        may be thrown.  This API will not use the supplier when in headless mode, this avoiding the
        creation of GUI components.  For this to work correctly, clients using custom property
        editors must defer construction of the editor until the supplier is called.
        
        :param java.lang.String or str optionName: the name of the option being registered.
        :param OptionType type: the OptionType for this options.
        :param java.lang.Object defaultValue: the defaultValue for the option. In this version of the method, the default
        value may be null.
        :param ghidra.util.HelpLocation help: the HelpLocation for this option.
        :param java.lang.String or str description: a description of the option.
        :param java.util.function.Supplier[java.beans.PropertyEditor] editor: an optional supplier of a custom editor for this property. Note if the option
        is a custom option, then the property editor can't be null;
        :raises IllegalStateException: if the options is a custom option and the editor is null.
        """

    @typing.overload
    @deprecated("Use instead\n registerOption(String, OptionType, Object, HelpLocation, String, Supplier)")
    def registerOption(self, optionName: typing.Union[java.lang.String, str], type: OptionType, defaultValue: java.lang.Object, help: ghidra.util.HelpLocation, description: typing.Union[java.lang.String, str], editor: java.beans.PropertyEditor):
        """
        Use instead
        :meth:`registerOption(String, OptionType, Object, HelpLocation, String, Supplier) <.registerOption>`
        
        :param java.lang.String or str optionName: the name of the option being registered.
        :param OptionType type: the OptionType for this options.
        :param java.lang.Object defaultValue: the defaultValue for the option. In this version of the method, the default
        value may be null.
        :param ghidra.util.HelpLocation help: the HelpLocation for this option.
        :param java.lang.String or str description: a description of the option.
        :param java.beans.PropertyEditor editor: an optional supplier of a custom editor for this property. Note if the option
        is a custom option, then the property editor can't be null;
        
        .. deprecated::
        
        Use instead
        :meth:`registerOption(String, OptionType, Object, HelpLocation, String, Supplier) <.registerOption>`
        """

    @typing.overload
    def registerOptionsEditor(self, editor: java.util.function.Supplier[OptionsEditor]):
        """
        Register the options editor that will handle the editing for all the options or a sub-group
        of options.
         
        
        Note: we use a *supplier* of a custom editor, instead of a custom editor, to avoid
        creating :obj:`PropertyEditor`s until needed.  This allows us to use the same API in both
        GUI mode and headless mode.  If GUI property editors are created in headless mode, exceptions
        may be thrown.  This API will not use the supplier when in headless mode, this avoiding the
        creation of GUI components.  For this to work correctly, clients using custom property
        editors must defer construction of the editor until the supplier is called.
        
        :param java.util.function.Supplier[OptionsEditor] editor: a supplier for the custom editor panel to be used to edit the options or
        sub-group of options.
        """

    @typing.overload
    @deprecated("Use instead registerOptionsEditor(Supplier)")
    def registerOptionsEditor(self, editor: OptionsEditor):
        """
        Use instead :meth:`registerOptionsEditor(Supplier) <.registerOptionsEditor>`
        
        :param OptionsEditor editor: the editor
        
        .. deprecated::
        
        Use instead :meth:`registerOptionsEditor(Supplier) <.registerOptionsEditor>`
        """

    def registerThemeColorBinding(self, optionName: typing.Union[java.lang.String, str], colorId: typing.Union[java.lang.String, str], help: ghidra.util.HelpLocation, description: typing.Union[java.lang.String, str]):
        """
        Register/binds the option to a theme color id. Changing the option's color via the options
        Gui will result in directly changing the theme color of the given color id.
        
        :param java.lang.String or str optionName: the name of the color option
        :param java.lang.String or str colorId: the theme color id whose color value is changed when the option's color is changed
        :param ghidra.util.HelpLocation help: the HelpLocation for this option
        :param java.lang.String or str description: a description of the option
        """

    def registerThemeFontBinding(self, optionName: typing.Union[java.lang.String, str], fontId: typing.Union[java.lang.String, str], help: ghidra.util.HelpLocation, description: typing.Union[java.lang.String, str]):
        """
        Register/binds the option to a theme font id. Changing the option's font via the options
        Gui will result in directly changing the theme color of the given font id.
        
        :param java.lang.String or str optionName: the name of the font option
        :param java.lang.String or str fontId: the theme color id whose color value is changed when the option's color
        is changed
        :param ghidra.util.HelpLocation help: the HelpLocation for this option
        :param java.lang.String or str description: a description of the option
        """

    def removeOption(self, optionName: typing.Union[java.lang.String, str]):
        """
        Remove the option name.
        
        :param java.lang.String or str optionName: name of option to remove
        """

    def restoreDefaultValue(self, optionName: typing.Union[java.lang.String, str]):
        """
        Restores the option denoted by the given name to its default value.
        
        :param java.lang.String or str optionName: The name of the option to restore
        
        .. seealso::
        
            | :obj:`.restoreDefaultValues()`
        """

    def restoreDefaultValues(self):
        """
        Restores **all** options contained herein to their default values.
        
        
        .. seealso::
        
            | :obj:`.restoreDefaultValue(String)`
        """

    def setActionTrigger(self, optionName: typing.Union[java.lang.String, str], value: ActionTrigger):
        """
        Sets the action trigger value for the option
        
        :param java.lang.String or str optionName: name of the option
        :param ActionTrigger value: action trigger to set
        :raises IllegalArgumentException: if a option with the given
        name already exists, but it is not an action trigger
        """

    def setBoolean(self, optionName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the boolean value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param jpype.JBoolean or bool value: value of the option
        """

    def setByteArray(self, optionName: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JByte]):
        """
        Sets the byte[] value for the given option name.
        
        :param java.lang.String or str optionName: the name of the option on which to save bytes.
        :param jpype.JArray[jpype.JByte] value: the value
        """

    def setColor(self, optionName: typing.Union[java.lang.String, str], value: java.awt.Color):
        """
        Sets the Color value for the option
        
        :param java.lang.String or str optionName: name of the option
        :param java.awt.Color value: Color to set
        :raises IllegalArgumentException: if a option with the given
        name already exists, but it is not a Color
        """

    def setCustomOption(self, optionName: typing.Union[java.lang.String, str], value: CustomOption):
        """
        Sets the Custom option value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param CustomOption value: the value
        """

    def setDate(self, optionName: typing.Union[java.lang.String, str], newSetting: java.util.Date):
        """
        Sets the Date value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param java.util.Date newSetting: the Date to set
        """

    def setDouble(self, optionName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JDouble, float]):
        """
        Sets the double value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param jpype.JDouble or float value: value of the option
        """

    def setEnum(self, optionName: typing.Union[java.lang.String, str], value: T):
        """
        Set the Enum value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param T value: Enum value of the option
        """

    def setFile(self, optionName: typing.Union[java.lang.String, str], value: jpype.protocol.SupportsPath):
        """
        Sets the File value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param jpype.protocol.SupportsPath value: the value
        """

    def setFloat(self, optionName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JFloat, float]):
        """
        Sets the float value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param jpype.JFloat or float value: value of the option
        """

    def setFont(self, optionName: typing.Union[java.lang.String, str], value: java.awt.Font):
        """
        Sets the Font value for the option
        
        :param java.lang.String or str optionName: name of the option
        :param java.awt.Font value: Font to set
        :raises IllegalArgumentException: if a option with the given
        name already exists, but it is not a Font
        """

    def setInt(self, optionName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Sets the int value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param jpype.JInt or int value: value of the option
        """

    @deprecated("use setActionTrigger(String, ActionTrigger) instead")
    def setKeyStroke(self, optionName: typing.Union[java.lang.String, str], value: javax.swing.KeyStroke):
        """
        Sets the KeyStroke value for the option
        
        :param java.lang.String or str optionName: name of the option
        :param javax.swing.KeyStroke value: KeyStroke to set
        :raises IllegalArgumentException: if a option with the given
        name already exists, but it is not a KeyStroke
        
        .. deprecated::
        
        use :meth:`setActionTrigger(String, ActionTrigger) <.setActionTrigger>` instead
        """

    def setLong(self, optionName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Sets the long value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param jpype.JLong or int value: value of the option
        """

    def setOptionsHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        """
        Set the location for where help can be found for this entire options object.
        
        :param ghidra.util.HelpLocation helpLocation: location for help on the option
        """

    def setString(self, optionName: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Set the String value for the option.
        
        :param java.lang.String or str optionName: name of the option
        :param java.lang.String or str value: value of the option
        """

    @property
    def registeredPropertyEditor(self) -> java.beans.PropertyEditor:
        ...

    @property
    def optionsHelpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @optionsHelpLocation.setter
    def optionsHelpLocation(self, value: ghidra.util.HelpLocation):
        ...

    @property
    def defaultValue(self) -> java.lang.Object:
        ...

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def leafOptionNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def defaultValueAsString(self) -> java.lang.String:
        ...

    @property
    def registered(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def type(self) -> OptionType:
        ...

    @property
    def childOptions(self) -> java.util.List[Options]:
        ...

    @property
    def propertyEditor(self) -> java.beans.PropertyEditor:
        ...

    @property
    def optionsEditor(self) -> OptionsEditor:
        ...

    @property
    def options(self) -> Options:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def alias(self) -> jpype.JBoolean:
        ...

    @property
    def optionNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def iD(self) -> java.lang.String:
        ...


class EditorStateFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def clear(self, options: Options, name: typing.Union[java.lang.String, str]):
        ...

    def clearAll(self):
        ...

    def getEditorState(self, options: Options, name: typing.Union[java.lang.String, str], listener: java.beans.PropertyChangeListener) -> EditorState:
        ...


class Option(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    UNREGISTERED_OPTION: typing.Final = "Unregistered Option"

    def doSetCurrentValue(self, value: java.lang.Object):
        ...

    def getCurrentValue(self) -> java.lang.Object:
        ...

    def getDefaultValue(self) -> java.lang.Object:
        ...

    def getDescription(self) -> str:
        ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        ...

    def getInceptionInformation(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getOptionType(self) -> OptionType:
        ...

    def getPropertyEditor(self) -> java.beans.PropertyEditor:
        ...

    def getValue(self, passedInDefaultValue: java.lang.Object) -> java.lang.Object:
        ...

    def isDefault(self) -> bool:
        ...

    def isRegistered(self) -> bool:
        ...

    def restoreDefault(self):
        ...

    def setCurrentValue(self, value: java.lang.Object):
        ...

    @property
    def optionType(self) -> OptionType:
        ...

    @property
    def inceptionInformation(self) -> java.lang.String:
        ...

    @property
    def default(self) -> jpype.JBoolean:
        ...

    @property
    def propertyEditor(self) -> java.beans.PropertyEditor:
        ...

    @property
    def defaultValue(self) -> java.lang.Object:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def registered(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...

    @property
    def currentValue(self) -> java.lang.Object:
        ...

    @currentValue.setter
    def currentValue(self, value: java.lang.Object):
        ...


class NoRegisteredEditorPropertyEditor(java.beans.PropertyEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractOptions(Options):

    class AliasBinding(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    SUPPORTED_CLASSES: typing.Final[java.util.Set[java.lang.Class[typing.Any]]]

    def dispose(self):
        ...

    @staticmethod
    def findPropertyEditor(originalValueClass: java.lang.Class[typing.Any]) -> java.beans.PropertyEditor:
        ...

    def getCategoryHelpLocation(self, categoryPath: typing.Union[java.lang.String, str]) -> ghidra.util.HelpLocation:
        ...

    def getOption(self, optionName: typing.Union[java.lang.String, str], type: OptionType, defaultValue: java.lang.Object) -> Option:
        ...

    def getOptionsEditor(self, categoryPath: typing.Union[java.lang.String, str]) -> OptionsEditor:
        ...

    def putObject(self, optionName: typing.Union[java.lang.String, str], newValue: java.lang.Object, type: OptionType):
        ...

    def registerOptionsEditor(self, categoryPath: typing.Union[java.lang.String, str], editorSupplier: java.util.function.Supplier[OptionsEditor]):
        ...

    def setCategoryHelpLocation(self, categoryPath: typing.Union[java.lang.String, str], helpLocation: ghidra.util.HelpLocation):
        ...

    def setName(self, newName: typing.Union[java.lang.String, str]):
        """
        Sets the name for this Options object.  Used when updating old options names to new names.
        
        :param java.lang.String or str newName: the new name for this options object.
        """

    @property
    def categoryHelpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def optionsEditor(self) -> OptionsEditor:
        ...


class WrappedDate(WrappedOption):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, date: java.util.Date):
        ...

    @typing.overload
    def __init__(self):
        ...


@typing.type_check_only
class WrappedColor(WrappedOption):
    """
    An wrapper object for registering Colors as options.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.Object()`
        """

    def readState(self, saveState: SaveState):
        """
        Reads the saved Color information and reconstructs the Color.
        """

    def writeState(self, saveState: SaveState):
        """
        Saves the Color information so that it can be reconstructed.
        """


class CustomOptionsEditor(java.lang.Object):
    """
    Marker interface to signal that the implementing PropertyEditor component desires to handle
    display editing of an option or options.  This allows options to create custom property
    editors that can paint and edit a group of interrelated options.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOptionDescriptions(self) -> jpype.JArray[java.lang.String]:
        """
        Gets the descriptions of the options that this editor is editing.
        
        :return: the descriptions of the options that this editor is editing; may be null.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getOptionNames(self) -> jpype.JArray[java.lang.String]:
        """
        Gets the names of the options that this editor is editing.
        
        :return: the names of the options that this editor is editing; may not be null.
        :rtype: jpype.JArray[java.lang.String]
        """

    @property
    def optionNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def optionDescriptions(self) -> jpype.JArray[java.lang.String]:
        ...


class PropertyText(javax.swing.JTextField):
    """
    An implementation of PropertyComponent that is represented as a text field.
    """

    @typing.type_check_only
    class UpdateDocumentListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pe: java.beans.PropertyEditor):
        """
        Constructor new PropertyText.
        
        :param java.beans.PropertyEditor pe: bean property editor that is used to get the value
        to show in the text field
        """


class FileOptions(AbstractOptions):

    @typing.type_check_only
    class FileOption(Option):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        ...

    def copy(self) -> FileOptions:
        ...

    def getFile(self) -> java.io.File:
        ...

    def readCustomOption(self, properties: GProperties) -> CustomOption:
        ...

    def save(self, saveFile: jpype.protocol.SupportsPath):
        ...

    @property
    def file(self) -> java.io.File:
        ...


class OptionsChangeListener(java.lang.Object):
    """
    Interface for notifying listeners when options change.
     
    
    Register with :meth:`ToolOptions.addOptionsChangeListener(OptionsChangeListener) <ToolOptions.addOptionsChangeListener>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def optionsChanged(self, options: ToolOptions, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that an option changed.
         
        
        Note: to reject an options change, you can throw a 
        :obj:`OptionsVetoException`.
        
        :param ToolOptions options: options object containing the property that changed
        :param java.lang.String or str optionName: name of option that changed
        :param java.lang.Object oldValue: old value of the option
        :param java.lang.Object newValue: new value of the option
        :raises OptionsVetoException: if a change is rejected
        """


@typing.type_check_only
class WrappedKeyStroke(WrappedOption):
    """
    Wrapper for a KeyStroke that will get saved as a property in an Options
    object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def toWrappedActionTrigger(self) -> WrappedActionTrigger:
        """
        A method to allow for converting the deprecated options key stroke usage to the new action
        trigger usage
        
        :return: a WrappedActionTrigger
        :rtype: WrappedActionTrigger
        """


class EditorState(java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, options: Options, name: typing.Union[java.lang.String, str]):
        ...

    def applyNonDefaults(self, save: Options):
        ...

    def applyValue(self):
        ...

    def getDescription(self) -> str:
        ...

    def getEditorComponent(self) -> java.awt.Component:
        ...

    def getTitle(self) -> str:
        ...

    def hasSameValue(self, compareTo: Options) -> bool:
        ...

    def isValueChanged(self) -> bool:
        ...

    def loadFrom(self, loadFrom: Options):
        ...

    def supportsCustomOptionsEditor(self) -> bool:
        """
        Returns true if the contained PropertyEditor desired to render and handle it's options
        directly, as opposed to using the generic framework.
        
        :return: true if the contained PropertyEditor desired to render and handle it's options
        directly, as opposed to using the generic framework.
        :rtype: bool
        """

    @property
    def valueChanged(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def title(self) -> java.lang.String:
        ...

    @property
    def editorComponent(self) -> java.awt.Component:
        ...


class ErrorPropertyEditor(java.beans.PropertyEditorSupport):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, errorMessage: typing.Union[java.lang.String, str], value: java.lang.Object):
        ...


class WrappedActionTrigger(WrappedOption):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OptionsEditor(java.lang.Object):
    """
    Interface to define methods for an editor that supplies its own
    component to be displayed in the OptionsDialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self):
        """
        Apply the changes.
        """

    def cancel(self):
        """
        Cancel the changes.
        """

    def dispose(self):
        """
        Dispose this editor
        """

    def getEditorComponent(self, options: Options, editorStateFactory: EditorStateFactory) -> javax.swing.JComponent:
        """
        Get the editor component.
        
        :param Options options: The editable options that for which a GUI component will be created
        :param EditorStateFactory editorStateFactory: The factory that will provide state objects this options editor
        """

    def reload(self):
        """
        A signal to reload the GUI widgets in the component created by this editor.  This will 
        happen when the options change out from under the editor, such as when the user restores
        the default options values.
        """

    def setOptionsPropertyChangeListener(self, listener: java.beans.PropertyChangeListener):
        """
        Sets the options change listener
        
        :param java.beans.PropertyChangeListener listener:
        """


class WrappedOption(java.lang.Object):
    """
    Wrapper class for an object that represents a property value and is
    saved as a set of primitives.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getObject(self) -> java.lang.Object:
        """
        Get the object that is the property value.
        """

    def getOptionType(self) -> OptionType:
        ...

    def readState(self, saveState: SaveState):
        """
        Concrete subclass of WrappedOption should read all of its
        state from the given saveState object.
        
        :param SaveState saveState: container of state information
        """

    def writeState(self, saveState: SaveState):
        """
        Concrete subclass of WrappedOption should write all of its
        state to the given saveState object.
        
        :param SaveState saveState: container of state information
        """

    @property
    def optionType(self) -> OptionType:
        ...

    @property
    def object(self) -> java.lang.Object:
        ...


@typing.type_check_only
class WrappedFont(WrappedOption):
    """
    A wrapper object for registering fonts as options.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.Object()`
        """

    def readState(self, saveState: SaveState):
        """
        Reads the saved Font information and reconstructs the font.
        """

    def writeState(self, saveState: SaveState):
        """
        Saves the Font information so that it can be reconstructed.
        """


class CustomOption(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    CUSTOM_OPTION_CLASS_NAME_KEY: typing.Final = "CUSTOM_OPTION_CLASS"
    """
    Key which corresponds to custom option implementation class.  The use of this key/value 
    within the stored state information is reserved for use by the option storage implementation 
    and should be ignored by :meth:`readState(GProperties) <.readState>` implementation.
    """


    def readState(self, properties: GProperties):
        """
        Read state from the given properties
        
        :param GProperties properties: container of state information
        """

    def toString(self) -> str:
        """
        Subclasses should implement this method to provide a formatted string value of this option 
        value.  The returned value will be used in support of the 
        :meth:`Options.getValueAsString(String) <Options.getValueAsString>` and :meth:`Options.getDefaultValueAsString(String) <Options.getDefaultValueAsString>`.
        
        :return: option value as string
        :rtype: str
        """

    def writeState(self, properties: GProperties):
        """
        Write state into the given properties
        
        :param GProperties properties: container of state information
        """


class ActionTrigger(java.lang.Object):
    """
    Represents a way to trigger an action in the system.  A trigger is based on a key stroke, a mouse 
    binding or both.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, keyStroke: javax.swing.KeyStroke):
        """
        Creates an action trigger with the given key stroke.
        
        :param javax.swing.KeyStroke keyStroke: the key stroke
        """

    @typing.overload
    def __init__(self, mouseBinding: gui.event.MouseBinding):
        """
        Creates an action trigger with the given mouse binding.
        
        :param gui.event.MouseBinding mouseBinding: the mouse binding
        """

    @typing.overload
    def __init__(self, keyStroke: javax.swing.KeyStroke, mouseBinding: gui.event.MouseBinding):
        """
        A convenience constructor for creating an action trigger with either or both values set.  At
        least one of the values must be non-null.
        
        :param javax.swing.KeyStroke keyStroke: the key stroke; may be null
        :param gui.event.MouseBinding mouseBinding: the mouse binding; may be null
        """

    @staticmethod
    def create(saveState: SaveState) -> ActionTrigger:
        """
        Creates a new action trigger by reading data from the given save state.
        
        :param SaveState saveState: the save state
        :return: the new action trigger
        :rtype: ActionTrigger
        """

    @staticmethod
    def getActionTrigger(string: typing.Union[java.lang.String, str]) -> ActionTrigger:
        """
        Creates a new action trigger from the given string.  The string is expected to be the result
        of calling :meth:`toString() <.toString>` on an instance of this class.
        
        :param java.lang.String or str string: the string to parse.
        :return: the new instance or null of the string is invalid.
        :rtype: ActionTrigger
        """

    def getKeyStroke(self) -> javax.swing.KeyStroke:
        ...

    def getMouseBinding(self) -> gui.event.MouseBinding:
        ...

    def writeState(self, saveState: SaveState):
        """
        Writes this action trigger's data into the given save state.
        
        :param SaveState saveState: the save state
        """

    @property
    def mouseBinding(self) -> gui.event.MouseBinding:
        ...

    @property
    def keyStroke(self) -> javax.swing.KeyStroke:
        ...


class PreferenceState(SaveState):
    """
    An implementation of SaveState that exists primarily to signal its intended usage.  The 
    SaveState is a generic object for saving program state through plugins.  This state object
    is meant to be used for preferences **that are not associated directly with a plugin**.
    """

    class_: typing.ClassVar[java.lang.Class]
    PREFERENCE_STATE_NAME: typing.Final = "PREFERENCE_STATE"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, element: org.jdom.Element):
        """
        Initializes a new state object from the given element.
        
        :param org.jdom.Element element: The element from which to initialize.
        """


class ToolOptions(AbstractOptions):
    """
    Class to manage a set of option name/value pairs for a category.
    
     
    The values may be primitives or :obj:`WrappedOption`s that are containers for primitive
    components.
    
     
    The name/value pair has an owner so that the option name can be removed from the Options
    object when it is no longer being used.
    
     
    Note: Property Names can have :obj:`Options.DELIMITER` characters to create a hierarchy.
    So too can sub-options accessed via :meth:`getOptions(String) <.getOptions>`.
    
     
    The Options Dialog shows the delimited hierarchy in tree format.
    """

    @typing.type_check_only
    class ToolOption(Option):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NotifyListenersRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    PRIMITIVE_CLASSES: typing.Final[java.util.Set[java.lang.Class[typing.Any]]]
    WRAPPABLE_CLASSES: typing.Final[java.util.Set[java.lang.Class[typing.Any]]]
    XML_ELEMENT_NAME: typing.Final = "CATEGORY"

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, root: org.jdom.Element):
        """
        Construct a new Options object from the given XML element.
        
        :param org.jdom.Element root: XML that contains the set of options to restore
        """

    def addOptionsChangeListener(self, l: OptionsChangeListener):
        """
        Add the options change listener. NOTE: The Options uses
        WeakReferences to manage the listeners; this means that you must supply a
        listener and maintain a handle to it, or else the listener will be
        garbage collected and will never get called. So for this reason, do
        *not* create the listener in an anonymous inner class.
        
        :param OptionsChangeListener l: listener to add
        """

    def copy(self) -> ToolOptions:
        ...

    def copyOptions(self, newOptions: Options):
        """
        Adds all the options name/value pairs to this Options.
        
        :param Options newOptions: the new options into which the current options values will be placed
        """

    def getXmlRoot(self, includeDefaultBindings: typing.Union[jpype.JBoolean, bool]) -> org.jdom.Element:
        """
        Return an XML element for the option names and values.
        Note: only those options which have been explicitly set
        will be included.
        
        :param jpype.JBoolean or bool includeDefaultBindings: true to include default key binding values in the xml
        :return: the xml root element
        :rtype: org.jdom.Element
        """

    def registerOptions(self, oldOptions: ToolOptions):
        ...

    def removeOptionsChangeListener(self, l: OptionsChangeListener):
        """
        Remove the options change listener.
        
        :param OptionsChangeListener l: listener to remove
        """

    def removeUnusedOptions(self):
        """
        Check each option to ensure that an owner is still registered for it;
        if there is no owner, then remove the option.
        """

    def takeListeners(self, oldOptions: ToolOptions):
        ...

    def validateOptions(self):
        ...

    @property
    def xmlRoot(self) -> org.jdom.Element:
        ...


class EnumEditor(java.beans.PropertyEditorSupport):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getEnums(self) -> jpype.JArray[java.lang.Enum[typing.Any]]:
        ...

    @property
    def enums(self) -> jpype.JArray[java.lang.Enum[typing.Any]]:
        ...


class PropertySelector(javax.swing.JComboBox[java.lang.String], java.awt.event.ItemListener):
    """
    An implementation of a PropertyComponent that is represented as a
    combo box.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pe: java.beans.PropertyEditor):
        """
        Constructor.
        
        :param java.beans.PropertyEditor pe: bean property editor that is updated when the state
        changes in the combo box
        """


class PropertyBoolean(javax.swing.JCheckBox, java.awt.event.ItemListener):
    """
    A basic editor for booleans.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pe: java.beans.PropertyEditor):
        """
        Constructor
        
        :param java.beans.PropertyEditor pe: bean property editor that is used to get the value to show in the text field
        """


class WrappedFile(WrappedOption):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        ...

    @typing.overload
    def __init__(self):
        ...


class OptionType(java.lang.Enum[OptionType]):

    @typing.type_check_only
    class StringAdapter(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IntStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LongStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DoubleStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BooleanStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DateStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NoTypeStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FloatStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnumStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DUMMY(java.lang.Enum[OptionType.DUMMY]):

        class_: typing.ClassVar[java.lang.Class]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> OptionType.DUMMY:
            ...

        @staticmethod
        def values() -> jpype.JArray[OptionType.DUMMY]:
            ...


    @typing.type_check_only
    class CustomStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class ByteArrayStringAdapter(OptionType.StringAdapter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FileStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColorStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FontStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyStrokeStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionTriggerStringAdapter(OptionType.StringAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    INT_TYPE: typing.Final[OptionType]
    LONG_TYPE: typing.Final[OptionType]
    STRING_TYPE: typing.Final[OptionType]
    DOUBLE_TYPE: typing.Final[OptionType]
    BOOLEAN_TYPE: typing.Final[OptionType]
    DATE_TYPE: typing.Final[OptionType]
    NO_TYPE: typing.Final[OptionType]
    FLOAT_TYPE: typing.Final[OptionType]
    ENUM_TYPE: typing.Final[OptionType]
    CUSTOM_TYPE: typing.Final[OptionType]
    BYTE_ARRAY_TYPE: typing.Final[OptionType]
    FILE_TYPE: typing.Final[OptionType]
    COLOR_TYPE: typing.Final[OptionType]
    FONT_TYPE: typing.Final[OptionType]
    KEYSTROKE_TYPE: typing.Final[OptionType]
    ACTION_TRIGGER: typing.Final[OptionType]

    def convertObjectToString(self, object: java.lang.Object) -> str:
        ...

    def convertStringToObject(self, string: typing.Union[java.lang.String, str]) -> java.lang.Object:
        ...

    @staticmethod
    def getOptionType(obj: java.lang.Object) -> OptionType:
        ...

    def getValueClass(self) -> java.lang.Class[typing.Any]:
        ...

    def isCompatible(self, object: java.lang.Object) -> bool:
        """
        Return true if the give value is of the correct type for this option type. Note that a
        value of null is compatible with any class type
        since it is an acceptable value for any class type.
        
        :param java.lang.Object object: the object to see if it is compatible with this option type
        :return: true if the give value is of the correct type for this option type.
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> OptionType:
        ...

    @staticmethod
    def values() -> jpype.JArray[OptionType]:
        ...

    @property
    def compatible(self) -> jpype.JBoolean:
        ...

    @property
    def valueClass(self) -> java.lang.Class[typing.Any]:
        ...


class WrappedCustomOption(WrappedOption):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, value: CustomOption):
        ...

    @typing.overload
    def __init__(self):
        ...

    def isValid(self) -> bool:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...


class XmlProperties(GProperties):
    """
    A convenience class for creating a GProperties object from a file containing XML data
    generated from :meth:`GProperties.saveToXmlFile(File) <GProperties.saveToXmlFile>`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        ...

    @typing.overload
    def __init__(self, element: org.jdom.Element):
        ...


class GProperties(java.lang.Object):
    """
    Class for saving name/value pairs as XML or Json.  Classes that want to be
    able to save their state can do so using the GProperies object.
    The idea is that each state variable in the class
    is first saved into a GProperties object via a String key.  Then the GProperties
    object is written out as XML or Json.  When the GProperties object is
    restored, the GProperties object is constructed with an XML Element or JsonObject
    that contains all of the name/value pairs. There are convenience subclasses for reading
    these from a file (XmlProperties and JsonProperties).
     
    Since the "get" methods require a default value, the object that is recovering its 
    state variables will be successfully initialized even if
    the given key,value pair is not found in the SaveState object.
     
    *Note: Names for property names are assumed to be unique. When a putXXX()
    method is called, if a value already exists for a name, it will
    be overwritten.*
     
    
    The GProperties supports the following types:
     
        java primitives
        arrays of java primitives
        String
        Color
        Font
        KeyStroke
        File
        Date
        Enum
        GProperties (values can be nested GProperties)
    """

    class_: typing.ClassVar[java.lang.Class]
    DATE_FORMAT: typing.ClassVar[java.text.DateFormat]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates a new GProperties object with a non-default name.  The name serves no real purpose
        other than as a hint as to what the GProperties represents
        
        :param java.lang.String or str name: of this GProperties object
        """

    @typing.overload
    def __init__(self, root: org.jdom.Element):
        """
        Construct a new GProperties object using the given XML element.
        
        :param org.jdom.Element root: XML contents of GProperties
        """

    @typing.overload
    def __init__(self, root: com.google.gson.JsonObject):
        """
        Construct a new GProperties object using the given JSonObject.
        
        :param com.google.gson.JsonObject root: JSonObject representing a GProperties
        """

    def clear(self):
        """
        Clear all objects from this GProperties
        """

    def getBoolean(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Gets the boolean value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JBoolean or bool defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the boolean value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: bool
        """

    def getBooleans(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JBoolean]) -> jpype.JArray[jpype.JBoolean]:
        """
        Gets the boolean array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JBoolean] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the boolean array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JBoolean]
        """

    def getByte(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JByte, int]) -> int:
        """
        Gets the byte value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JByte or int defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the byte value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: int
        """

    def getBytes(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Gets the byte array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JByte] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the byte array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getColor(self, name: typing.Union[java.lang.String, str], defaultValue: java.awt.Color) -> java.awt.Color:
        """
        Gets the Color value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param java.awt.Color defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the Color value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: java.awt.Color
        """

    def getDate(self, name: typing.Union[java.lang.String, str], defaultValue: java.util.Date) -> java.util.Date:
        """
        Gets the Date value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param java.util.Date defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the Date value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: java.util.Date
        """

    def getDouble(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JDouble, float]) -> float:
        """
        Gets the double value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JDouble or float defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the double value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: float
        """

    def getDoubles(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JDouble]) -> jpype.JArray[jpype.JDouble]:
        """
        Gets the double array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JDouble] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the double array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JDouble]
        """

    def getEnum(self, name: typing.Union[java.lang.String, str], defaultValue: T) -> T:
        """
        Gets the Enum value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param T defaultValue: the default Enum value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the Enum value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: T
        """

    def getFile(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Gets the File value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.protocol.SupportsPath defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the File value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: java.io.File
        """

    def getFloat(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JFloat, float]) -> float:
        """
        Gets the float value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JFloat or float defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the float value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: float
        """

    def getFloats(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JFloat]) -> jpype.JArray[jpype.JFloat]:
        """
        Gets the float array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JFloat] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the float array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JFloat]
        """

    def getFont(self, name: typing.Union[java.lang.String, str], defaultValue: java.awt.Font) -> java.awt.Font:
        """
        Gets the Font value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param java.awt.Font defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the Font value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: java.awt.Font
        """

    def getGProperties(self, name: typing.Union[java.lang.String, str]) -> GProperties:
        ...

    def getInt(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the int value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JInt or int defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the int value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: int
        """

    def getInts(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JInt]) -> jpype.JArray[jpype.JInt]:
        """
        Gets the int array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JInt] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the int array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getKeyStroke(self, name: typing.Union[java.lang.String, str], defaultValue: javax.swing.KeyStroke) -> javax.swing.KeyStroke:
        """
        Gets the KeyStroke value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param javax.swing.KeyStroke defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the KeyStroke value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: javax.swing.KeyStroke
        """

    def getLong(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JLong, int]) -> int:
        """
        Gets the long value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JLong or int defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the long value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: int
        """

    def getLongs(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JLong]) -> jpype.JArray[jpype.JLong]:
        """
        Gets the long array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JLong] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the long array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JLong]
        """

    def getName(self) -> str:
        """
        Returns the name of this GProperties
        
        :return: the name of this GProperties
        :rtype: str
        """

    def getNames(self) -> jpype.JArray[java.lang.String]:
        """
        Return the names of the properties in this GProperties
        
        :return: the names of the properties in this GProperties
        :rtype: jpype.JArray[java.lang.String]
        """

    def getShort(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[jpype.JShort, int]) -> int:
        """
        Gets the short value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JShort or int defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the short value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: int
        """

    def getShorts(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[jpype.JShort]) -> jpype.JArray[jpype.JShort]:
        """
        Gets the short array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[jpype.JShort] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the short array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getString(self, name: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the String value for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param java.lang.String or str defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the String value associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: str
        """

    def getStrings(self, name: typing.Union[java.lang.String, str], defaultValue: jpype.JArray[java.lang.String]) -> jpype.JArray[java.lang.String]:
        """
        Gets the String array for the given name.
        
        :param java.lang.String or str name: the name of the pair.
        :param jpype.JArray[java.lang.String] defaultValue: the default value to be returned if the name does
        not exist in the map, or it does not contain the proper object type.
        :return: the String array associated with the given name or the defaultValue
        passed in if the name doesn't exist or is the wrong type.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getXmlElement(self, name: typing.Union[java.lang.String, str]) -> org.jdom.Element:
        """
        Returns the root of an XML sub-tree associated with the
        given name.
        
        :param java.lang.String or str name: The name associated with the desired Element.
        :return: The root of an XML sub-tree associated with the
        given name.
        :rtype: org.jdom.Element
        """

    def hasValue(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if there is a value for the given name
        
        :param java.lang.String or str name: true the name of the property to check for a value
        :return: true if this GProperties has a value for the given name
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this GProperties contains no elements
        
        :return: true if there are no properties in this GProperties
        :rtype: bool
        """

    def putBoolean(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        """
        Associates a boolean value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JBoolean or bool value: The value in the name,value pair.
        """

    def putBooleans(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JBoolean]):
        """
        Associates a boolean array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JBoolean] value: The value in the name,value pair.
        """

    def putByte(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JByte, int]):
        """
        Associates a byte value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JByte or int value: The value in the name,value pair.
        """

    def putBytes(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JByte]):
        """
        Associates a byte array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JByte] value: The value in the name,value pair.
        """

    def putColor(self, name: typing.Union[java.lang.String, str], value: java.awt.Color):
        """
        Associates a Color value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param java.awt.Color value: The value in the name,value pair.
        """

    def putDate(self, name: typing.Union[java.lang.String, str], value: java.util.Date):
        """
        Associates a Date value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param java.util.Date value: The value in the name,value pair.
        """

    def putDouble(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JDouble, float]):
        """
        Associates a double value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JDouble or float value: The value in the name,value pair.
        """

    def putDoubles(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JDouble]):
        """
        Associates a double value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JDouble] value: The value in the name,value pair.
        """

    def putEnum(self, name: typing.Union[java.lang.String, str], value: java.lang.Enum[typing.Any]):
        """
        Associates an Enum with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param java.lang.Enum[typing.Any] value: The Enum value in the name,value pair.
        """

    def putFile(self, name: typing.Union[java.lang.String, str], value: jpype.protocol.SupportsPath):
        """
        Associates a File value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.protocol.SupportsPath value: The value in the name,value pair.
        """

    def putFloat(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JFloat, float]):
        """
        Associates a float value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JFloat or float value: The value in the name,value pair.
        """

    def putFloats(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JFloat]):
        """
        Associates a float array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JFloat] value: The value in the name,value pair.
        """

    def putFont(self, name: typing.Union[java.lang.String, str], value: java.awt.Font):
        """
        Associates a Font value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param java.awt.Font value: The value in the name,value pair.
        """

    def putGProperties(self, name: typing.Union[java.lang.String, str], value: GProperties):
        """
        Associates a sub SaveState value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param GProperties value: The value in the name,value pair.
        """

    def putInt(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Associates an integer value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JInt or int value: The value in the name,value pair.
        """

    def putInts(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JInt]):
        """
        Associates an integer array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JInt] value: The value in the name,value pair.
        """

    def putKeyStroke(self, name: typing.Union[java.lang.String, str], value: javax.swing.KeyStroke):
        """
        Associates a KeyStroke value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param javax.swing.KeyStroke value: The value in the name,value pair.
        """

    def putLong(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Associates a long value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JLong or int value: The value in the name,value pair.
        """

    def putLongs(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JLong]):
        """
        Associates a long array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JLong] value: The value in the name,value pair.
        """

    def putShort(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JShort, int]):
        """
        Associates a short value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JShort or int value: The value in the name,value pair.
        """

    def putShorts(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[jpype.JShort]):
        """
        Associates a short array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[jpype.JShort] value: The value in the name,value pair.
        """

    def putString(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Associates a String value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param java.lang.String or str value: The value in the name,value pair.
        """

    def putStrings(self, name: typing.Union[java.lang.String, str], value: jpype.JArray[java.lang.String]):
        """
        Associates a String array with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param jpype.JArray[java.lang.String] value: The value in the name,value pair.
        """

    def putXmlElement(self, name: typing.Union[java.lang.String, str], element: org.jdom.Element):
        """
        Adds an XML element to the
        this GProperties. Used by plugins that have more
        complicated state information that needs to be saved.
        
        :param java.lang.String or str name: the name to associate with the element
        :param org.jdom.Element element: XML element which is the root of an
        XML sub-tree.
        """

    def remove(self, name: typing.Union[java.lang.String, str]):
        """
        Remove the object identified by the given name
        
        :param java.lang.String or str name: the name of the property to remove
        """

    def saveToJson(self) -> com.google.gson.JsonObject:
        """
        Save this object to an JsonObject
        
        :return: JsonObject containing the properties
        :rtype: com.google.gson.JsonObject
        """

    def saveToJsonFile(self, file: jpype.protocol.SupportsPath):
        """
        Outputs this GProperties to a file using Json
         
        
        For example, a GProperties that is created with:
         
        ss = new GProperties("foo")
            ss.putString("Name", "Bob");
            ss.putBoolean("Retired", true);
            ss.putInt("Age", 65);
            ss.putEnum("Endian", Endian.BIG);
        
        would produce a Json file with the following text
        
        {
        "GPROPERTIES NAME": "foo",
        "VALUES": {
            "Name": "Bob"
            "Retired": true,
            "Age": 65,
            "Endian": "BIG",
        },
        "TYPES": {
            "Name": "String"
            "Retired": "boolean",
            "Age": "int",
            "Endian": "enum",
        },    
        "ENUM CLASSES": {
            "Endian": "ghidra.program.model.lang.Endian"
        }
        }
         
        
        :param jpype.protocol.SupportsPath file: the file to save to
        :raises IOException: if an error occurs writing to the given file
        """

    def saveToXml(self) -> org.jdom.Element:
        """
        Save this object to an XML element.
        
        :return: Element XML element containing the properties
        :rtype: org.jdom.Element
        """

    def saveToXmlFile(self, file: jpype.protocol.SupportsPath):
        """
        Write the properties to a file as XML
        
        :param jpype.protocol.SupportsPath file: the file to write to.
        :raises IOException: if the file could not be written
        """

    def size(self) -> int:
        """
        Return the number of properties in this GProperties
        
        :return: The number of properties in this GProperties
        :rtype: int
        """

    @property
    def names(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def gProperties(self) -> GProperties:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def xmlElement(self) -> org.jdom.Element:
        ...


class JSonProperties(GProperties):
    """
    A convenience class for creating a GProperties object from a file containing JSon data
    generated from :meth:`GProperties.saveToJsonFile(File) <GProperties.saveToJsonFile>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath):
        ...


class SaveState(XmlProperties):
    """
    Class for saving name/value pairs as XML or Json.  Classes that want to be
    able to save their state can do so using the SaveState object.
    The idea is that each state variable in the class
    is first saved into a SaveState object via a String key.  Then the SaveState
    object is written out as XML or Json.  When the save state object is
    restored, the SaveState object is constructed with an XML Element or JsonObject
    that contains all of the name/value pairs. Since the "get" methods require
    a default value, the object that is recovering its state variables
    will be successfully initialized even if
    the given key,value pair is not found in the SaveState object.
     
    *Note: Names for options are assumed to be unique. When a putXXX()
    method is called, if a value already exists for a name, it will
    be overwritten.*
     
    
    The SaveState supports the following types:
     
        java primitives
        arrays of java primitives
        String
        Color
        Font
        KeyStroke
        File
        Date
        Enum
        SaveState (values can be nested SaveStates)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates a new SaveState object with a non-default name.  The name serves no real purpose
        other than as a hint as to what the SaveState represents
        
        :param java.lang.String or str name: of the state
        """

    @typing.overload
    def __init__(self):
        """
        Default Constructor for SaveState; uses "SAVE_STATE" as the
        name of the state.
        
        
        .. seealso::
        
            | :obj:`java.lang.Object.Object()`
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Construct a SaveState from a file containing XML from a previously saved SaveState.
        
        :param jpype.protocol.SupportsPath file: the file containing the XML to read.
        :raises IOException: if the file can't be read or is not formatted properly for a SaveState
        """

    @typing.overload
    def __init__(self, element: org.jdom.Element):
        ...

    def getSaveState(self, name: typing.Union[java.lang.String, str]) -> SaveState:
        """
        Returns the sub SaveState associated with the
        given name.
        
        :param java.lang.String or str name: The name associated with the desired Element.
        :return: The SaveState object associated with the
        given name.
        :rtype: SaveState
        """

    def putSaveState(self, name: typing.Union[java.lang.String, str], value: SaveState):
        """
        Associates a sub SaveState value with the given name.
        
        :param java.lang.String or str name: The name in the name,value pair.
        :param SaveState value: The value in the name,value pair.
        """

    def saveToFile(self, file: jpype.protocol.SupportsPath):
        """
        Write the saveState to a file as XML
        
        :param jpype.protocol.SupportsPath file: the file to write to.
        :raises IOException: if the file could not be written
        """

    @property
    def saveState(self) -> SaveState:
        ...



__all__ = ["ThemeFontOption", "SubOptions", "ThemeColorOption", "Options", "EditorStateFactory", "Option", "NoRegisteredEditorPropertyEditor", "AbstractOptions", "WrappedDate", "WrappedColor", "CustomOptionsEditor", "PropertyText", "FileOptions", "OptionsChangeListener", "WrappedKeyStroke", "EditorState", "ErrorPropertyEditor", "WrappedActionTrigger", "OptionsEditor", "WrappedOption", "WrappedFont", "CustomOption", "ActionTrigger", "PreferenceState", "ToolOptions", "EnumEditor", "PropertySelector", "PropertyBoolean", "WrappedFile", "OptionType", "WrappedCustomOption", "XmlProperties", "GProperties", "JSonProperties", "SaveState"]
