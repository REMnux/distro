from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing.event # type: ignore


T = typing.TypeVar("T")


class IntegerSignednessFormattingModeSettingsDefinition(EnumSettingsDefinition):
    """
    The settings definition for the numeric display format for handling signed values.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[IntegerSignednessFormattingModeSettingsDefinition]
    DEF_SIGNED: typing.Final[IntegerSignednessFormattingModeSettingsDefinition]
    DEF_UNSIGNED: typing.Final[IntegerSignednessFormattingModeSettingsDefinition]

    def getDisplayChoice(self, settings: Settings) -> str:
        ...

    def getFormatMode(self, settings: Settings) -> ghidra.util.SignednessFormatMode:
        """
        Returns the format based on the specified settings
        
        :param Settings settings: the instance settings or null for default value.
        :return: the format mode
        :rtype: ghidra.util.SignednessFormatMode
        """

    def setDisplayChoice(self, settings: Settings, choice: typing.Union[java.lang.String, str]):
        """
        Sets the settings object to the enum value indicating the specified choice as a string.
        
        :param Settings settings: the settings to store the value.
        :param java.lang.String or str choice: enum string representing a choice in the enum.
        """

    def setFormatMode(self, settings: Settings, mode: ghidra.util.SignednessFormatMode):
        """
        Set, or clear if ``mode`` is null, the new mode in the provided settings
        
        :param Settings settings: settings object
        :param ghidra.util.SignednessFormatMode mode: new value to assign, or null to clear
        """

    @property
    def formatMode(self) -> ghidra.util.SignednessFormatMode:
        ...

    @property
    def displayChoice(self) -> java.lang.String:
        ...


class NumberSettingsDefinition(SettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]

    def allowNegativeValue(self) -> bool:
        """
        Determine if negative values are permitted.
        
        :return: true if negative values are permitted, else false.
        :rtype: bool
        """

    def getMaxValue(self) -> java.math.BigInteger:
        """
        Get the maximum value permitted.  The absolute value of the setting may not exceed this value.
        
        :return: maximum value permitted
        :rtype: java.math.BigInteger
        """

    def getValue(self, settings: Settings) -> int:
        """
        Gets the value for this SettingsDefinition given a Settings object.
        
        :param Settings settings: the set of Settings values for a particular location or null for default value.
        :return: the value for this settings object given the context.
        :rtype: int
        """

    def isHexModePreferred(self) -> bool:
        """
        Determine if hexidecimal entry/display is preferred due to the
        nature of the setting (e.g., mask)
        
        :return: true if hex preferred over decimal, else false
        :rtype: bool
        """

    def setValue(self, settings: Settings, value: typing.Union[jpype.JLong, int]):
        """
        Sets the given value into the given settings object using this settingsDefinition as the key.
        
        :param Settings settings: the settings object to store the value in.
        :param jpype.JLong or int value: the value to store in the settings object using this settingsDefinition as the key.
        """

    @property
    def maxValue(self) -> java.math.BigInteger:
        ...

    @property
    def hexModePreferred(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class BooleanSettingsDefinition(SettingsDefinition):
    """
    The inteface for SettingsDefinitions that have boolean values.  SettingsDefinitions
    objects are used as keys into Settings objects that contain the values using a name-value
    type storage mechanism.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getValue(self, settings: Settings) -> bool:
        """
        gets the value for this SettingsDefinition given a Settings object.
        
        :param Settings settings: the set of Settings values for a particular location or null for default value.
        :return: the values for this settings object given the context.
        :rtype: bool
        """

    def setValue(self, settings: Settings, value: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the given value into the given settings object using this settingsDefinition as the key.
        
        :param Settings settings: the settings object to store the value in.
        :param jpype.JBoolean or bool value: the value to store in the settings object using this settingsDefinition as the key.
        """

    @property
    def value(self) -> jpype.JBoolean:
        ...


class StringSettingsDefinition(SettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]

    def addPreferredValues(self, settingsOwner: java.lang.Object, set: java.util.Set[java.lang.String]) -> bool:
        """
        Add preferred setting values to the specified set as obtained from the specified
        settingsOwner.
        
        :param java.lang.Object settingsOwner: settings owner from which a definition may query preferred values.
        Supported values are specific to this settings definition.  An unsupported settingsOwner
        will return false.
        :param java.util.Set[java.lang.String] set: value set to which values should be added
        :return: true if settingsOwner is supported and set updated, else false.
        :rtype: bool
        """

    def getSuggestedValues(self, settings: Settings) -> jpype.JArray[java.lang.String]:
        """
        Get suggested setting values
        
        :param Settings settings: settings object
        :return: suggested settings or null if none or unsupported;
        :rtype: jpype.JArray[java.lang.String]
        """

    def getValue(self, settings: Settings) -> str:
        """
        Gets the value for this SettingsDefinition given a Settings object.
        
        :param Settings settings: the set of Settings values for a particular location or null for default value.
        :return: the value for this settings object given the context.
        :rtype: str
        """

    def setValue(self, settings: Settings, value: typing.Union[java.lang.String, str]):
        """
        Sets the given value into the given settings object using this settingsDefinition as the key.
        
        :param Settings settings: the settings object to store the value in.
        :param java.lang.String or str value: the value to store in the settings object using this settingsDefinition as the key.
        """

    def supportsSuggestedValues(self) -> bool:
        """
        Determine if this settings definition supports suggested values.
        See :meth:`getSuggestedValues(Settings) <.getSuggestedValues>`.
        
        :return: true if suggested values are supported, else false.
        :rtype: bool
        """

    @property
    def value(self) -> java.lang.String:
        ...

    @property
    def suggestedValues(self) -> jpype.JArray[java.lang.String]:
        ...


class EnumSettingsDefinition(SettingsDefinition):
    """
    Interface for a SettingsDefinition with enumerated values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getChoice(self, settings: Settings) -> int:
        """
        Returns the current value for this settings
        
        :param Settings settings: The settings to search
        :return: the value for the settingsDefintions
        :rtype: int
        """

    def getDisplayChoice(self, value: typing.Union[jpype.JInt, int], settings: Settings) -> str:
        """
        Returns the String for the given enum value
        
        :param jpype.JInt or int value: the value to get a display string for
        :param Settings settings: the instance settings which may affect the results
        :return: the display string for the given settings.
        :rtype: str
        """

    def getDisplayChoices(self, settings: Settings) -> jpype.JArray[java.lang.String]:
        """
        Gets the list of choices as strings based on the current settings
        
        :param Settings settings: the instance settings
        :return: an array of strings which represent valid choices based on the current
        settings.
        :rtype: jpype.JArray[java.lang.String]
        """

    def setChoice(self, settings: Settings, value: typing.Union[jpype.JInt, int]):
        """
        Sets the given value into the settings object using this definition as a key
        
        :param Settings settings: the settings to store the value.
        :param jpype.JInt or int value: the settings value to be stored.
        """

    @property
    def displayChoices(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def choice(self) -> jpype.JInt:
        ...


class FloatingPointPrecisionSettingsDefinition(EnumSettingsDefinition):
    """
    SettingsDefinition to define the number of digits of precision to show. The value 
    is rendered to thousandths, 3 digits of precision, by default.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[FloatingPointPrecisionSettingsDefinition]
    """
    Default definition.
    """

    MAX_PRECISION: typing.Final[jpype.JInt]

    def getChoice(self, displayChoice: typing.Union[java.lang.String, str], settings: Settings) -> int:
        ...

    def getPrecision(self, settings: Settings) -> int:
        ...

    def setPrecision(self, settings: Settings, digits: typing.Union[jpype.JInt, int]):
        ...

    @property
    def precision(self) -> jpype.JInt:
        ...


class SettingsImpl(Settings, java.io.Serializable):
    """
    Basic implementation of the Settings object
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_SETTINGS: typing.Final[Settings]

    @typing.overload
    def __init__(self):
        """
        Construct a new SettingsImpl.
        """

    @typing.overload
    def __init__(self, allowedSettingPredicate: java.util.function.Predicate[java.lang.String]):
        """
        Construct a new SettingsImpl with a modification predicate.
        
        :param java.util.function.Predicate[java.lang.String] allowedSettingPredicate: callback for checking an allowed setting modification
        """

    @typing.overload
    def __init__(self, settings: Settings):
        """
        Construct a new SettingsImpl object.  If settings object is specified this
        settings will copy all name/value pairs and underlying defaults.
        
        :param Settings settings: the settings object to copy
        """

    @typing.overload
    def __init__(self, immutable: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new SettingsImpl.
        
        :param jpype.JBoolean or bool immutable: if true settings are immutable with the exception of
        setting its default settings.  If false settings may be modified.
        """

    @typing.overload
    def __init__(self, listener: javax.swing.event.ChangeListener, changeSourceObj: java.lang.Object):
        """
        Construct a new SettingsImpl with the given listener
        
        :param javax.swing.event.ChangeListener listener: object to be notified as settings values change
        :param java.lang.Object changeSourceObj: source object to be associated with change events
        """

    def setDefaultSettings(self, settings: Settings):
        ...


class JavaEnumSettingsDefinition(EnumSettingsDefinition, typing.Generic[T]):
    """
    A :obj:`SettingsDefinition` implementation that uses a real java :obj:`Enum`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, settingName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], defaultValue: T):
        """
        Creates a new :obj:`JavaEnumSettingsDefinition`.
        
        :param java.lang.String or str settingName: String that specifies how this setting is stored
        :param java.lang.String or str name: Descriptive name of this setting
        :param java.lang.String or str description: Longer description
        :param T defaultValue: Enum instance that will be returned when this :obj:`SettingsDefinition`
        has not been specified yet.
        """

    def getDefaultEnum(self) -> T:
        """
        Returns the Enum instance that is the default Enum for this :obj:`SettingsDefinition`.
        
        :return: Enum
        :rtype: T
        """

    def getEnumByOrdinal(self, ordinal: typing.Union[jpype.JInt, int]) -> T:
        """
        Returns the Enum instance that corresponds to the specified ordinal value.
        
        :param jpype.JInt or int ordinal: integer that corresponds to an Enum.
        :return: Enum
        :rtype: T
        """

    @typing.overload
    def getEnumValue(self, settings: Settings) -> T:
        """
        Returns an enum instance that corresponds to the setting stored, or the
        :meth:`default enum <.getDefaultEnum>` if the setting has not been assigned yet.
        
        :param Settings settings: :obj:`Settings` object that stores the settings values.
        :return: Enum<T> value, or :meth:`getDefaultEnum() <.getDefaultEnum>` if not present.
        :rtype: T
        """

    @typing.overload
    def getEnumValue(self, settings: Settings, defaultValueOverride: T) -> T:
        """
        Returns an enum instance that corresponds to the setting stored, or the
        a custom default value if the setting has not been assigned yet.
        
        :param Settings settings: :obj:`Settings` object that stores the settings values.
        :return: Enum<T> value, or the specified defaultValueOveride if not present.
        :rtype: T
        """

    def getOrdinalByString(self, stringValue: typing.Union[java.lang.String, str]) -> int:
        """
        returns the Enum's ordinal using the Enum's string representation.
        
        :param java.lang.String or str stringValue: Enum's string rep
        :return: integer index of the Enum
        :rtype: int
        """

    def setEnumValue(self, settings: Settings, enumValue: T):
        """
        Sets the value of this :obj:`SettingsDefinition` using the ordinal of the specified
        enum.
        
        :param Settings settings: Where :obj:`SettingsDefinition` values are stored.
        :param T enumValue: Enum to store
        """

    @property
    def enumByOrdinal(self) -> T:
        ...

    @property
    def enumValue(self) -> T:
        ...

    @property
    def ordinalByString(self) -> jpype.JInt:
        ...

    @property
    def defaultEnum(self) -> T:
        ...


class Settings(java.lang.Object):
    """
    Settings objects store name-value pairs.  Each SettingsDefinition defines one
    or more names to use to store values in settings objects.  Exactly what type
    of value and how to interpret the value is done by the SettingsDefinition object.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_STRING_ARRAY: typing.Final[jpype.JArray[java.lang.String]]

    def clearAllSettings(self):
        """
        Removes all name-value pairs from this settings object
        """

    def clearSetting(self, name: typing.Union[java.lang.String, str]):
        """
        Removes any value associated with the given name
        
        :param java.lang.String or str name: the key to remove any association
        """

    def getDefaultSettings(self) -> Settings:
        """
        Returns the underlying default settings for these settings or null if there are none
        
        :return: underlying default settings or null
        :rtype: Settings
        """

    def getLong(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Gets the Long value associated with the given name
        
        :param java.lang.String or str name: the key used to retrieve a value
        :return: the Long value for a key
        :rtype: int
        """

    def getNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get this list of keys that currently have values associated with them
        
        :return: an array of string keys.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getString(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the String value associated with the given name
        
        :param java.lang.String or str name: the key used to retrieve a value
        :return: the String value for a key
        :rtype: str
        """

    def getSuggestedValues(self, settingsDefinition: StringSettingsDefinition) -> jpype.JArray[java.lang.String]:
        """
        Get an array of suggested values for the specified string settings definition.
        
        :param StringSettingsDefinition settingsDefinition: string settings definition
        :return: suggested values array (may be empty)
        :rtype: jpype.JArray[java.lang.String]
        """

    def getValue(self, name: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Gets the object associated with the given name
        
        :param java.lang.String or str name: the key used to retrieve a value
        :return: the object associated with a given key
        :rtype: java.lang.Object
        """

    def isChangeAllowed(self, settingsDefinition: SettingsDefinition) -> bool:
        """
        Determine if a settings change corresponding to the specified 
        settingsDefinition is permitted.
        
        :param SettingsDefinition settingsDefinition: settings definition
        :return: true if change permitted else false
        :rtype: bool
        """

    def isEmpty(self) -> bool:
        """
        Returns true if there are no key-value pairs stored in this settings object.
        This is not a reflection of the underlying default settings which may still
        contain a key-value pair when this settings object is empty.
        
        :return: true if there are no key-value pairs stored in this settings object
        :rtype: bool
        """

    def setLong(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        """
        Associates the given long value with the name.
        Note that an attempted setting change may be ignored if prohibited
        (e.g., immutable Settings, undefined setting name).
        
        :param java.lang.String or str name: the key
        :param jpype.JLong or int value: the value associated with the key
        """

    def setString(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Associates the given String value with the name.
        Note that an attempted setting change may be ignored if prohibited
        (e.g., immutable Settings, undefined setting name).
        
        :param java.lang.String or str name: the key
        :param java.lang.String or str value: the value associated with the key
        """

    def setValue(self, name: typing.Union[java.lang.String, str], value: java.lang.Object):
        """
        Associates the given object with the name.
        Note that an attempted setting change may be ignored if prohibited
        (e.g., immutable Settings, undefined setting name).
        
        :param java.lang.String or str name: the key
        :param java.lang.Object value: the value to associate with the key
        """

    @property
    def names(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def changeAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def suggestedValues(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def defaultSettings(self) -> Settings:
        ...


class FormatSettingsDefinition(EnumSettingsDefinition):
    """
    The settings definition for the numeric display format
    """

    class_: typing.ClassVar[java.lang.Class]
    HEX: typing.Final = 0
    DECIMAL: typing.Final = 1
    BINARY: typing.Final = 2
    OCTAL: typing.Final = 3
    CHAR: typing.Final = 4
    DEF_HEX: typing.Final[FormatSettingsDefinition]
    DEF_DECIMAL: typing.Final[FormatSettingsDefinition]
    DEF_BINARY: typing.Final[FormatSettingsDefinition]
    DEF_OCTAL: typing.Final[FormatSettingsDefinition]
    DEF_CHAR: typing.Final[FormatSettingsDefinition]
    DEF: typing.Final[FormatSettingsDefinition]

    def getDisplayChoice(self, settings: Settings) -> str:
        ...

    def getFormat(self, settings: Settings) -> int:
        """
        Returns the format based on the specified settings
        
        :param Settings settings: the instance settings or null for default value.
        :return: the format value (HEX, DECIMAL, BINARY, OCTAL, CHAR), or HEX if invalid
        data in the FORMAT settings value
        :rtype: int
        """

    def getRadix(self, settings: Settings) -> int:
        """
        Returns the numeric radix associated with the format identified by the specified settings.
        
        :param Settings settings: the instance settings.
        :return: the format radix
        :rtype: int
        """

    def getRepresentationPostfix(self, settings: Settings) -> str:
        """
        Returns a descriptive string suffix that should be appended after converting a value
        using the radix returned by :meth:`getRadix(Settings) <.getRadix>`.
        
        :param Settings settings: the instance settings
        :return: string suffix, such as "h" for HEX, "o" for octal
        :rtype: str
        """

    def setDisplayChoice(self, settings: Settings, choice: typing.Union[java.lang.String, str]):
        """
        Sets the settings object to the enum value indicating the specified choice as a string.
        
        :param Settings settings: the settings to store the value.
        :param java.lang.String or str choice: enum string representing a choice in the enum.
        """

    @property
    def radix(self) -> jpype.JInt:
        ...

    @property
    def format(self) -> jpype.JInt:
        ...

    @property
    def representationPostfix(self) -> java.lang.String:
        ...

    @property
    def displayChoice(self) -> java.lang.String:
        ...


class SettingsDefinition(java.lang.Object):
    """
    Generic interface for defining display options on data and dataTypes.  Uses
    Settings objects to store values which are interpreted by SettingsDefinition objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self, settings: Settings):
        """
        Removes any values in the given settings object assocated with this settings definition
        
        :param Settings settings: the settings object to be cleared.
        """

    @staticmethod
    def concat(settings: jpype.JArray[SettingsDefinition], *additional: SettingsDefinition) -> jpype.JArray[SettingsDefinition]:
        """
        Create a new list of :obj:`SettingsDefinition`s by concat'ing a base list with
        a var-arg'ish additional list of setting defs.  Any additional duplicates are discarded.
        
        :param jpype.JArray[SettingsDefinition] settings: List of settings defs.
        :param jpype.JArray[SettingsDefinition] additional: More settings defs to add
        :return: new array with all the settings defs joined together.
        :rtype: jpype.JArray[SettingsDefinition]
        """

    def copySetting(self, srcSettings: Settings, destSettings: Settings):
        """
        Copies any setting value associated with this settings definition from the
        srcSettings settings to the destSettings.
        
        :param Settings srcSettings: the settings to be copied
        :param Settings destSettings: the settings to be updated.
        """

    @staticmethod
    def filterSettingsDefinitions(definitions: jpype.JArray[SettingsDefinition], filter: java.util.function.Predicate[SettingsDefinition]) -> jpype.JArray[SettingsDefinition]:
        """
        Get datatype settings definitions for the specified datatype exclusive of any default-use-only definitions.
        
        :param jpype.JArray[SettingsDefinition] definitions: settings definitions to be filtered
        :param java.util.function.Predicate[SettingsDefinition] filter: callback which determines if definition should be included in returned array
        :return: filtered settings definitions
        :rtype: jpype.JArray[SettingsDefinition]
        """

    def getDescription(self) -> str:
        """
        Returns a description of this settings definition
        
        :return: setting description
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the display name of this SettingsDefinition
        
        :return: display name for setting
        :rtype: str
        """

    def getStorageKey(self) -> str:
        """
        Get the :obj:`Settings` key which is used when storing a key/value entry.
        
        :return: settings storage key
        :rtype: str
        """

    def getValueString(self, settings: Settings) -> str:
        """
        Get the setting value as a string which corresponds to this definition.
        A default value string will be returned if a setting has not been stored.
        
        :param Settings settings: settings
        :return: value string or null if not set and default has not specified by this definition
        :rtype: str
        """

    def hasSameValue(self, settings1: Settings, settings2: Settings) -> bool:
        """
        Check two settings for equality which correspond to this 
        settings definition.
        
        :param Settings settings1: first settings
        :param Settings settings2: second settings
        :return: true if the same else false
        :rtype: bool
        """

    def hasValue(self, setting: Settings) -> bool:
        """
        Determine if a setting value has been stored
        
        :param Settings setting: stored settings
        :return: true if a value has been stored, else false
        :rtype: bool
        """

    @property
    def valueString(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def storageKey(self) -> java.lang.String:
        ...



__all__ = ["IntegerSignednessFormattingModeSettingsDefinition", "NumberSettingsDefinition", "BooleanSettingsDefinition", "StringSettingsDefinition", "EnumSettingsDefinition", "FloatingPointPrecisionSettingsDefinition", "SettingsImpl", "JavaEnumSettingsDefinition", "Settings", "FormatSettingsDefinition", "SettingsDefinition"]
