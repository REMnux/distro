from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import generic.theme.laf
import ghidra.util.classfinder
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.plaf # type: ignore
import javax.swing.text # type: ignore


T = typing.TypeVar("T")


class AbstractThemeReader(java.lang.Object):
    """
    Abstract base class for reading theme values either in sections (theme property files) or no
    sections (theme files)
    """

    @typing.type_check_only
    class Section(java.lang.Object):
        """
        Represents all the value found in a section of the theme properties file. Sections are
        defined by a line containing just "[section name]"
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, sectionName: typing.Union[java.lang.String, str], lineNumber: typing.Union[jpype.JInt, int]):
            """
            Constructor sectionName the section name
            
            :param java.lang.String or str sectionName: the name of this section
            :param jpype.JInt or int lineNumber: the line number in the file where the section started
            """

        def add(self, line: typing.Union[java.lang.String, str], lineNumber: typing.Union[jpype.JInt, int]):
            """
            Adds a raw line from the file to this section. The line will be parsed into a a
            key-value pair.
            
            :param java.lang.String or str line: the line to be added/parsed
            :param jpype.JInt or int lineNumber: the line number in the file for this line
            """

        def getKeys(self) -> java.util.Set[java.lang.String]:
            """
            Returns a set of all keys in the section
            
            :return: a set of all keys in the section
            :rtype: java.util.Set[java.lang.String]
            """

        @typing.overload
        def getLineNumber(self, key: typing.Union[java.lang.String, str]) -> int:
            """
            Returns the line number in the original file where the key was parsed
            
            :param java.lang.String or str key: the key to get a line number for
            :return: the line number in the original file where the key was parsed
            :rtype: int
            """

        @typing.overload
        def getLineNumber(self) -> int:
            """
            Returns the line number in the file where this section began.
            
            :return: the line number in the file where this section began.
            :rtype: int
            """

        def getName(self) -> str:
            """
            Returns the name of this section
            
            :return: the name of this section
            :rtype: str
            """

        def getValue(self, key: typing.Union[java.lang.String, str]) -> str:
            """
            Returns the value for the given key.
            
            :param java.lang.String or str key: the key to get a value for
            :return: the value for the given key
            :rtype: str
            """

        def isEmpty(self) -> bool:
            """
            Returns true if the section is empty.
            
            :return: true if the section is empty.
            :rtype: bool
            """

        def remove(self, key: typing.Union[java.lang.String, str]):
            """
            Removes the value with the given key
            
            :param java.lang.String or str key: the key to remove
            """

        @property
        def keys(self) -> java.util.Set[java.lang.String]:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def lineNumber(self) -> jpype.JInt:
            ...

        @property
        def value(self) -> java.lang.String:
            ...

        @property
        def empty(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getErrors(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of errors found while parsing
        
        :return: a list of errors found while parsing
        :rtype: java.util.List[java.lang.String]
        """

    @property
    def errors(self) -> java.util.List[java.lang.String]:
        ...


class GThemeDefaults(java.lang.Object):
    """
    This class contains many suitable default values for commonly used concepts.  See each static
    class below.
     
    
    The values in this class can be used where standard colors are desired.   For example, where
    clients used to hard-code black for the font color:
     
    ``
    JLabel label = new JLabel():
    label.setColor(Color.BLACK);
    ``
     
    Can instead be programmed to use the system's current theme font color instead:
     
    ``
    import generic.theme.GThemeDefaults.Colors;
    
    ...
    
    JLabel label = new JLabel():
    label.setColor(Colors.FOREGROUND);
    ``
     
    Note that in the second example, you can use the shorthand version of the values in this class
    as long as you import them correctly.  This means you do not have to use this form:
     
    ``
    component.setColor(GThemeDefaults.Colors.FOREGROUND);
    ``
    """

    class Ids(java.lang.Object):

        class Fonts(java.lang.Object):

            class_: typing.ClassVar[java.lang.Class]
            MONOSPACED: typing.Final = "font.monospaced"

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class Colors(java.lang.Object):
        """
        Colors mapped to common system widget concepts, such as foreground, background, border, etc.
        """

        class Tables(java.lang.Object):
            """
            Color values to use for tables
            """

            class_: typing.ClassVar[java.lang.Class]
            ERROR_SELECTED: typing.Final[GColor]
            ERROR_UNSELECTED: typing.Final[GColor]
            UNEDITABLE_SELECTED: typing.Final[GColor]
            UNEDITABLE_UNSELECTED: typing.Final[GColor]

            def __init__(self):
                ...


        class Viewport(java.lang.Object):

            class_: typing.ClassVar[java.lang.Class]
            UNEDITABLE_BACKGROUND: typing.Final[GColor]
            """
            By default the system :obj:`JViewport`s use BACKGROUND for their background, which
            is the primary background color (typically white on light themes).  Some clients
            would like the background color to match the uneditable background color used by
            :obj:`JPanel`.   This color allows the empty space in the viewport to  match the
            parent panel color.
            """


            def __init__(self):
                ...


        class Tooltips(java.lang.Object):
            """
            Color values to use with tooltips
            """

            class_: typing.ClassVar[java.lang.Class]
            BACKGROUND: typing.Final[GColor]
            FOREGROUND: typing.Final[GColor]

            def __init__(self):
                ...


        class Messages(java.lang.Object):
            """
            'Messages' is primarily used by system dialogs to display status.  That the colors are
            used for foregrounds is implied.
            """

            class_: typing.ClassVar[java.lang.Class]
            NORMAL: typing.Final[GColor]
            ERROR: typing.Final[GColor]
            HINT: typing.Final[GColor]
            WARNING: typing.Final[GColor]

            def __init__(self):
                ...


        class Palette(java.lang.Object):
            """
            Generic palette colors, using color names, that may be changed along with the theme.
            These are not all defined palette colors, but some of the more commonly used colors.
            """

            class_: typing.ClassVar[java.lang.Class]
            NO_COLOR: typing.Final[java.awt.Color]
            """
            Transparent color
            """

            BLACK: typing.Final[GColor]
            BLUE: typing.Final[GColor]
            CYAN: typing.Final[GColor]
            DARK_GRAY: typing.Final[GColor]
            GOLD: typing.Final[GColor]
            GRAY: typing.Final[GColor]
            GREEN: typing.Final[GColor]
            LAVENDER: typing.Final[GColor]
            LIGHT_GRAY: typing.Final[GColor]
            LIME: typing.Final[GColor]
            MAGENTA: typing.Final[GColor]
            MAROON: typing.Final[GColor]
            ORANGE: typing.Final[GColor]
            PINK: typing.Final[GColor]
            PURPLE: typing.Final[GColor]
            RED: typing.Final[GColor]
            SILVER: typing.Final[GColor]
            TEAL: typing.Final[GColor]
            WHITE: typing.Final[GColor]
            YELLOW: typing.Final[GColor]

            def __init__(self):
                ...

            @staticmethod
            def getColor(name: typing.Union[java.lang.String, str]) -> GColor:
                """
                Returns a new :obj:`GColor` for the given palette name.
                 
                
                For a list of supported palette IDs, see ``gui.palette.theme.properties``.
                 
                
                It is preferred to use the static colors defined in :obj:`Palette` when possible, as
                it prevents excess object creation.  This method should be used when the desired
                palette color is not in that list.  Further, this method should only be called once
                per use, such as when initializing a constant value.
                
                :param java.lang.String or str name: the palette entry name
                :return: the GColor
                :rtype: GColor
                """


        class_: typing.ClassVar[java.lang.Class]
        BACKGROUND: typing.Final[GColor]
        FOREGROUND: typing.Final[GColor]
        FOREGROUND_DISABLED: typing.Final[GColor]
        CURSOR: typing.Final[GColor]
        ERROR: typing.Final[GColor]
        BORDER: typing.Final[GColor]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ThemePropertyFileReader(AbstractThemeReader):
    """
    Reads the values for a single theme.properities file
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: generic.jar.ResourceFile):
        """
        Constructor for when the theme.properties file is a :obj:`ResourceFile`
        
        :param generic.jar.ResourceFile file: the :obj:`ResourceFile` esourceFileto read
        :raises IOException: if an I/O error occurs reading the file
        """

    def getDarkDefaultValues(self) -> GThemeValueMap:
        """
        Returns the map of dark defaults values.
        
        :return: the map of dark defaults values.
        :rtype: GThemeValueMap
        """

    def getDefaultValues(self) -> GThemeValueMap:
        """
        Returns the map of standard defaults values.
        
        :return: the map of standard defaults values.
        :rtype: GThemeValueMap
        """

    def getLookAndFeelSections(self) -> java.util.Map[LafType, GThemeValueMap]:
        """
        Returns a map of all the custom (look and feel specific) value maps
        
        :return: a map of all the custom (look and feel specific) value maps
        :rtype: java.util.Map[LafType, GThemeValueMap]
        """

    @property
    def defaultValues(self) -> GThemeValueMap:
        ...

    @property
    def lookAndFeelSections(self) -> java.util.Map[LafType, GThemeValueMap]:
        ...

    @property
    def darkDefaultValues(self) -> GThemeValueMap:
        ...


class ThemeEvent(java.lang.Object):
    """
    Event for when a theme value changes;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def hasAnyColorChanged(self) -> bool:
        """
        Returns true if any color value changed.
        
        :return: true if any color value changed.
        :rtype: bool
        """

    def hasAnyFontChanged(self) -> bool:
        """
        Returns true if any font value changed.
        
        :return: true if any font value changed.
        :rtype: bool
        """

    def hasAnyIconChanged(self) -> bool:
        """
        Returns true if any icon value changed.
        
        :return: true if any icon value changed.
        :rtype: bool
        """

    def haveAllValuesChanged(self) -> bool:
        """
        Returns true if all colors, fonts, and icons may have changed. This doesn't guarantee that 
        all the values have actually changed, just that they might have. In other words, a mass
        change occurred (theme change, theme reset, etc.) and any or all values may have changed.
        
        :return: true if all colors, fonts, and icons may have changed.
        :rtype: bool
        """

    def isColorChanged(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the color associated with the given id has changed.
        
        :param java.lang.String or str id: the color id to test if changed
        :return: true if the color associated with the given id has changed
        :rtype: bool
        """

    def isFontChanged(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the font associated with the given id has changed.
        
        :param java.lang.String or str id: the font id to test if changed
        :return: true if the font associated with the given id has changed
        :rtype: bool
        """

    def isIconChanged(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the icon associated with the given id has changed.
        
        :param java.lang.String or str id: the icon id to test if changed
        :return: true if the icon associated with the given id has changed
        :rtype: bool
        """

    def isLookAndFeelChanged(self) -> bool:
        """
        Returns true if the :obj:`LookAndFeel` has changed (theme changed).
        
        :return: true if the :obj:`LookAndFeel` has changed (theme changed).
        :rtype: bool
        """

    @property
    def lookAndFeelChanged(self) -> jpype.JBoolean:
        ...

    @property
    def iconChanged(self) -> jpype.JBoolean:
        ...

    @property
    def fontChanged(self) -> jpype.JBoolean:
        ...

    @property
    def colorChanged(self) -> jpype.JBoolean:
        ...


class BooleanPropertyValue(JavaPropertyValue):
    """
    A Java property value for keys that use boolean values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str], value: typing.Union[java.lang.Boolean, bool]):
        ...

    @staticmethod
    def isBooleanKey(key: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def parse(key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> BooleanPropertyValue:
        ...


class SystemThemeIds(java.lang.Object):
    """
    This class provides a set of IDs that can be used in the application, regardless of which Look
    and Feel (LaF) is being used.
     
    
    Various LaFs have different names for common concepts and even define additional concepts not
    listed here. The values in this class are those the application uses use regardless of the LaF
    being used. When we load a specific LaF, a :obj:`UiDefaultsMapper` specific to that LaF is used
    to map its common LaF ids to these standard system ids. The :obj:`GThemeDefaults` uses these
    system ids to define colors that can be used throughout the application without using these ids
    directly.
     
    
    The ids are assigned to categories as follows:
     
    * CONTROL- these ids are used for colors and fonts for general system components such as
    Buttons, Checkboxes, or anything that doesn't fit into one of the other areas
    * VIEW - these ids are used for the colors and fonts used for widgets that display data
    such as Trees, Tables, TextFieds, and Lists
    * MENU - these ids are used by menu components such as Menus and MenuItems.
    * TOOLTIP - these ids are used just by the tooltip component
    
     
    
    For each of those categories the ids specify a specific property for those components.
     
    *  BG - the background color
    *  FG - the foreground color
    *  BG_SELECTED - the background color when the component is selected
    *  FG_SELECTED - the foreground color when the component is selected
    *  FG_DISABLED - the foreground color when the component is disabled
    *  BG_BORDER - the border color
    *  FONT - the font
    """

    class_: typing.ClassVar[java.lang.Class]
    FONT_CONTROL_ID: typing.Final = "system.font.control"
    FONT_VIEW_ID: typing.Final = "system.font.view"
    FONT_MENU_ID: typing.Final = "system.font.menu"
    BG_CONTROL_ID: typing.Final = "system.color.bg.control"
    BG_VIEW_ID: typing.Final = "system.color.bg.view"
    BG_TOOLTIP_ID: typing.Final = "system.color.bg.tooltip"
    BG_VIEW_SELECTED_ID: typing.Final = "system.color.bg.selected.view"
    BG_BORDER_ID: typing.Final = "system.color.bg.border"
    FG_CONTROL_ID: typing.Final = "system.color.fg.control"
    FG_VIEW_ID: typing.Final = "system.color.fg.view"
    FG_TOOLTIP_ID: typing.Final = "system.color.fg.tooltip"
    FG_VIEW_SELECTED_ID: typing.Final = "system.color.fg.selected.view"
    FG_DISABLED_ID: typing.Final = "system.color.fg.disabled"

    def __init__(self):
        ...


class PropertyFileThemeDefaults(ApplicationThemeDefaults):
    """
    Loads all the system theme.property files that contain all the default color, font, and
    icon values.
    """

    class_: typing.ClassVar[java.lang.Class]


class ApplicationThemeManager(ThemeManager):
    """
    This is the fully functional :obj:`ThemeManager` that manages themes in a application. To
    activate the theme functionality, Applications (or tests) must call
    :meth:`ApplicationThemeManager.initialize() <ApplicationThemeManager.initialize>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getGColorUiResource(self, id: typing.Union[java.lang.String, str]) -> GColorUIResource:
        """
        Gets a UIResource version of the GColor for the given id. Using this method ensures that
        the same instance is used for a given id. This fixes an issue with some
        :obj:`LookAndFeel`s that internally use '==' comparisons.
        
        :param java.lang.String or str id: the id to get a GColorUIResource for
        :return: a GColorUIResource for the given id
        :rtype: GColorUIResource
        """

    @staticmethod
    def initialize():
        """
        Initialized the Theme and its values for the application.
        """

    def refreshGThemeValues(self):
        ...

    def setJavaDefaults(self, map: GThemeValueMap):
        """
        Sets the map of Java default UI values. These are the UI values defined by the current Java
        Look and Feel.
        
        :param GThemeValueMap map: the default theme values defined by the :obj:`LookAndFeel`
        """

    @property
    def gColorUiResource(self) -> GColorUIResource:
        ...


@typing.type_check_only
class ThemeReader(AbstractThemeReader):
    """
    Reads Themes from a file or :obj:`Reader`
    """

    class_: typing.ClassVar[java.lang.Class]

    def readTheme(self) -> GTheme:
        ...


class GColor(java.awt.Color):
    """
    A :obj:`Color` whose value is dynamically determined by looking up its id into a global
    color table that is determined by the active :obj:`GTheme`. 
     
    The idea is for developers to
    not use specific colors in their code, but to instead use a GColor with an id that hints at 
    its use. For example, instead of hard coding a component's background color to white by coding
    "component.setBackground(Color.white)", you would do something like 
    "component.setBackground(new GColor("color.mywidget.bg"). Then in a 
    "[module name].theme.properties" file (located in the module's data directory), you would 
    set the default value by adding this line "color.mywidget.bg = white".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[java.lang.String, str]):
        """
        Construct a GColor with an id that will be used to look up the current color associated with 
        that id, which can be changed at runtime.
        
        :param java.lang.String or str id: the id used to lookup the current value for this color
        """

    def getId(self) -> str:
        """
        Returns the id for this GColor.
        
        :return: the id for this GColor.
        :rtype: str
        """

    def isUnresolved(self) -> bool:
        """
        Returns true if this GColor could not find a value for its color id in the current theme
        and is using the default color as its delegate
        
        :return: true if this GColor could not find a value for its color id in the current theme
        :rtype: bool
        """

    def refresh(self, currentValues: GThemeValueMap):
        """
        Reloads the delegate.
        
        :param GThemeValueMap currentValues: the map of current theme values
        """

    @staticmethod
    def refreshAll(currentValues: GThemeValueMap):
        """
        Static method for notifying all the existing GColors that colors have changed and they
        should reload their cached indirect color.
        
        :param GThemeValueMap currentValues: the map of current theme values
        """

    def toDebugString(self) -> str:
        """
        Generates a more verbose toString()
        
        :return: a more verbose toString()
        :rtype: str
        """

    def toHexString(self) -> str:
        """
        Returns this color as a hex string that starts with '#'
        
        :return: the hex string
        :rtype: str
        """

    def withAlpha(self, newAlpha: typing.Union[jpype.JInt, int]) -> GColor:
        """
        Creates a transparent version of this GColor. If the underlying value of this GColor changes,
        the transparent version will also change.
        
        :param jpype.JInt or int newAlpha: the transparency level for the new color
        :return: a transparent version of this GColor
        :rtype: GColor
        """

    @property
    def unresolved(self) -> jpype.JBoolean:
        ...

    @property
    def id(self) -> java.lang.String:
        ...


class FontValue(ThemeValue[java.awt.Font]):
    """
    A class for storing :obj:`Font` values that have a String id (e.g. font.foo.bar) and either
    a concrete font or a reference id which is the String id of another FontValue that it
    will inherit its font from. So if this class's font value is non-null, the refId will be null
    and if the class's refId is non-null, then the font value will be null.
    """

    class_: typing.ClassVar[java.lang.Class]
    LAF_ID_PREFIX: typing.Final = "laf.font."
    EXTERNAL_LAF_ID_PREFIX: typing.Final = "[laf.font]"
    LAST_RESORT_DEFAULT: typing.Final[java.awt.Font]

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], value: java.awt.Font):
        """
        Constructor used when the FontValue will have a direct :obj:`Font` value. The refId
        will be null.
        
        :param java.lang.String or str id: the id for this FontValue
        :param java.awt.Font value: the :obj:`Font` to associate with the given id
        """

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str]):
        """
        Constructor used when the FontValue will inherit its :obj:`Font` from another FontValue. The
        font value field will be null.
        
        :param java.lang.String or str id: the id for this FontValue
        :param java.lang.String or str refId: the id of another FontValue that this FontValue will inherit from
        """

    @staticmethod
    def fontToString(font: java.awt.Font) -> str:
        """
        Converts a file to a string.
        
        :param java.awt.Font font: the font to convert to a String
        :return: a String that represents the font
        :rtype: str
        """

    def getModifier(self) -> FontModifier:
        ...

    @staticmethod
    def getStyle(styleString: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the Font style int for the given style string
        
        :param java.lang.String or str styleString: the string to convert to a Font style int
        :return: the Font style int for the given style string
        :rtype: int
        """

    @staticmethod
    def isFontKey(key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given key string is a valid external key for a font value
        
        :param java.lang.String or str key: the key string to test
        :return: true if the given key string is a valid external key for a font value
        :rtype: bool
        """

    @staticmethod
    def parse(key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> FontValue:
        """
        Parses the value string into a font or reference and creates a new FontValue using
        the given key and the parse results.
        
        :param java.lang.String or str key: the key to associate the parsed value with
        :param java.lang.String or str value: the font value to parse
        :return: a FontValue with the given key and the parsed value
        :rtype: FontValue
        :raises ParseException: if there is an exception parsing
        """

    @property
    def modifier(self) -> FontModifier:
        ...


class ApplicationThemeDefaults(java.lang.Object):
    """
    Provides theme default values, such as those loaded from ``*.theme.property`` files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDarkValues(self) -> GThemeValueMap:
        """
        Returns the dark default :obj:`GThemeValueMap`
        
        :return: the dark default :obj:`GThemeValueMap`
        :rtype: GThemeValueMap
        """

    def getLightValues(self) -> GThemeValueMap:
        """
        Returns the light default :obj:`GThemeValueMap`
        
        :return: the light default :obj:`GThemeValueMap`
        :rtype: GThemeValueMap
        """

    def getLookAndFeelValues(self, lafType: LafType) -> GThemeValueMap:
        """
        Returns the default values specific to a given Look and Feel
        
        :param LafType lafType: the Look and Feel type
        :return: the default values specific to a given Look and Feel
        :rtype: GThemeValueMap
        """

    @property
    def darkValues(self) -> GThemeValueMap:
        ...

    @property
    def lightValues(self) -> GThemeValueMap:
        ...

    @property
    def lookAndFeelValues(self) -> GThemeValueMap:
        ...


class ThemeListener(java.lang.Object):
    """
    Listener interface for theme changes
    """

    class_: typing.ClassVar[java.lang.Class]

    def themeChanged(self, event: ThemeEvent):
        """
        Called when the theme or any of its values change
        
        :param ThemeEvent event: the :obj:`ThemeEvent` that describes what changed
        """


class ColorChangedThemeEvent(ThemeEvent):
    """
    :obj:`ThemeEvent` for when a color changes for exactly one color id.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, values: GThemeValueMap, color: ColorValue):
        """
        Constructor
        
        :param GThemeValueMap values: the set of theme values used to resolve indirect references
        :param ColorValue color: the new :obj:`ColorValue` for the color id that changed
        """


class HeadlessThemeManager(ThemeManager):
    """
    This is a strange implementation of :obj:`ThemeManager` that is meant to be used in a headless
    environment, but also needs theme properties to have been loaded.  This is needed by any
    application that needs to do theme property validation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def initialize():
        ...


class ThemeManager(java.lang.Object):
    """
    This class manages application themes and their values. The ThemeManager is an abstract
    base class that has two concrete subclasses (and others for testing purposes) -
    StubThemeManager and ApplicationThememManager. The StubThemeManager exists as a placeholder
    until the ApplicationThemeManager is installed via :meth:`ApplicationThemeManager.initialize() <ApplicationThemeManager.initialize>`.
     
    
    The basic idea is that all the colors, fonts, and icons used in an application should be
    accessed indirectly via an "id" string. Then the actual color, font, or icon can be changed
    without changing the source code. The default mapping of the id strings to a value is defined
    in ``<name>.theme.properties`` files which are dynamically discovered by searching the module's
    data directory. Also, these files can optionally define a dark default value for an id which
    would replace the standard default value in the event that the current theme specifies that it
    is a dark theme. Themes are used to specify the application's :obj:`LookAndFeel`, whether or
    not it is dark, and any customized values for colors, fonts, or icons. There are several
    "built-in" themes, one for each supported :obj:`LookAndFeel`, but additional themes can
    be defined and stored in the users application home directory as a ``<name>.theme`` file.
     
    
    Clients that just need to access the colors, fonts, and icons from the theme can use the
    convenience methods in the :obj:`Gui` class.  Clients that need to directly manipulate the
    themes and values will need to directly use the ThemeManager which and be retrieved using the
    static :meth:`getInstance() <.getInstance>` method.
    """

    class_: typing.ClassVar[java.lang.Class]
    THEME_DIR: typing.Final = "themes"

    def __init__(self):
        ...

    def addTheme(self, newTheme: GTheme):
        """
        Adds the given theme to set of all themes.
        
        :param GTheme newTheme: the theme to add
        """

    def addThemeListener(self, listener: ThemeListener):
        """
        Adds a :obj:`ThemeListener` to be notified of theme changes.
        
        :param ThemeListener listener: the listener to be notified
        """

    def adjustFonts(self, amount: typing.Union[jpype.JInt, int]):
        """
        Adjust the size of all fonts by the given amount.
        
        :param jpype.JInt or int amount: the number to add to the current font size;
        """

    def deleteTheme(self, theme: GTheme):
        """
        Removes the theme from the set of all themes. Also, if the theme has an associated
        file, the file will be deleted.
        
        :param GTheme theme: the theme to delete
        """

    def getActiveTheme(self) -> GTheme:
        """
        Returns the active theme.
        
        :return: the active theme.
        :rtype: GTheme
        """

    def getAllThemes(self) -> java.util.Set[GTheme]:
        """
        Returns a set of all known themes.
        
        :return: a set of all known themes.
        :rtype: java.util.Set[GTheme]
        """

    def getApplicationDarkDefaults(self) -> GThemeValueMap:
        """
        Returns the :obj:`GThemeValueMap` containing all the dark default values defined
        in theme.properties files. Note that dark defaults includes light defaults that haven't
        been overridden by a dark default with the same id.
        
        :return: the :obj:`GThemeValueMap` containing all the dark values defined in
        theme.properties files
        :rtype: GThemeValueMap
        """

    def getApplicationLightDefaults(self) -> GThemeValueMap:
        """
        Returns the :obj:`GThemeValueMap` containing all the standard default values defined
        in theme.properties files.
        
        :return: the :obj:`GThemeValueMap` containing all the standard values defined in
        theme.properties files
        :rtype: GThemeValueMap
        """

    def getColor(self, id: typing.Union[java.lang.String, str]) -> java.awt.Color:
        """
        Returns the :obj:`Color` registered for the given id. Will output an error message if
        the id can't be resolved.
        
        :param java.lang.String or str id: the id to get the direct color for
        :return: the :obj:`Color` registered for the given id.
        :rtype: java.awt.Color
        """

    def getCurrentValues(self) -> GThemeValueMap:
        """
        Returns a :obj:`GThemeValueMap` of all current theme values including unsaved changes to the
        theme.
        
        :return: a :obj:`GThemeValueMap` of all current theme values
        :rtype: GThemeValueMap
        """

    @staticmethod
    def getDefaultTheme() -> GTheme:
        """
        Returns the default theme for the current platform.
        
        :return: the default theme for the current platform.
        :rtype: GTheme
        """

    def getDefaults(self) -> GThemeValueMap:
        """
        Returns a :obj:`GThemeValueMap` containing all default values for the current theme. It
        is a combination of application defined defaults and java :obj:`LookAndFeel` defaults.
        
        :return: the current set of defaults.
        :rtype: GThemeValueMap
        """

    def getFont(self, id: typing.Union[java.lang.String, str]) -> java.awt.Font:
        """
        Returns the current :obj:`Font` associated with the given id. A default font will be
        returned if the font can't be resolved and an error message will be printed to the console.
        
        :param java.lang.String or str id: the id for the desired font
        :return: the current :obj:`Font` associated with the given id.
        :rtype: java.awt.Font
        """

    def getIcon(self, id: typing.Union[java.lang.String, str]) -> javax.swing.Icon:
        """
        Returns the Icon registered for the given id. If no icon is registered for the id,
        the default icon will be returned and an error message will be dumped to the console
        
        :param java.lang.String or str id: the id to get the registered icon for
        :return: the actual icon registered for the given id
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getInstance() -> ThemeManager:
        ...

    def getJavaDefaults(self) -> GThemeValueMap:
        """
        Returns the :obj:`GThemeValueMap` containing all the default theme values defined by the
        current :obj:`LookAndFeel`.
        
        :return: the :obj:`GThemeValueMap` containing all the default theme values defined by the
        current :obj:`LookAndFeel`
        :rtype: GThemeValueMap
        """

    def getLookAndFeelType(self) -> LafType:
        """
        Returns the :obj:`LafType` for the currently active :obj:`LookAndFeel`
        
        :return: the :obj:`LafType` for the currently active :obj:`LookAndFeel`
        :rtype: LafType
        """

    def getNonDefaultValues(self) -> GThemeValueMap:
        """
        Returns a :obj:`GThemeValueMap` contains all values that differ from the default
        values (values defined by the :obj:`LookAndFeel` or in the theme.properties files.
        
        :return: a :obj:`GThemeValueMap` contains all values that differ from the defaults.
        :rtype: GThemeValueMap
        """

    def getSupportedThemes(self) -> java.util.List[GTheme]:
        """
        Returns a set of all known themes that are supported on the current platform.
        
        :return: a set of all known themes that are supported on the current platform.
        :rtype: java.util.List[GTheme]
        """

    def getTheme(self, themeName: typing.Union[java.lang.String, str]) -> GTheme:
        """
        Returns the known theme that has the given name.
        
        :param java.lang.String or str themeName: the name of the theme to retrieve
        :return: the known theme that has the given name
        :rtype: GTheme
        """

    def getThemeValues(self) -> GThemeValueMap:
        """
        Returns the theme values as defined by the current theme, ignoring any unsaved changes that
        are currently applied to the application.
        
        :return: the theme values as defined by the current theme, ignoring any unsaved changes that
        are currently applied to the application
        :rtype: GThemeValueMap
        """

    def hasColor(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an color for the given Id has been defined
        
        :param java.lang.String or str id: the id to check for an existing color.
        :return: true if an color for the given Id has been defined
        :rtype: bool
        """

    def hasFont(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an font for the given Id has been defined
        
        :param java.lang.String or str id: the id to check for an existing font.
        :return: true if an font for the given Id has been defined
        :rtype: bool
        """

    def hasIcon(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an icon for the given Id has been defined
        
        :param java.lang.String or str id: the id to check for an existing icon.
        :return: true if an icon for the given Id has been defined
        :rtype: bool
        """

    def hasThemeChanges(self) -> bool:
        """
        Returns true if there are any unsaved changes to the current theme.
        
        :return: true if there are any unsaved changes to the current theme.
        :rtype: bool
        """

    def hasThemeValueChanges(self) -> bool:
        """
        Returns true if any theme values have changed.  This does not take into account the current
        Look and Feel.   Use :meth:`hasThemeChanges() <.hasThemeChanges>` to also account for changes to the Look and
        Feel.
        
        :return: true if any theme values have changed
        :rtype: bool
        """

    def isChangedColor(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the color associated with the given id has been changed from the current
        theme value for that id.
        
        :param java.lang.String or str id: the color id to check if it has been changed
        :return: true if the color associated with the given id has been changed from the current
        theme value for that id.
        :rtype: bool
        """

    def isChangedFont(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the font associated with the given id has been changed from the current
        theme value for that id.
        
        :param java.lang.String or str id: the font id to check if it has been changed
        :return: true if the font associated with the given id has been changed from the current
        theme value for that id.
        :rtype: bool
        """

    def isChangedIcon(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the Icon associated with the given id has been changed from the current
        theme value for that id.
        
        :param java.lang.String or str id: the Icon id to check if it has been changed
        :return: true if the Icon associated with the given id has been changed from the current
        theme value for that id.
        :rtype: bool
        """

    def isDarkTheme(self) -> bool:
        """
        Returns true if the current theme use dark default values.
        
        :return: true if the current theme use dark default values.
        :rtype: bool
        """

    def isUpdatingTheme(self) -> bool:
        """
        Returns true if the theme system is in the process of updating
        
        :return: true if the theme system is in the process of updating
        :rtype: bool
        """

    @typing.overload
    @deprecated("use isUsingAquaUI()")
    def isUsingAquaUI(self, UI: javax.swing.plaf.ComponentUI) -> bool:
        """
        Returns true if the given UI object is using the Aqua Look and Feel.
        
        :param javax.swing.plaf.ComponentUI UI: the UI to examine.  (This parameter is ignored)
        :return: true if the UI is using Aqua
        :rtype: bool
        
        .. deprecated::
        
        use :meth:`isUsingAquaUI() <.isUsingAquaUI>`
        """

    @typing.overload
    def isUsingAquaUI(self) -> bool:
        """
        Returns true if the current UI is using the Aqua Look and Feel.
        
        :return: true if the UI is using Aqua
        :rtype: bool
        """

    def isUsingFlatUI(self) -> bool:
        """
        Returns true if the current UI is the FlatLaf Dark or FlatLaf Light Look and Feel.
        
        :return: true if the current UI is the FlatLaf Dark or FlatLaf Light Look and Feel
        :rtype: bool
        """

    def isUsingNimbusUI(self) -> bool:
        """
        Returns true if 'Nimbus' is the current Look and Feel
        
        :return: true if 'Nimbus' is the current Look and Feel
        :rtype: bool
        """

    @typing.overload
    def registerFont(self, component: java.awt.Component, fontId: typing.Union[java.lang.String, str]):
        """
        Binds the component to the font identified by the given font id. Whenever the font for
        the font id changes, the component will updated with the new font.
        
        :param java.awt.Component component: the component to set/update the font
        :param java.lang.String or str fontId: the id of the font to register with the given component
        """

    @typing.overload
    def registerFont(self, component: java.awt.Component, fontId: typing.Union[java.lang.String, str], fontStyle: typing.Union[jpype.JInt, int]):
        """
        Binds the component to the font identified by the given font id. Whenever the font for
        the font id changes, the component will updated with the new font.
         
        
        This method is fairly niche and should not be called by most clients.  Instead, call
        :meth:`registerFont(Component, String) <.registerFont>`.
        
        :param java.awt.Component component: the component to set/update the font
        :param java.lang.String or str fontId: the id of the font to register with the given component
        :param jpype.JInt or int fontStyle: the font style
        """

    def removeThemeListener(self, listener: ThemeListener):
        """
        Removes the given :obj:`ThemeListener` from the list of listeners to be notified of
        theme changes.
        
        :param ThemeListener listener: the listener to be removed
        """

    def restoreColor(self, id: typing.Union[java.lang.String, str]):
        """
        Restores the current color value for the given color id to the value established by the
        current theme.
        
        :param java.lang.String or str id: the color id to restore back to the original theme value
        """

    def restoreFont(self, id: typing.Union[java.lang.String, str]):
        """
        Restores the current font value for the given font id to the value established by the
        current theme.
        
        :param java.lang.String or str id: the font id to restore back to the original theme value
        """

    def restoreIcon(self, id: typing.Union[java.lang.String, str]):
        """
        Restores the current icon value for the given icon id to the value established by the
        current theme.
        
        :param java.lang.String or str id: the icon id to restore back to the original theme value
        """

    def restoreThemeValues(self):
        """
        Restores all the current application back to the values as specified by the active theme.
        In other words, reverts any changes to the active theme that haven't been saved.
        """

    @typing.overload
    def setColor(self, id: typing.Union[java.lang.String, str], color: java.awt.Color):
        """
        Updates the current color for the given id.
        
        :param java.lang.String or str id: the color id to update to the new color
        :param java.awt.Color color: the new color for the id
        """

    @typing.overload
    def setColor(self, newValue: ColorValue):
        """
        Updates the current value for the color id in the newValue
        
        :param ColorValue newValue: the new :obj:`ColorValue` to install in the current values.
        """

    @typing.overload
    def setFont(self, id: typing.Union[java.lang.String, str], font: java.awt.Font):
        """
        Updates the current font for the given id.
        
        :param java.lang.String or str id: the font id to update to the new color
        :param java.awt.Font font: the new font for the id
        """

    @typing.overload
    def setFont(self, newValue: FontValue):
        """
        Updates the current value for the font id in the newValue
        
        :param FontValue newValue: the new :obj:`FontValue` to install in the current values.
        """

    @typing.overload
    def setIcon(self, id: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Updates the current :obj:`Icon` for the given id.
        
        :param java.lang.String or str id: the icon id to update to the new icon
        :param javax.swing.Icon icon: the new :obj:`Icon` for the id
        """

    @typing.overload
    def setIcon(self, newValue: IconValue):
        """
        Updates the current value for the :obj:`Icon` id in the newValue
        
        :param IconValue newValue: the new :obj:`IconValue` to install in the current values.
        """

    def setLookAndFeel(self, lafType: LafType, useDarkDefaults: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the current :obj:`LookAndFeel`. This is used by theme editors to allow users to
        see the effects of changing LookAndFeels when configuring a theme. Setting this different
        from the activeTheme's LookAndFeel setting means that the current theme is in an unsaved
        state and causes the :meth:`hasThemeChanges() <.hasThemeChanges>` method to return true.
        
        :param LafType lafType: the :obj:`LafType` to set the LookAndFeel to
        :param jpype.JBoolean or bool useDarkDefaults: true if the application should used dark defaults with this
        LookAndFeel
        """

    def setTheme(self, theme: GTheme):
        """
        Sets the application's active theme to the given theme.
        
        :param GTheme theme: the theme to make active
        """

    def unRegisterFont(self, component: javax.swing.JComponent, fontId: typing.Union[java.lang.String, str]):
        """
        Removes the component and font id binding made in a previous call to 
        :meth:`registerFont(Component, String) <.registerFont>`.
        
        :param javax.swing.JComponent component: the component to remove
        :param java.lang.String or str fontId: the id of the font previously registered
        """

    @property
    def updatingTheme(self) -> jpype.JBoolean:
        ...

    @property
    def changedColor(self) -> jpype.JBoolean:
        ...

    @property
    def nonDefaultValues(self) -> GThemeValueMap:
        ...

    @property
    def applicationLightDefaults(self) -> GThemeValueMap:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def allThemes(self) -> java.util.Set[GTheme]:
        ...

    @property
    def usingAquaUI(self) -> jpype.JBoolean:
        ...

    @property
    def applicationDarkDefaults(self) -> GThemeValueMap:
        ...

    @property
    def supportedThemes(self) -> java.util.List[GTheme]:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def darkTheme(self) -> jpype.JBoolean:
        ...

    @property
    def javaDefaults(self) -> GThemeValueMap:
        ...

    @property
    def defaults(self) -> GThemeValueMap:
        ...

    @property
    def activeTheme(self) -> GTheme:
        ...

    @property
    def changedFont(self) -> jpype.JBoolean:
        ...

    @property
    def changedIcon(self) -> jpype.JBoolean:
        ...

    @property
    def lookAndFeelType(self) -> LafType:
        ...

    @property
    def usingFlatUI(self) -> jpype.JBoolean:
        ...

    @property
    def theme(self) -> GTheme:
        ...

    @theme.setter
    def theme(self, value: GTheme):
        ...

    @property
    def themeValues(self) -> GThemeValueMap:
        ...

    @property
    def currentValues(self) -> GThemeValueMap:
        ...

    @property
    def usingNimbusUI(self) -> jpype.JBoolean:
        ...

    @property
    def font(self) -> java.awt.Font:
        ...


class LafType(java.lang.Enum[LafType]):
    """
    An enumeration that represents the set of supported :obj:`LookAndFeel`s
    """

    class_: typing.ClassVar[java.lang.Class]
    METAL: typing.Final[LafType]
    NIMBUS: typing.Final[LafType]
    GTK: typing.Final[LafType]
    MOTIF: typing.Final[LafType]
    FLAT_LIGHT: typing.Final[LafType]
    FLAT_DARK: typing.Final[LafType]
    WINDOWS: typing.Final[LafType]
    WINDOWS_CLASSIC: typing.Final[LafType]
    MAC: typing.Final[LafType]

    @staticmethod
    def fromName(name: typing.Union[java.lang.String, str]) -> LafType:
        """
        Returns the LafType for the given name or null if the given name does not match any types
        
        :param java.lang.String or str name: the name to search a LafType for.
        :return: the LafType for the given name or null if the given name does not match any types
        :rtype: LafType
        """

    @staticmethod
    def getDefaultLookAndFeel() -> LafType:
        """
        Returns the default LafType for the current platform.
        
        :return: the default LafType for the current platform.
        :rtype: LafType
        """

    def getDisplayString(self) -> str:
        """
        Gets the preferred display string for this type.
        
        :return: the preferred display string.
        :rtype: str
        """

    def getLookAndFeelManager(self, themeManager: ApplicationThemeManager) -> generic.theme.laf.LookAndFeelManager:
        """
        Returns a LookAndFeelManager that can install and update the :obj:`LookAndFeel` associated
        with this LafType.
        
        :param ApplicationThemeManager themeManager: The application ThemeManager
        :return: a LookAndFeelManager that can install and update the :obj:`LookAndFeel` associated
        with this LafType.
        :rtype: generic.theme.laf.LookAndFeelManager
        """

    def getName(self) -> str:
        """
        Returns the name of this LafType.
        
        :return: the name of this LafType.
        :rtype: str
        """

    def isSupported(self) -> bool:
        """
        Returns true if the :obj:`LookAndFeel` represented by this LafType is supported on the
        current platform.
        
        :return: true if the :obj:`LookAndFeel` represented by this LafType is supported on the
        current platform
        :rtype: bool
        """

    def usesDarkDefaults(self) -> bool:
        """
        Returns true if the LookAndFeel represented by this LafType uses application dark 
        default values.
        
        :return: true if the LookAndFeel represented by this LafType uses application dark 
        default values.
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LafType:
        ...

    @staticmethod
    def values() -> jpype.JArray[LafType]:
        ...

    @property
    def lookAndFeelManager(self) -> generic.theme.laf.LookAndFeelManager:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def supported(self) -> jpype.JBoolean:
        ...


class GTheme(GThemeValueMap):
    """
    Class to store all the configurable appearance properties (Colors, Fonts, Icons, Look and Feel)
    in an application.
    """

    class_: typing.ClassVar[java.lang.Class]
    FILE_PREFIX: typing.Final = "File:"
    JAVA_ICON: typing.Final = "<JAVA ICON>"
    FILE_EXTENSION: typing.ClassVar[java.lang.String]
    ZIP_FILE_EXTENSION: typing.ClassVar[java.lang.String]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates a new GTheme with the given name, the default :obj:`LookAndFeel` for the 
        platform and not using dark defaults. This theme will be using all the standard defaults
        from the theme.property files and the defaults from the default LookAndFeel.
        
        :param java.lang.String or str name: the name for this GTheme
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], lafType: LafType):
        """
        Creates a new empty GTheme with the given name, :obj:`LookAndFeel`, and whether or not to
        use dark defaults.
        
        :param java.lang.String or str name: the name for the new GTheme
        :param LafType lafType: the look and feel type used by this theme
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str], lafType: LafType, useDarkDefaults: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for creating a GTheme with an associated File.
        
        :param jpype.protocol.SupportsPath file: the file that this theme will save to
        :param java.lang.String or str name: the name of the new theme
        :param LafType lafType: the :obj:`LafType` for the new theme
        :param jpype.JBoolean or bool useDarkDefaults: true if this new theme uses dark defaults
        """

    def getFile(self) -> java.io.File:
        """
        Returns the file associated with this theme.
        
        :return: the file associated with this theme.
        :rtype: java.io.File
        """

    def getLookAndFeelType(self) -> LafType:
        """
        Returns the name of the LookAndFeel associated with this GTheme
        
        :return: the name of the LookAndFeel associated with this GTheme
        :rtype: LafType
        """

    def getName(self) -> str:
        """
        Returns the name of this GTheme
        
        :return: the name of this GTheme
        :rtype: str
        """

    def getThemeLocater(self) -> str:
        """
        Returns a String that can be used to find and restore this theme.
        
        :return: a String that can be used to find and restore this theme.
        :rtype: str
        """

    def hasSupportedLookAndFeel(self) -> bool:
        """
        Returns true if this theme has a :obj:`LookAndFeel` that is supported by the current
        platform.
        
        :return: true if this theme has a :obj:`LookAndFeel` that is supported by the current
        platform.
        :rtype: bool
        """

    def isReadOnly(self) -> bool:
        """
        Returns true if this theme can not be changed
        
        :return: true if this theme can not be changed
        :rtype: bool
        """

    @staticmethod
    def loadTheme(file: jpype.protocol.SupportsPath) -> GTheme:
        """
        Reads a theme from a file. The file can be either a theme file or a zip file containing
        a theme file and optionally a set of icon files.
        
        :param jpype.protocol.SupportsPath file: the file to read.
        :return: the theme that was read from the file
        :rtype: GTheme
        :raises IOException: if an error occurred trying to read a theme from the file.
        """

    def save(self):
        """
        Saves this theme to its associated file.
        
        :raises IOException: if an I/O error occurs when writing the file
        """

    def setColor(self, id: typing.Union[java.lang.String, str], color: java.awt.Color):
        """
        Sets the Color for the given id
        
        :param java.lang.String or str id: the id to associate with the given Color
        :param java.awt.Color color: the Color to associate with the given id
        """

    def setColorRef(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str]):
        """
        Sets a referred Color for the given id
        
        :param java.lang.String or str id: the id to associate with the refId
        :param java.lang.String or str refId: the id of an indirect Color lookup for the given id.
        """

    def setFont(self, id: typing.Union[java.lang.String, str], font: java.awt.Font):
        """
        Sets the Font for the given id
        
        :param java.lang.String or str id: the id to associate with the given Font
        :param java.awt.Font font: the Font to associate with the given id
        """

    def setFontRef(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str]):
        """
        Sets a referred font for the given id
        
        :param java.lang.String or str id: the id to associate with the given Font reference id
        :param java.lang.String or str refId: the id of an indirect Font lookup for the given id.
        """

    def setIcon(self, id: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Sets the icon for the given id
        
        :param java.lang.String or str id: the id to associate with the given IconPath
        :param javax.swing.Icon icon: the icon to assign to the given id
        """

    def setIconRef(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str]):
        """
        Sets a referred icon id for the given id
        
        :param java.lang.String or str id: the id to associate with the given Font
        :param java.lang.String or str refId: the id of an indirect Icon lookup for the given id.
        """

    def useDarkDefaults(self) -> bool:
        """
        Returns true if this theme should use dark defaults
        
        :return: true if this theme should use dark defaults
        :rtype: bool
        """

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def themeLocater(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def lookAndFeelType(self) -> LafType:
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...


class GAttributes(javax.swing.text.SimpleAttributeSet):
    """
    A drop-in replacement for clients using :obj:`SimpleAttributeSet`s.  This class will apply a
    default set of font attributes based on the given font and optional color.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, f: java.awt.Font):
        ...

    @typing.overload
    def __init__(self, f: java.awt.Font, c: GColor):
        ...

    def toStyledHtml(self, content: typing.Union[java.lang.String, str]) -> str:
        """
        A convenience method to style the given text in HTML using the font and color attributes
        defined in this attribute set.  The text will be HTML escaped.
        
        :param java.lang.String or str content: the content
        :return: the styled content
        :rtype: str
        
        .. seealso::
        
            | :obj:`HTMLUtilities.styleText(SimpleAttributeSet, String)`
        """


class ThemeValueUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def parseGroupings(source: typing.Union[java.lang.String, str], startChar: typing.Union[jpype.JChar, int, str], endChar: typing.Union[jpype.JChar, int, str]) -> java.util.List[java.lang.String]:
        """
        Parses the given source string into a list of strings, one for each group. The startChar
        and endChar defined the group characters. So, for example, "(ab (cd))(ef)((gh))" would 
        result in a list with the following values: "ab (cd)", "ef", and "(gh)"
        
        :param java.lang.String or str source: the source string to parse into groups
        :param jpype.JChar or int or str startChar: the character that defines the start of a group
        :param jpype.JChar or int or str endChar: the character that defines then end of a group
        :return: a List of strings, one for each consecutive group contained in the string
        :rtype: java.util.List[java.lang.String]
        :raises ParseException: if the groupings are not balanced or missing altogether
        """


class StubThemeManager(ThemeManager):
    """
    Version of ThemeManager that is used before an application or test installs a full
    ApplicationThemeManager. Provides enough basic functionality used by the Gui class to
    allow simple unit tests to run.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Gui(java.lang.Object):
    """
    Provides a static set of methods for globally managing application themes and their values.
     
    
    The basic idea is that all the colors, fonts, and icons used in an application should be
    accessed indirectly via an "id" string. Then the actual color, font, or icon can be changed
    without changing the source code. The default mapping of the id strings to a value is defined
    in {name}.theme.properties files which are dynamically discovered by searching the module's
    data directory. Also, these files can optionally define a dark default value for an id which
    would replace the standard default value in the event that the current theme specifies that it
    is a dark theme. Themes are used to specify the application's :obj:`LookAndFeel`, whether or
    not it is dark, and any customized values for colors, fonts, or icons. There are several
    "built-in" themes, one for each supported :obj:`LookAndFeel`, but additional themes can
    be defined and stored in the users application home directory as a {name}.theme file.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def addThemeListener(listener: ThemeListener):
        """
        Adds a :obj:`ThemeListener` to be notified of theme changes.
        
        :param ThemeListener listener: the listener to be notified
        """

    @staticmethod
    def brighter(color: java.awt.Color) -> java.awt.Color:
        """
        Returns a brighter version of the given color or darker if the current theme is dark.
        
        :param java.awt.Color color: the color to get a brighter version of
        :return: a brighter version of the given color or darker if the current theme is dark
        :rtype: java.awt.Color
        """

    @staticmethod
    def darker(color: java.awt.Color) -> java.awt.Color:
        """
        Returns a darker version of the given color or brighter if the current theme is dark.
        
        :param java.awt.Color color: the color to get a darker version of
        :return: a darker version of the given color or brighter if the current theme is dark
        :rtype: java.awt.Color
        """

    @staticmethod
    def getColor(id: typing.Union[java.lang.String, str]) -> java.awt.Color:
        """
        Returns the :obj:`Color` registered for the given id. Will output an error message if
        the id can't be resolved.
        
        :param java.lang.String or str id: the id to get the direct color for
        :return: the :obj:`Color` registered for the given id.
        :rtype: java.awt.Color
        """

    @staticmethod
    def getFont(id: typing.Union[java.lang.String, str]) -> java.awt.Font:
        """
        Returns the current :obj:`Font` associated with the given id. A default font will be
        returned if the font can't be resolved and an error message will be printed to the console.
        
        :param java.lang.String or str id: the id for the desired font
        :return: the current :obj:`Font` associated with the given id.
        :rtype: java.awt.Font
        """

    @staticmethod
    def getIcon(id: typing.Union[java.lang.String, str]) -> javax.swing.Icon:
        """
        Returns the Icon registered for the given id. If no icon is registered for the id,
        the default icon will be returned and an error message will be dumped to the console
        
        :param java.lang.String or str id: the id to get the registered icon for
        :return: the actual icon registered for the given id
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def hasColor(id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an color for the given Id has been defined
        
        :param java.lang.String or str id: the id to check for an existing color.
        :return: true if an color for the given Id has been defined
        :rtype: bool
        """

    @staticmethod
    def hasFont(id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an font for the given Id has been defined
        
        :param java.lang.String or str id: the id to check for an existing font.
        :return: true if an font for the given Id has been defined
        :rtype: bool
        """

    @staticmethod
    def hasIcon(id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an icon for the given Id has been defined
        
        :param java.lang.String or str id: the id to check for an existing icon.
        :return: true if an icon for the given Id has been defined
        :rtype: bool
        """

    @staticmethod
    def isBlinkingCursors() -> bool:
        """
        Returns true if the application should allow blinking cursors, false otherwise. Custom
        components can use this method to determine if they should have a blinking cursor or not.
        
        :return: true if the application should allow blinking cursors, false otherwise.
        :rtype: bool
        """

    @staticmethod
    def isDarkTheme() -> bool:
        """
        Returns true if the active theme is using dark defaults
        
        :return: true if the active theme is using dark defaults
        :rtype: bool
        """

    @staticmethod
    def isSystemId(id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given id is a system-defined id, such as those starting with
        ``laf.color`` or ``system.color``.
        
        :param java.lang.String or str id: the id
        :return: true if the given id is a system-defined id
        :rtype: bool
        """

    @staticmethod
    def isUpdatingTheme() -> bool:
        """
        Returns true if the theme system is in the process of updating
        
        :return: true if the theme system is in the process of updating
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def registerFont(component: java.awt.Component, fontId: typing.Union[java.lang.String, str]):
        """
        Binds the component to the font identified by the given font id. Whenever the font for
        the font id changes, the component will updated with the new font.
         
        
        Calling this method will trigger a call to :meth:`JComponent.setFont(Font) <JComponent.setFont>`.
        
        :param java.awt.Component component: the component to set/update the font
        :param java.lang.String or str fontId: the id of the font to register with the given component
        """

    @staticmethod
    @typing.overload
    def registerFont(component: javax.swing.JComponent, fontStyle: typing.Union[jpype.JInt, int]):
        """
        Registers the given component with the given font style.  This method allows clients to not
        define a font id in the theme system, but instead to signal that they want the default font
        for the given component, modified with the given style.  As the underlying font is changed,
        the client will be updated with that new font with the given style applied.
         
        
        Most clients should **not** be using this method.  Instead, use
        :meth:`registerFont(JComponent, int) <.registerFont>`.
         
        
        The downside of using this method is that the end user cannot modify the style of the font.
        By using the standard theming mechanism for registering fonts, the end user has full control.
        
        :param javax.swing.JComponent component: the component to set/update the font
        :param jpype.JInt or int fontStyle: the font style, one of Font.BOLD, Font.ITALIC,
        """

    @staticmethod
    def removeThemeListener(listener: ThemeListener):
        """
        Removes the given :obj:`ThemeListener` from the list of listeners to be notified of
        theme changes.
        
        :param ThemeListener listener: the listener to be removed
        """

    @staticmethod
    def setBlinkingCursors(b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets application's blinking cursor state. This will affect all JTextFields, JTextAreas, 
        JTextPanes via :obj:`UIDefaults`. Custom components can also respect this setting by
        either adding a :obj:`ThemeListener` or overriding :meth:`JComponent.updateUI() <JComponent.updateUI>`
         
        NOTE: This method is a bit odd here as it doesn't really apply to a theme. But it
        requires manipulation of the look and feel which is managed by the theme. If other 
        application level properties  come along and also require changing the UIDefaults, 
        perhaps a more general solution might be to add a way for clients to register a callback
        so that they get a chance to change the UIDefaults map as the look and feel is loaded.
        
        :param jpype.JBoolean or bool b: true for blinking text cursors, false for non-blinking text cursors
        """

    @staticmethod
    def unRegisterFont(component: javax.swing.JComponent, fontId: typing.Union[java.lang.String, str]):
        """
        Removes the component and font id binding made in a previous call to 
        :meth:`registerFont(Component, String) <.registerFont>`.
         
        
        Clients need to call this method if they decide to change the font id being used for a given
        component.  Must clients do not need to use this method.
        
        :param javax.swing.JComponent component: the component to remove
        :param java.lang.String or str fontId: the id of the font previously registered
        """


class FontChangedThemeEvent(ThemeEvent):
    """
    :obj:`ThemeEvent` for when a font changes for exactly one font id.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, values: GThemeValueMap, font: FontValue):
        """
        Constructor
        
        :param GThemeValueMap values: the set of theme values used to resolve indirect references
        :param FontValue font: the new :obj:`FontValue` for the font id that changed
        """


class IconChangedThemeEvent(ThemeEvent):
    """
    :obj:`ThemeEvent` for when an icon changes for exactly one icon id.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, values: GThemeValueMap, icon: IconValue):
        """
        Constructor
        
        :param IconValue icon: the new :obj:`IconValue` for the icon id that changed
        """


class ThemeWriter(java.lang.Object):
    """
    Writes a theme to a file either as a single theme file or as a zip file that contains the theme
    file and any external (from the file system, not the classpath) icons used by the theme.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, theme: GTheme):
        """
        Constructor
        
        :param GTheme theme: the theme to be written to a file
        """

    def writeTheme(self, file: jpype.protocol.SupportsPath, asZip: typing.Union[jpype.JBoolean, bool]):
        """
        Writes the theme to the given file with the option to output as a zip file.
        
        :param jpype.protocol.SupportsPath file: the file to write to
        :param jpype.JBoolean or bool asZip: if true, outputs in zip format
        :raises FileNotFoundException: i
        :raises IOException: if an I/O error occurs trying to write the file
        """

    def writeThemeToFile(self, file: jpype.protocol.SupportsPath):
        """
        Writes the theme to the given file.
        
        :param jpype.protocol.SupportsPath file: the file to write to
        :raises FileNotFoundException: i
        :raises IOException: if an I/O error occurs trying to write the file
        """

    def writeThemeToZipFile(self, file: jpype.protocol.SupportsPath):
        """
        Writes the theme to the given file in a zip format.
        
        :param jpype.protocol.SupportsPath file: the file to write to
        :raises IOException: if an I/O error occurs trying to write the file
        """


class ColorValue(ThemeValue[java.awt.Color]):
    """
    A class for storing :obj:`Color` values that have a String id (e.g. color.bg.foo) and either
    a concrete color or a reference id which is the String id of another ColorValue that it
    will inherit its color from. So if this class's color value is non-null, the refId will be null
    and if the class's refId is non-null, then the color value will be null.
    """

    class_: typing.ClassVar[java.lang.Class]
    LAF_ID_PREFIX: typing.Final = "laf.color."
    EXTERNAL_LAF_ID_PREFIX: typing.Final = "[laf.color]"
    LAST_RESORT_DEFAULT: typing.Final[java.awt.Color]

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], value: java.awt.Color):
        """
        Constructor used when the ColorValue will have a direct :obj:`Color` value. The refId will
        be null. Note: if a :obj:`GColor` is passed in as the value, then this will be an indirect
        ColorValue that inherits its color from the id stored in the GColor.
        
        :param java.lang.String or str id: the id for this ColorValue
        :param java.awt.Color value: the :obj:`Color` to associate with the given id
        """

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str]):
        """
        Constructor used when the ColorValue will inherit its color from another ColorValue. The
        color value field will be null.
        
        :param java.lang.String or str id: the id for this ColorValue
        :param java.lang.String or str refId: the id of another ColorValue that this ColorValue will inherit from
        """

    @staticmethod
    def isColorKey(key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given key string is a valid external key for a color value
        
        :param java.lang.String or str key: the key string to test
        :return: true if the given key string is a valid external key for a color value
        :rtype: bool
        """

    @staticmethod
    def parse(key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> ColorValue:
        """
        Parses the value string into a color or reference and creates a new ColorValue using
        the given key and the parse results.
        
        :param java.lang.String or str key: the key to associate the parsed value with
        :param java.lang.String or str value: the color value to parse
        :return: a ColorValue with the given key and the parsed value
        :rtype: ColorValue
        """


class GIconUIResource(GIcon, javax.swing.plaf.UIResource):
    """
    Version of GIcon that implements UIResource. It is important that when setting java defaults
    in the :obj:`UIDefaults` that it implements UIResource. Otherwise, java will think the icon
    was set explicitly by client code and therefore can't update it generically when it goes to 
    update the default icon in the UIs for each component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[java.lang.String, str]):
        ...


class IconValue(ThemeValue[javax.swing.Icon]):
    """
    A class for storing :obj:`Icon` values that have a String id (e.g. icon.bg.foo) and either
    a concrete icon or a reference id which is the String id of another IconValue that it
    will inherit its icon from. So if this class's icon value is non-null, the refId will be null
    and if the class's refId is non-null, then the icon value will be null.
    """

    class_: typing.ClassVar[java.lang.Class]
    LAF_ID_PREFIX: typing.Final = "laf.icon."
    EXTERNAL_LAF_ID_PREFIX: typing.Final = "[laf.icon]"
    LAST_RESORT_DEFAULT: typing.Final[javax.swing.Icon]

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Constructor used when the ColorValue will have a direct :obj:`Icon` value. The refId will
        be null. Note: if a :obj:`GIcon` is passed in as the value, then this will be an indirect
        IconValue that inherits its icon from the id stored in the GIcon.
        
        :param java.lang.String or str id: the id for this IconValue
        :param javax.swing.Icon icon: the :obj:`Icon` to associate with the given id
        """

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str]):
        """
        Constructor used when the IconValue will inherit its :obj:`Icon` from another IconValue. The
        icon value field will be null.
        
        :param java.lang.String or str id: the id for this IconValue
        :param java.lang.String or str refId: the id of another IconValue that this IconValue will inherit from
        """

    @staticmethod
    def iconToString(icon: javax.swing.Icon) -> str:
        """
        Converts an icon to a string.
        
        :param javax.swing.Icon icon: the icon to convert to a String
        :return: a String that represents the icon
        :rtype: str
        """

    @staticmethod
    def isIconKey(key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given key string is a valid external key for an icon value
        
        :param java.lang.String or str key: the key string to test
        :return: true if the given key string is a valid external key for an icon value
        :rtype: bool
        """

    @staticmethod
    def parse(key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> IconValue:
        """
        Parses the value string into an icon or reference and creates a new IconValue using
        the given key and the parse results.
        
        :param java.lang.String or str key: the key to associate the parsed value with
        :param java.lang.String or str value: the color value to parse
        :return: an IconValue with the given key and the parsed value
        :rtype: IconValue
        :raises ParseException: if the value can't be parsed
        """


class IconModifier(java.lang.Object):
    """
    Class that can transform one icon into another. Useful for scaling, translating, disabling,
    or overlaying an icon.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, size: java.awt.Dimension, translation: java.awt.Point, rotation: typing.Union[java.lang.Integer, int], disabled: typing.Union[jpype.JBoolean, bool], mirror: typing.Union[jpype.JBoolean, bool], flip: typing.Union[jpype.JBoolean, bool]):
        """
        Creates an IconModifier that can scale, translate, or disable an icon.
        
        :param java.awt.Dimension size: if non-null, scales an icon to this size.
        :param java.awt.Point translation: if non-null, translates an icon by this amount
        :param java.lang.Integer or int rotation: if non-null, the amount in degrees to rotate the icon
        :param jpype.JBoolean or bool disabled: if true, creates a disabled version of the icon
        :param jpype.JBoolean or bool mirror: if true, the image will have its x values swapped (left to right)
        :param jpype.JBoolean or bool flip: if true, the image will have its y values swapped (turned upside down)
        """

    def getSerializationString(self) -> str:
        """
        Returns a string that can be parsed by the :meth:`parse(String) <.parse>` method of this class
        
        :return: a string that can be parsed by the :meth:`parse(String) <.parse>` method of this class
        :rtype: str
        """

    def modify(self, icon: javax.swing.Icon, values: GThemeValueMap) -> javax.swing.Icon:
        """
        Modifies the given icon by the any of the modifiers set.
        
        :param javax.swing.Icon icon: the icon to be modified
        :param GThemeValueMap values: the ThemeValueMap needed if the modify action is to overlay other icons. The 
        values are used to resolve indirect overlay icon references
        :return: A new Icon that is a modified version of the given icon
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def parse(iconModifierString: typing.Union[java.lang.String, str]) -> IconModifier:
        """
        Parses the given string as one or more icon modifiers
        
        :param java.lang.String or str iconModifierString: the string to parse as modifiers
        :return: an IconModifier as specified by the given string
        :rtype: IconModifier
        :raises ParseException: if the iconModifierString in not properly formatted icon modifier
        """

    def setDisabled(self):
        """
        Sets this modifier to disable an icon
        """

    def setFlip(self):
        """
        Sets the modifier to flip the icon side to side
        """

    def setMirror(self):
        """
        Sets the modifier to flip the icon side to side
        """

    def setMoveModifier(self, point: java.awt.Point):
        """
        Sets the translation for this modifier. Icons that are modified by this IconModifier will
        be translated by the amount of the given point.
        
        :param java.awt.Point point: the x,y amount to translate an image
        """

    def setRotationModifer(self, degrees: typing.Union[jpype.JInt, int]):
        """
        Sets the rotation for this modifier. Icons that are modified by this IconModifier will
        be rotated by the given amount (in degrees)
        
        :param jpype.JInt or int degrees: the rotation amount;
        """

    def setSizeModifier(self, size: java.awt.Dimension):
        """
        Sets size modifier. Icons that are modified by this IconModifier will be scaled to this size.
        
        :param java.awt.Dimension size: the size to scale modified icons.
        """

    @property
    def serializationString(self) -> java.lang.String:
        ...


class GThemeValueMap(java.lang.Object):
    """
    Class for storing colors, fonts, and icons by id
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a new empty map.
        """

    @typing.overload
    def __init__(self, initial: GThemeValueMap):
        """
        Constructs a new value map, populated by all the values in the given map. Essentially clones
        the given map.
        
        :param GThemeValueMap initial: the set of values to initialize to
        """

    def addColor(self, value: ColorValue) -> ColorValue:
        """
        Adds the :obj:`ColorValue` to the map. If a ColorValue already exists in the map with
        the same id, it will be replaced
        
        :param ColorValue value: the :obj:`ColorValue` to store in the map.
        :return: the previous value for the color key or null if no previous value existed
        :rtype: ColorValue
        """

    def addFont(self, value: FontValue) -> FontValue:
        """
        Adds the :obj:`FontValue` to the map. If a FontValue already exists in the map with
        the same id, it will be replaced
        
        :param FontValue value: the :obj:`FontValue` to store in the map.
        :return: the previous value for the font key or null if no previous value existed
        :rtype: FontValue
        """

    def addIcon(self, value: IconValue) -> IconValue:
        """
        Adds the :obj:`IconValue` to the map. If a IconValue already exists in the map with
        the same id, it will be replaced
        
        :param IconValue value: the :obj:`IconValue` to store in the map.
        :return: the previous value for the icon key or null if no previous value existed
        :rtype: IconValue
        """

    def addProperty(self, value: JavaPropertyValue) -> JavaPropertyValue:
        """
        Adds the given property value to this map. If a property value already exists in the map with
        the same id, it will be replaced.
        
        :param JavaPropertyValue value: the :obj:`JavaPropertyValue` to store in the map.
        :return: the previous value for the icon key or null if no previous value existed.
        :rtype: JavaPropertyValue
        """

    def checkForUnresolvedReferences(self):
        ...

    def clear(self):
        """
        Clears all color, font, and icon values from this map
        """

    def containsColor(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if a :obj:`ColorValue` exists in this map for the given id.
        
        :param java.lang.String or str id: the id to check
        :return: true if a :obj:`ColorValue` exists in this map for the given id
        :rtype: bool
        """

    def containsFont(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if a :obj:`FontValue` exists in this map for the given id.
        
        :param java.lang.String or str id: the id to check
        :return: true if a :obj:`FontValue` exists in this map for the given id
        :rtype: bool
        """

    def containsIcon(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an :obj:`IconValue` exists in this map for the given id.
        
        :param java.lang.String or str id: the id to check
        :return: true if an :obj:`IconValue` exists in this map for the given id
        :rtype: bool
        """

    def containsProperty(self, id: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if an :obj:`JavaPropertyValue` exists in this map for the given id.
        
        :param java.lang.String or str id: the id to check
        :return: true if an :obj:`JavaPropertyValue` exists in this map for the given id
        :rtype: bool
        """

    def getChangedValues(self, base: GThemeValueMap) -> GThemeValueMap:
        """
        Returns a new :obj:`GThemeValueMap` that is only populated by values that don't exist
        in the give map.
        
        :param GThemeValueMap base: the set of values (usually the default set) to compare against to determine
        what values are changed.
        :return: a new :obj:`GThemeValueMap` that is only populated by values that don't exist
        in the give map
        :rtype: GThemeValueMap
        """

    def getColor(self, id: typing.Union[java.lang.String, str]) -> ColorValue:
        """
        Returns the current :obj:`ColorValue` for the given id or null if none exists.
        
        :param java.lang.String or str id: the id to look up a color for
        :return: the current :obj:`ColorValue` for the given id or null if none exists.
        :rtype: ColorValue
        """

    def getColorIds(self) -> java.util.Set[java.lang.String]:
        """
        Returns the set of all color ids in this map
        
        :return: the set of all color ids in this map
        :rtype: java.util.Set[java.lang.String]
        """

    def getColors(self) -> java.util.List[ColorValue]:
        """
        Returns a list of all the :obj:`ColorValue`s stored in this map.
        
        :return: a list of all the :obj:`ColorValue`s stored in this map.
        :rtype: java.util.List[ColorValue]
        """

    def getExternalIconFiles(self) -> java.util.Set[java.io.File]:
        """
        Gets the set of icon (.png, .gif) files that are used by IconValues that came from files
        versus resources in the classpath. These are the icon files that need to be included when
        exporting this set of values to a zip file.
        
        :return: the set of icon (.png, .gif) files that are used by IconValues that came from files
        versus resources in the classpath
        :rtype: java.util.Set[java.io.File]
        """

    def getFont(self, id: typing.Union[java.lang.String, str]) -> FontValue:
        """
        Returns the current :obj:`FontValue` for the given id or null if none exists.
        
        :param java.lang.String or str id: the id to look up a font for
        :return: the current :obj:`FontValue` for the given id or null if none exists.
        :rtype: FontValue
        """

    def getFontIds(self) -> java.util.Set[java.lang.String]:
        """
        Returns the set of all font ids in this map
        
        :return: the set of all font ids in this map
        :rtype: java.util.Set[java.lang.String]
        """

    def getFonts(self) -> java.util.List[FontValue]:
        """
        Returns a list of all the :obj:`FontValue`s stored in this map.
        
        :return: a list of all the :obj:`FontValue`s stored in this map.
        :rtype: java.util.List[FontValue]
        """

    def getIcon(self, id: typing.Union[java.lang.String, str]) -> IconValue:
        """
        Returns the current :obj:`IconValue` for the given id or null if none exists.
        
        :param java.lang.String or str id: the id to look up a icon for
        :return: the current :obj:`IconValue` for the given id or null if none exists.
        :rtype: IconValue
        """

    def getIconIds(self) -> java.util.Set[java.lang.String]:
        """
        Returns the set of all icon ids in this map
        
        :return: the set of all icon ids in this map
        :rtype: java.util.Set[java.lang.String]
        """

    def getIcons(self) -> java.util.List[IconValue]:
        """
        Returns a list of all the :obj:`IconValue`s stored in this map.
        
        :return: a list of all the :obj:`IconValue`s stored in this map.
        :rtype: java.util.List[IconValue]
        """

    def getProperties(self) -> java.util.List[JavaPropertyValue]:
        """
        Returns a list of all the :obj:`JavaPropertyValue`s stored in this map.
        
        :return: a list of all the :obj:`JavaPropertyValue`s stored in this map.
        :rtype: java.util.List[JavaPropertyValue]
        """

    def getProperty(self, id: typing.Union[java.lang.String, str]) -> JavaPropertyValue:
        """
        Returns the current :obj:`JavaPropertyValue` for the given id or null if none exists.
        
        :param java.lang.String or str id: the id to look up a icon for
        :return: the current :obj:`JavaPropertyValue` for the given id or null if none exists.
        :rtype: JavaPropertyValue
        """

    def getPropertyIds(self) -> java.util.Set[java.lang.String]:
        """
        Returns the set of all Java property ids in this map
        
        :return: the set of all Java property ids in this map
        :rtype: java.util.Set[java.lang.String]
        """

    def getResolvedColor(self, id: typing.Union[java.lang.String, str]) -> java.awt.Color:
        """
        Returns the resolved color, following indirections as needed to get the color ultimately
        assigned to the given id.
        
        :param java.lang.String or str id: the id for which to get a color
        :return: the resolved color, following indirections as needed to get the color ultimately
        assigned to the given id.
        :rtype: java.awt.Color
        """

    def getResolvedFont(self, id: typing.Union[java.lang.String, str]) -> java.awt.Font:
        """
        Returns the resolved font, following indirections as needed to get the font ultimately
        assigned to the given id.
        
        :param java.lang.String or str id: the id for which to get a font
        :return: the resolved font, following indirections as needed to get the font ultimately
        assigned to the given id
        :rtype: java.awt.Font
        """

    def getResolvedIcon(self, id: typing.Union[java.lang.String, str]) -> javax.swing.Icon:
        """
        Returns the resolved icon, following indirections as needed to get the icon ultimately
        assigned to the given id.
        
        :param java.lang.String or str id: the id for which to get an icon
        :return: the resolved icon, following indirections as needed to get the icon ultimately
        assigned to the given id
        :rtype: javax.swing.Icon
        """

    def getResolvedProperty(self, id: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Returns the resolved property, following indirections as needed to get the property
        ultimately assigned to the given id.
        
        :param java.lang.String or str id: the id for which to get an property
        :return: the resolved property, following indirections as needed to get the property
        ultimately assigned to the given id
        :rtype: java.lang.Object
        """

    def isEmpty(self) -> bool:
        """
        Returns true if there are not color, font, icon or property values in this map
        
        :return: true if there are not color, font, icon or property values in this map
        :rtype: bool
        """

    def load(self, valueMap: GThemeValueMap):
        """
        Loads all the values from the given map into this map, replacing values with the
        same ids.
        
        :param GThemeValueMap valueMap: the map whose values are to be loaded into this map
        """

    def removeColor(self, id: typing.Union[java.lang.String, str]):
        """
        removes any :obj:`ColorValue` with the given id from this map.
        
        :param java.lang.String or str id: the id to remove
        """

    def removeFont(self, id: typing.Union[java.lang.String, str]):
        """
        removes any :obj:`FontValue` with the given id from this map.
        
        :param java.lang.String or str id: the id to remove
        """

    def removeIcon(self, id: typing.Union[java.lang.String, str]):
        """
        removes any :obj:`IconValue` with the given id from this map.
        
        :param java.lang.String or str id: the id to remove
        """

    def removeProperty(self, id: typing.Union[java.lang.String, str]):
        """
        removes any :obj:`JavaPropertyValue` with the given id from this map.
        
        :param java.lang.String or str id: the id to remove
        """

    def size(self) -> java.lang.Object:
        """
        Returns the total number of color, font, icon and property values stored in this map
        
        :return: the total number of color, font, icon and property values stored in this map
        :rtype: java.lang.Object
        """

    @property
    def resolvedColor(self) -> java.awt.Color:
        ...

    @property
    def fontIds(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def color(self) -> ColorValue:
        ...

    @property
    def icon(self) -> IconValue:
        ...

    @property
    def propertyIds(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def resolvedIcon(self) -> javax.swing.Icon:
        ...

    @property
    def icons(self) -> java.util.List[IconValue]:
        ...

    @property
    def colors(self) -> java.util.List[ColorValue]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def changedValues(self) -> GThemeValueMap:
        ...

    @property
    def colorIds(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def iconIds(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def fonts(self) -> java.util.List[FontValue]:
        ...

    @property
    def externalIconFiles(self) -> java.util.Set[java.io.File]:
        ...

    @property
    def resolvedProperty(self) -> java.lang.Object:
        ...

    @property
    def resolvedFont(self) -> java.awt.Font:
        ...

    @property
    def properties(self) -> java.util.List[JavaPropertyValue]:
        ...

    @property
    def font(self) -> FontValue:
        ...


class StringPropertyValue(JavaPropertyValue):
    """
    A Java property value for keys that use String values.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def isStringKey(key: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def parse(key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> StringPropertyValue:
        ...


class ThemeValue(java.lang.Comparable[ThemeValue[T]], typing.Generic[T]):
    """
    A generic class for storing theme values that have a String id (e.g. color.bg.foo) and either
    a concrete value of type T or a reference id which is the String id of another ThemeValue. So
    if this class's value is non-null, the refId will be null and if the class's refId is non-null,
    then the value will be null.
    """

    class_: typing.ClassVar[java.lang.Class]

    def get(self, values: GThemeValueMap) -> T:
        """
        Returns the T value for this instance, following references as needed. Uses the given
        preferredValues map to resolve references. If the value can't be resolved by following
        reference chains, an error stack trace will be generated and the default T value will
        be returned. In rare situations where it is acceptable for the value to not be resolvable,
        use the :meth:`hasResolvableValue(GThemeValueMap) <.hasResolvableValue>` method first.
        
        :param GThemeValueMap values: the :obj:`GThemeValueMap` used to resolve references if this
        instance doesn't have an actual value.
        :return: the T value for this instance, following references as needed.
        :rtype: T
        """

    def getId(self) -> str:
        """
        Returns the identifier for this ThemeValue.
        
        :return: the identifier for this ThemeValue.
        :rtype: str
        """

    def getRawValue(self) -> T:
        """
        Returns the stored value. Does not follow referenceIds. Will be null if this instance
        has a referenceId.
        
        :return: the stored value. Does not follow referenceIds. Will be null if this instance
        has a referenceId.
        :rtype: T
        """

    def getReferenceId(self) -> str:
        """
        Returns the referencId of another ThemeValue that we inherit its value pr null if we have
        a value
        
        :return: the referencId of another ThemeValue that we inherit its value or null if we have
        a value
        :rtype: str
        """

    def getSerializationString(self) -> str:
        """
        Returns the "key = value" String for writing this ThemeValue to a file
        
        :return: the "key = value" String for writing this ThemeValue to a file
        :rtype: str
        """

    def hasResolvableValue(self, values: GThemeValueMap) -> bool:
        """
        Returns true if the ThemeValue can resolve to the concrete T value (color, font, or icon)
        from the given set of theme values.
        
        :param GThemeValueMap values: the set of values to use to try and follow reference chains to ultimately
        resolve the ThemeValue to a an actual T value
        :return: true if the ThemeValue can resolve to the concrete T value (color, font, or icon)
        from the given set of theme values.
        :rtype: bool
        """

    def inheritsFrom(self, ancestorId: typing.Union[java.lang.String, str], values: GThemeValueMap) -> bool:
        """
        Returns true if this ThemeValue derives its value from the given ancestorId.
        
        :param java.lang.String or str ancestorId: the id to test if this Theme value inherits from
        :param GThemeValueMap values: the set of values used to resolve indirect references to attempt to trace
        back to the given ancestor id
        :return: true if this ThemeValue derives its value from the given ancestorId.
        :rtype: bool
        """

    def installValue(self, themeManager: ThemeManager):
        """
        Install this value as the current value for the application
        
        :param ThemeManager themeManager: the application ThemeManager
        """

    def isExternal(self) -> bool:
        """
        True if this value is one that is one that is defined outside of the application, such as a
        Java Look and Feel key.
        
        :return: true if external
        :rtype: bool
        """

    def isIndirect(self) -> bool:
        """
        Returns true if this ColorValue gets its value from some other ColorValue
        
        :return: true if this ColorValue gets its value from some other ColorValue
        :rtype: bool
        """

    @property
    def external(self) -> jpype.JBoolean:
        ...

    @property
    def indirect(self) -> jpype.JBoolean:
        ...

    @property
    def rawValue(self) -> T:
        ...

    @property
    def serializationString(self) -> java.lang.String:
        ...

    @property
    def id(self) -> java.lang.String:
        ...

    @property
    def referenceId(self) -> java.lang.String:
        ...


class AllValuesChangedThemeEvent(ThemeEvent):
    """
    :obj:`ThemeEvent` for when a new theme is set or the current theme is reset to its original 
    values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lookAndFeelChanged: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param jpype.JBoolean or bool lookAndFeelChanged: true if the overall theme was changed which may have caused the
        :obj:`LookAndFeel` to change
        """


class ThemePreferences(java.lang.Object):
    """
    Reads and writes current theme info to preferences
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def load(self) -> GTheme:
        """
        Returns the theme that was stored in preferences or the default theme if none stored.
        
        :return: the last theme used (stored in preferences) or the default theme if not stored
        in preferences
        :rtype: GTheme
        """

    def save(self, theme: GTheme):
        """
        Saves the current theme choice to :obj:`Preferences`.
        
        :param GTheme theme: the theme to remember in :obj:`Preferences`
        """


class FontModifier(java.lang.Object):
    """
    Class that can transform one font into another. For example if want a font that is the same
    basic font as some other font, but is just a different size,style, or family, you use a
    FontModifier
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, family: typing.Union[java.lang.String, str], style: typing.Union[java.lang.Integer, int], size: typing.Union[java.lang.Integer, int]):
        """
        Creates a new FontModifier that can change a given font by one or more font properties.
        
        :param java.lang.String or str family: if non-null, modifies a font to use this family
        :param java.lang.Integer or int style: if non-null, modifies a font to use this style
        :param java.lang.Integer or int size: if non-null, modifies a font to be this size
        """

    def addFamilyModifier(self, newFamily: typing.Union[java.lang.String, str]):
        """
        Sets the family for modifying a font
        
        :param java.lang.String or str newFamily: the font family to use when modifying fonts
        """

    def addSizeModfier(self, newSize: typing.Union[jpype.JInt, int]):
        """
        Sets the font size modifier
        
        :param jpype.JInt or int newSize: the size to use when modifying fonts
        """

    def addStyleModifier(self, newStyle: typing.Union[jpype.JInt, int]):
        """
        Sets the font style modifier. This can be called multiple times to bold and italicize.
        
        :param jpype.JInt or int newStyle: the style to use for the font.
        """

    def getSerializationString(self) -> str:
        """
        Returns a string that can be parsed by the :meth:`parse(String) <.parse>` method of this class
        
        :return: a string that can be parsed by the :meth:`parse(String) <.parse>` method of this class
        :rtype: str
        """

    def modify(self, font: java.awt.Font) -> java.awt.Font:
        """
        Returns a modified font for the given font.
        
        :param java.awt.Font font: the font to be modified
        :return: a new modified font
        :rtype: java.awt.Font
        """

    @staticmethod
    def parse(value: typing.Union[java.lang.String, str]) -> FontModifier:
        """
        Parses the given string as one or more font modifiers
        
        :param java.lang.String or str value: the string to parse as modifiers
        :return: a FontModifier as specified by the given string
        :rtype: FontModifier
        :raises ParseException: if The value can't be parsed
        """

    @property
    def serializationString(self) -> java.lang.String:
        ...


class JavaPropertyValue(ThemeValue[java.lang.Object]):
    """
    A base class that represents a Java UIManager property.  This value is used to allow for
    overriding Java UI values using the theme properties files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[java.lang.String, str], refId: typing.Union[java.lang.String, str], value: java.lang.Object):
        ...


class DiscoverableGTheme(GTheme, ghidra.util.classfinder.ExtensionPoint):
    """
    Abstract base class for built-in :obj:`GTheme`s.
    """

    class_: typing.ClassVar[java.lang.Class]


class GIcon(javax.swing.Icon):
    """
    An :obj:`Icon` whose value is dynamically determined by looking up its id into a global
    icon table that is determined by the active :obj:`GTheme`.
     
    The idea is for developers to
    not use specific icons in their code, but to instead use a GIcon with an id that hints at 
    its use. For example, instead of hard coding a label's icon by coding 
    "label.setIcon(ResourceManager.loadImage("images/refresh.png", you would do something like 
    label.setIcon(new GIcon("icon.refresh"). Then in a "[module name].theme.properties" file 
    (located in the module's data directory), you would set the default value by adding this
    line "icon.refresh = images/refresh.png".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[java.lang.String, str]):
        """
        Construct a GIcon with an id that will be used to look up the current icon associated with
        that id, which can be changed at runtime.
        
        :param java.lang.String or str id: the id used to lookup the current value for this icon
        """

    def getDelegate(self) -> javax.swing.Icon:
        """
        Returns the current delegate for this GIcon. Note that this delegate can change when the
        theme changes or is edited.
        
        :return: the current delegate icon for this GIcon.
        :rtype: javax.swing.Icon
        """

    def getId(self) -> str:
        """
        Returns the id for this GIcon.
        
        :return: the id for this GIcon.
        :rtype: str
        """

    def getImageIcon(self) -> javax.swing.ImageIcon:
        """
        Returns the image for this icon.
        
        :return: the image
        :rtype: javax.swing.ImageIcon
        """

    def getUrl(self) -> java.net.URL:
        """
        Returns the url used to load the icon delegate of this class.  If the delegate icon was not 
        loaded from a url, then null will be returned.
        
        :return: the icon or null
        :rtype: java.net.URL
        """

    def refresh(self, currentValues: GThemeValueMap):
        """
        Reloads the delegate.
        
        :param GThemeValueMap currentValues: the map of current theme values
        """

    @staticmethod
    def refreshAll(currentValues: GThemeValueMap):
        """
        Static method for notifying all the existing GIcon that icons have changed and they
        should reload their cached indirect icon.
        
        :param GThemeValueMap currentValues: the map of all current theme values
        """

    @property
    def delegate(self) -> javax.swing.Icon:
        ...

    @property
    def imageIcon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def id(self) -> java.lang.String:
        ...

    @property
    def url(self) -> java.net.URL:
        ...


class GColorUIResource(GColor, javax.swing.plaf.UIResource):
    """
    Version of GColor that implements UIResource. It is important that when setting java defaults
    in the :obj:`UIDefaults` that it implements UIResource. Otherwise, java will think the color
    was set explicitly by client code and therefore can't update it generically when it goes to 
    update the default color in the UIs for each component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[java.lang.String, str]):
        ...

    def toGColor(self) -> GColor:
        """
        Returns a non-UIResource GColor for this GColorUiResource's id
        
        :return: a non-UIResource GColor for this GColorUiResource's id
        :rtype: GColor
        """



__all__ = ["AbstractThemeReader", "GThemeDefaults", "ThemePropertyFileReader", "ThemeEvent", "BooleanPropertyValue", "SystemThemeIds", "PropertyFileThemeDefaults", "ApplicationThemeManager", "ThemeReader", "GColor", "FontValue", "ApplicationThemeDefaults", "ThemeListener", "ColorChangedThemeEvent", "HeadlessThemeManager", "ThemeManager", "LafType", "GTheme", "GAttributes", "ThemeValueUtils", "StubThemeManager", "Gui", "FontChangedThemeEvent", "IconChangedThemeEvent", "ThemeWriter", "ColorValue", "GIconUIResource", "IconValue", "IconModifier", "GThemeValueMap", "StringPropertyValue", "ThemeValue", "AllValuesChangedThemeEvent", "ThemePreferences", "FontModifier", "JavaPropertyValue", "DiscoverableGTheme", "GIcon", "GColorUIResource"]
