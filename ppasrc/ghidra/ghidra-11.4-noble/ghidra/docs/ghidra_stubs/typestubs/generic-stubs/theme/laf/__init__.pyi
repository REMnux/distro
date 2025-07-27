from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.theme
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.border # type: ignore
import javax.swing.plaf.nimbus # type: ignore


T = typing.TypeVar("T")


class MotifUiDefaultsMapper(UiDefaultsMapper):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MacLookAndFeelManager(LookAndFeelManager):
    """
    Manages installing and updating the Mac Aqua look and feel.  This is where we make look and
    feel changes specific to the Mac Aqua look and feel, so that it works with the theming feature.
    """

    @typing.type_check_only
    class MacUiDefaultsMapper(UiDefaultsMapper):

        class_: typing.ClassVar[java.lang.Class]

        def installValuesIntoUIDefaults(self, currentValues: generic.theme.GThemeValueMap):
            """
            Overridden to change the Mac menu painters.  The default painters do not honor 
            the color values set by the Look and Feel. We override the painters by using
            either a Java border or our own painters that will use the theme colors.
            
            :param generic.theme.GThemeValueMap currentValues: the values to install into the LookAndFeel UiDefaults map
            """


    @typing.type_check_only
    class BackgroundBorder(javax.swing.border.EmptyBorder):
        """
        Background painter for selected menu items.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, color: generic.theme.GColor):
            ...

        def paintBorder(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class UiDefaultsMapper(java.lang.Object):
    """
    The purpose of this class is to introduce multiple levels of indirection into the Java
    ``LookAndFeel`` (LaF), which allows the user to change these values.  Further, when
    introducing this indirection we combine the Java settings into user-friendly system ids to make
    changing these values easier.
     
    
    This class defines these user-friendly groups.  The default system assignments are based on the
    :obj:`BasicLookAndFeel` values.
     
    
    Subclasses can override the mapping of these standard system values for particular LaFs that have
    different ids or color assignments.
     
    
    Some basic concepts:
      
    * UI Defaults - key-value pairs defined by the Java LaF; there are 2 key types, widget
    keys and Java group/reusable keys (e.g., Button.background; control)
    * UI Indirection - UI Defaults values are changed to point to custom terms we created to
    allow for indirection (e.g., Button.background -> laf.color.Button.background)
    * Normalized Keys - keys we created to facilitate the UI Indirection, based upon the Java
    keys (e.g., laf.color.Button.background)
    * System Color/Font Keys - user facing terms for common color or font concepts into an
    easy-to-change setting (e.g., system.color.fg.text)
    * Palette Keys - dynamically generated color palette keys based on the LaF for any colors
    and fonts that were not mapped into an system color or font (e.g.,
    laf.palette.color.01)
    
    
     
    
    The mapper performs the following operations:
      
    1. Extracts all color, font, and icon values from the UI Defaults.
    2. Use the current LaF values to populate the pre-defined system colors and fonts.
    3. Any UI Defaults values not assigned in the previous step will be assigned to a dynamic shared
    palette color or font.
    4. Update Java UI Defaults to use our indirection and system values.
    """

    @typing.type_check_only
    class ValueGrouper(java.lang.Object, typing.Generic[T]):
        """
        Used to match values (Colors or Fonts) into appropriate system groups. System group are
        searched in the order the groups are given in the constructor.
         
        
        Groups allow us to use the same group id for many components that by default have the same
        value (Color or Font).  This grouper allows us to specify the precedence to use when
        searching for the best group.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ColorGrouper(UiDefaultsMapper.ValueGrouper[java.awt.Color]):
        """
        Searches through all the system color ids registered for this matcher to find a system color
        id that matches a given color. The order that color system ids are added is important and is
        the precedence order if more than one system color id has the same color.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FontGrouper(UiDefaultsMapper.ValueGrouper[java.awt.Font]):
        """
        Searches through all the system font ids registered for this matcher to find a system font id
        that matches a given font. The order that system font ids are added is important and is
        the precedence order if more than one system id has the same font.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    LAF_COLOR_ID_PREFIX: typing.Final = "laf.color."
    LAF_FONT_ID_PREFIX: typing.Final = "laf.font."
    LAF_ICON_ID_PREFIX: typing.Final = "laf.icon."
    LAF_PROPERTY_PREFIX: typing.Final = "laf.property."
    """
    A prefix for UIManager properties that are not colors, fonts or icons (e.g., boolean)
    """


    def getNormalizedIdToLafIdMap(self) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns a mapping of normalized LaF Ids so that when fonts and icons get changed using the
        normalized ids that are presented to the user, we know which LaF ids need to be updated in
        the UiDefaults so that the LookAndFeel will pick up and use the changes.
        
        :return: a mapping of normalized LaF ids to original LaF ids.
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getNormalizedJavaDefaults(self) -> generic.theme.GThemeValueMap:
        """
        Returns the normalized id to value map that will be installed into the theme manager to be
        the user changeable values for affecting the Java LookAndFeel colors, fonts, and icons.
         
        
        The keys in the returned map have been normalized and all start with 'laf.'
        
        :return: a map of changeable values that affect java LookAndFeel values
        :rtype: generic.theme.GThemeValueMap
        """

    def installValuesIntoUIDefaults(self, currentValues: generic.theme.GThemeValueMap):
        """
        Updates the UIDefaults file with indirect colors (GColors) and any overridden font or icon
        values as defined in theme.properites files and saved themes.
        
        :param generic.theme.GThemeValueMap currentValues: a Map that contains all the values including those the may have
        been overridden by the theme.properties files or saved themes
        """

    @property
    def normalizedIdToLafIdMap(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def normalizedJavaDefaults(self) -> generic.theme.GThemeValueMap:
        ...


class WindowsClassicLookAndFeelManager(LookAndFeelManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class MetalLookAndFeelManager(LookAndFeelManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class CustomNimbusLookAndFeel(javax.swing.plaf.nimbus.NimbusLookAndFeel):
    """
    Extends the :obj:`NimbusLookAndFeel` (Nimbus) to intercept :meth:`getDefaults() <.getDefaults>`. Nimbus 
    does not honor changes to the UIDefaults after it is installed as the active
    :obj:`LookAndFeel`, so we have to make the changes at the time the UIDefaults are installed. 
     
    
    To get around this issue, we extend Nimbus so that we can install our GColors and
    overridden properties as Nimbus is being installed, specifically during the call to the 
    getDefaults() method. For all other Look And Feels, the GColors and overridden properties are 
    changed in the UIDefaults after the Look And Feel is installed, so they don't need to extend the
    Look and Feel class.
     
    
    Also, unlike other LaFs, Nimbus needs to be reinstalled every time we need to make a change to 
    any of the UIDefaults values, since it does not respond to changes other than when first 
    installed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNormalizedIdToLafIdMap(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def normalizedIdToLafIdMap(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...


class GtkLookAndFeelManager(LookAndFeelManager):
    """
    :obj:`LookAndFeelManager` for GTK
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class WindowsLookAndFeelManager(LookAndFeelManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class FontChangeListener(java.lang.Object):
    """
    A simple interface that signals the client has a font that should be updated when the theme is
    updated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fontChanged(self, fontId: typing.Union[java.lang.String, str], f: java.awt.Font):
        """
        Called when the client should update its font to the given font.
        
        :param java.lang.String or str fontId: the theme font id being updated
        :param java.awt.Font f: the font
        """


class FlatLookAndFeelManager(LookAndFeelManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, laf: generic.theme.LafType, themeManager: generic.theme.ApplicationThemeManager):
        ...


class MotifLookAndFeelManager(LookAndFeelManager):
    """
    Motif :obj:`LookAndFeelManager`. Specialized so that it can return the Motif installer
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class NimbusUiDefaultsMapper(UiDefaultsMapper):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LookAndFeelManager(java.lang.Object):
    """
    Manages installing and updating a :obj:`LookAndFeel`
    """

    class_: typing.ClassVar[java.lang.Class]

    def colorsChanged(self):
        """
        Called when one or more colors have changed.
        """

    def fontsChanged(self, changedFontIds: java.util.Set[java.lang.String]):
        """
        Called when one or more fonts have changed.
         
        
        This will update the Java :obj:`UIManager` and trigger a reload of the UIs.
        
        :param java.util.Set[java.lang.String] changedFontIds: the set of Java Font ids that are affected by this change; these are
        the normalized ids
        """

    @staticmethod
    def getLookAndFeelIdsForType(defaults: javax.swing.UIDefaults, clazz: java.lang.Class[typing.Any]) -> java.util.List[java.lang.String]:
        """
        Searches the given UIDefaults for ids whose value matches the given class
        
        :param javax.swing.UIDefaults defaults: the UIDefaults to search
        :param java.lang.Class[typing.Any] clazz: the value class to look for (i.e., Color, Font, or Icon)
        :return: the list of ids whose value is of the given class type.
        :rtype: java.util.List[java.lang.String]
        """

    def getLookAndFeelType(self) -> generic.theme.LafType:
        """
        Returns the :obj:`LafType` managed by this manager.
        
        :return: the :obj:`LafType`
        :rtype: generic.theme.LafType
        """

    def iconsChanged(self, changedIconIds: java.util.Set[java.lang.String], newIcon: javax.swing.Icon):
        """
        Called when one or more icons have changed.
        
        :param java.util.Set[java.lang.String] changedIconIds: set of icon ids affected by this icon change
        :param javax.swing.Icon newIcon: the new icon to use for the given set of icon ids
        """

    def installCursorBlinkingProperties(self):
        ...

    def installLookAndFeel(self):
        """
        Installs the :obj:`LookAndFeel`
        
        :raises java.lang.ClassNotFoundException: if the ``LookAndFeel``
                class could not be found
        :raises java.lang.InstantiationException: if a new instance of the class
                couldn't be created
        :raises java.lang.IllegalAccessException: if the class or initializer isn't accessible
        :raises UnsupportedLookAndFeelException: if
                ``lnf.isSupportedLookAndFeel()`` is false
        """

    @typing.overload
    def registerFont(self, component: java.awt.Component, fontId: typing.Union[java.lang.String, str]):
        """
        Binds the component to the font identified by the given font id. Whenever the font for
        the font id changes, the component will be updated with the new font.
        
        :param java.awt.Component component: the component to set/update the font
        :param java.lang.String or str fontId: the id of the font to register with the given component
        """

    @typing.overload
    def registerFont(self, component: java.awt.Component, fontId: typing.Union[java.lang.String, str], fontStyle: typing.Union[jpype.JInt, int]):
        """
        Binds the component to the font identified by the given font id. Whenever the font for
        the font id changes, the component will be updated with the new font.
         
        
        This method is fairly niche and should not be called by most clients.  Instead, call
        :meth:`registerFont(Component, String) <.registerFont>`.
        
        :param java.awt.Component component: the component to set/update the font
        :param java.lang.String or str fontId: the id of the font to register with the given component
        :param jpype.JInt or int fontStyle: the font style
        """

    def resetAll(self, javaDefaults: generic.theme.GThemeValueMap):
        """
        Called when all colors, fonts, and icons may have changed
        
        :param generic.theme.GThemeValueMap javaDefaults: the current set of java defaults so that those ids can be updated
        special as needed by the current :obj:`LookAndFeel`
        """

    def unRegisterFont(self, component: javax.swing.JComponent, fontId: typing.Union[java.lang.String, str]):
        """
        Removes the given component and id binding from this class.
        
        :param javax.swing.JComponent component: the component to remove
        :param java.lang.String or str fontId: the id used when originally registered
        
        .. seealso::
        
            | :obj:`.registerFont(Component, String)`
        """

    @property
    def lookAndFeelType(self) -> generic.theme.LafType:
        ...


class NimbusLookAndFeelManager(LookAndFeelManager):
    """
    Nimbus :obj:`LookAndFeelManager`. Specialized so that it can return the Nimbus installer and
    perform specialized updating when icons or fonts change. Basically, this class needs to
    re-install a new instance of the Nimbus LookAndFeel each time a font or icon changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, themeManager: generic.theme.ApplicationThemeManager):
        ...


class FlatDarkUiDefaultsMapper(FlatUiDefaultsMapper):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ComponentFontRegistry(java.lang.Object):
    """
    Maintains a weak set of components associated with a given font id. Whenever the font changes
    for the font id, this class will update the component's font to the new value.
    """

    @typing.type_check_only
    class StyledComponent(java.lang.Object):
        """
        A simple container that holds a font style and the component that uses that style.  The
        component is managed using a weak reference to help prevent memory leaks.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fontId: typing.Union[java.lang.String, str]):
        """
        Constructs a registry for components bound to the given font id
        
        :param java.lang.String or str fontId: the id of the font to update the containing components
        """

    @typing.overload
    def addComponent(self, component: java.awt.Component):
        """
        Adds a :obj:`Component` to the weak set of components whose font should be updated when
        the underlying font changes for this registry's font id.
        
        :param java.awt.Component component: the component to add
        """

    @typing.overload
    def addComponent(self, component: java.awt.Component, fontStyle: typing.Union[jpype.JInt, int]):
        """
        Allows clients to update the default font being used for a component to use the given style.
        
        :param java.awt.Component component: the component
        :param jpype.JInt or int fontStyle: the font style (e.g., :obj:`Font.BOLD`)
        """

    def removeComponent(self, component: java.awt.Component):
        """
        Removes the given component from this registry.
        
        :param java.awt.Component component: the component
        """

    def updateComponentFonts(self):
        """
        Updates the font for all components bound to this registry's font id.
        """


class FlatUiDefaultsMapper(UiDefaultsMapper):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FontNonUiResource(java.awt.Font):
    """
    Font subclass for creating an non UIResource Font from a FontUIResource. (The Font constructor
    that takes a font was protected)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, font: java.awt.Font):
        ...



__all__ = ["MotifUiDefaultsMapper", "MacLookAndFeelManager", "UiDefaultsMapper", "WindowsClassicLookAndFeelManager", "MetalLookAndFeelManager", "CustomNimbusLookAndFeel", "GtkLookAndFeelManager", "WindowsLookAndFeelManager", "FontChangeListener", "FlatLookAndFeelManager", "MotifLookAndFeelManager", "NimbusUiDefaultsMapper", "LookAndFeelManager", "NimbusLookAndFeelManager", "FlatDarkUiDefaultsMapper", "ComponentFontRegistry", "FlatUiDefaultsMapper", "FontNonUiResource"]
