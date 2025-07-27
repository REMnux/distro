from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import generic.theme
import java.awt # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.plaf # type: ignore


class LookAndFeelUtils(java.lang.Object):
    """
    A utility class to manage LookAndFeel (LaF) settings.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getLookAndFeelType() -> generic.theme.LafType:
        """
        Returns the :obj:`LafType` for the currently active :obj:`LookAndFeel`
        
        :return: the :obj:`LafType` for the currently active :obj:`LookAndFeel`
        :rtype: generic.theme.LafType
        """

    @staticmethod
    def installGlobalOverrides():
        """
        This method does nothing.  This is not handled by the theming system in the look and feel
        manager.
        """

    @staticmethod
    def isUsingAquaUI(UI: javax.swing.plaf.ComponentUI) -> bool:
        """
        Returns true if the given UI object is using the Aqua Look and Feel.
        
        :param javax.swing.plaf.ComponentUI UI: the UI to examine.
        :return: true if the UI is using Aqua
        :rtype: bool
        """

    @staticmethod
    def isUsingFlatUI() -> bool:
        """
        Returns true if the current UI is the FlatLaf Dark or FlatLaf Light Look and Feel.
        
        :return: true if the current UI is the FlatLaf Dark or FlatLaf Light Look and Feel
        :rtype: bool
        """

    @staticmethod
    def isUsingNimbusUI() -> bool:
        """
        Returns true if 'Nimbus' is the current Look and Feel
        
        :return: true if 'Nimbus' is the current Look and Feel
        :rtype: bool
        """

    @staticmethod
    def performPlatformSpecificFixups():
        ...


class ComponentInfoDialog(docking.DialogComponentProvider, java.beans.PropertyChangeListener):
    """
    Diagnostic dialog for display information about the components in a window and related focus
    information.
    """

    @typing.type_check_only
    class ComponentTableModel(docking.widgets.table.GDynamicColumnTableModel[ComponentInfoDialog.ComponentInfo, java.lang.Object]):

        @typing.type_check_only
        class ComponentNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class ToolTipColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class AccessibleNameColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class AccessibleDescriptionColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class ComponentClassColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class ComponentIdColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.Integer, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class ParentIdColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class TraversalKeysColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class FocusableColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.Boolean, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class IsFocusCycleRootColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.Boolean, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class focusCycleRootColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class CycleIndexColumn(docking.widgets.table.AbstractDynamicTableColumn[ComponentInfoDialog.ComponentInfo, java.lang.Integer, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ComponentInfo(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getClassSimpleName(self) -> str:
            ...

        def getComponent(self) -> java.awt.Component:
            ...

        def getCycleRootIndex(self) -> int:
            ...

        def getDepth(self) -> int:
            ...

        def getId(self) -> int:
            ...

        def getName(self) -> str:
            ...

        def getNameAndId(self) -> str:
            ...

        def getParent(self) -> ComponentInfoDialog.ComponentInfo:
            ...

        def getToolTip(self) -> str:
            ...

        def getTraversalComps(self) -> java.util.List[java.awt.Component]:
            ...

        def isCycleRoot(self) -> bool:
            ...

        def isFocusable(self) -> bool:
            ...

        @staticmethod
        def resetIds():
            ...

        @property
        def classSimpleName(self) -> java.lang.String:
            ...

        @property
        def parent(self) -> ComponentInfoDialog.ComponentInfo:
            ...

        @property
        def component(self) -> java.awt.Component:
            ...

        @property
        def depth(self) -> jpype.JInt:
            ...

        @property
        def nameAndId(self) -> java.lang.String:
            ...

        @property
        def cycleRoot(self) -> jpype.JBoolean:
            ...

        @property
        def toolTip(self) -> java.lang.String:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def focusable(self) -> jpype.JBoolean:
            ...

        @property
        def id(self) -> jpype.JInt:
            ...

        @property
        def cycleRootIndex(self) -> jpype.JInt:
            ...

        @property
        def traversalComps(self) -> java.util.List[java.awt.Component]:
            ...


    @typing.type_check_only
    class EventDisplayPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["LookAndFeelUtils", "ComponentInfoDialog"]
