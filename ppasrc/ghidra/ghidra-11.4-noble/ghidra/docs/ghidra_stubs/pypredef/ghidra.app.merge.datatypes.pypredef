from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.theme
import ghidra.app.merge
import ghidra.framework.data
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


K = typing.TypeVar("K")
V = typing.TypeVar("V")


@typing.type_check_only
class SourceArchiveMergePanel(javax.swing.JPanel):
    """
    Panel to select a source archive in order to resolve a conflict.
    """

    class_: typing.ClassVar[java.lang.Class]
    LATEST_BUTTON_NAME: typing.Final = "Latest"
    CHECKED_OUT_BUTTON_NAME: typing.Final = "Checked Out"
    ORIGINAL_BUTTON_NAME: typing.Final = "Original"


@typing.type_check_only
class CategoryMergePanel(javax.swing.JPanel):
    """
    Panel that shows a conflict for a category; gets user input to resolve
    the conflict.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class DataTypeMergeManager(ghidra.app.merge.MergeResolver):
    """
    Manager for merging category and data type changes
    """

    @typing.type_check_only
    class FixUpInfo(java.lang.Comparable[DataTypeMergeManager.FixUpInfo]):
        """
        FixUpInfo objects that must be resolved after
        data types have been added and conflicts resolved.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyIdentityHashMap(java.util.HashMap[K, V], typing.Generic[K, V]):
        """
        ``MyIdentityHashMap`` extends :obj:`HashMap` with the only difference being its 
        implementation of :meth:`hashCode() <.hashCode>` and :meth:`equals(Object) <.equals>` which are based purely on 
        the map instance identity and not its content.
         
        
        This unique implementation was created due to the use of this map as a key within another
        ``Map``.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.framework.data.DomainObjectMergeManager, resultDomainObject: ghidra.program.model.data.DataTypeManagerDomainObject, myDomainObject: ghidra.program.model.data.DataTypeManagerDomainObject, originalDomainObject: ghidra.program.model.data.DataTypeManagerDomainObject, latestDomainObject: ghidra.program.model.data.DataTypeManagerDomainObject, latestChanges: ghidra.program.model.listing.DataTypeChangeSet, myChanges: ghidra.program.model.listing.DataTypeChangeSet):
        """
        Manager for merging the data types using the four programs.
        
        :param ghidra.framework.data.DomainObjectMergeManager mergeManager: overall merge manager for domain object
        :param ghidra.program.model.data.DataTypeManagerDomainObject resultDomainObject: the program to be updated with the result of the merge.
        This is the program that will actually get checked in.
        :param ghidra.program.model.data.DataTypeManagerDomainObject myDomainObject: the program requesting to be checked in.
        :param ghidra.program.model.data.DataTypeManagerDomainObject originalDomainObject: the program that was checked out.
        :param ghidra.program.model.data.DataTypeManagerDomainObject latestDomainObject: the latest checked-in version of the program.
        :param ghidra.program.model.listing.DataTypeChangeSet latestChanges: the address set of changes between original and latest versioned program.
        :param ghidra.program.model.listing.DataTypeChangeSet myChanges: the address set of changes between original and my modified program.
        """

    def merge(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Merge the data types using the four programs.
        
        :param ghidra.util.task.TaskMonitor monitor: merge task monitor
        
        .. seealso::
        
            | :obj:`MergeConstants`
        """


@typing.type_check_only
class DataTypePanel(javax.swing.JPanel):
    """
    Panel to show the contents of a Data Type.
    """

    @typing.type_check_only
    class EnumEntry(java.lang.Comparable[DataTypePanel.EnumEntry]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    SOURCE_COLOR: generic.theme.GColor


@typing.type_check_only
class CategoryConflictPanel(javax.swing.JPanel):
    """
    Shows radio buttons to resolve conflict for category.
    """

    class_: typing.ClassVar[java.lang.Class]
    LATEST_BUTTON_NAME: typing.Final = "LatestVersionRB"
    CHECKED_OUT_BUTTON_NAME: typing.Final = "CheckedOutVersionRB"
    ORIGINAL_BUTTON_NAME: typing.Final = "OriginalVersionRB"


@typing.type_check_only
class SourceArchivePanel(javax.swing.JPanel):
    """
    Panel to show the contents of a Source Archive.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setSourceArchive(self, sourceArchive: ghidra.program.model.data.SourceArchive):
        ...


@typing.type_check_only
class DataTypeMergePanel(javax.swing.JPanel):
    """
    Panel to select a data type in order to resolve a conflict.
    """

    class_: typing.ClassVar[java.lang.Class]
    LATEST_BUTTON_NAME: typing.Final = "Latest"
    CHECKED_OUT_BUTTON_NAME: typing.Final = "Checked Out"
    ORIGINAL_BUTTON_NAME: typing.Final = "Original"



__all__ = ["SourceArchiveMergePanel", "CategoryMergePanel", "DataTypeMergeManager", "DataTypePanel", "CategoryConflictPanel", "SourceArchivePanel", "DataTypeMergePanel"]
