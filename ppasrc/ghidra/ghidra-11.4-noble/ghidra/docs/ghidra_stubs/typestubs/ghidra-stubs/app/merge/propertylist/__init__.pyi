from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.merge
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import javax.swing # type: ignore


@typing.type_check_only
class PropertyListMergePanel(javax.swing.JPanel):
    """
    Panel to show conflicts for properties and the number of conflicts.
    """

    class_: typing.ClassVar[java.lang.Class]
    LATEST_BUTTON_NAME: typing.Final = "Latest"
    CHECKED_OUT_BUTTON_NAME: typing.Final = "Checked Out"
    ORIGINAL_BUTTON_NAME: typing.Final = "Original"


@typing.type_check_only
class ConflictPanel(javax.swing.JPanel):
    """
    Panel that shows differences for properties in Property Lists.
    """

    class_: typing.ClassVar[java.lang.Class]
    LATEST_BUTTON_NAME: typing.Final = "Latest"
    CHECKED_OUT_BUTTON_NAME: typing.Final = "Checked Out"
    ORIGINAL_BUTTON_NAME: typing.Final = "Original"


class PropertyListMergeManager(ghidra.app.merge.MergeResolver):
    """
    Manages options changes and conflicts between the latest versioned 
    Program and the Program that is being checked into version control.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultProgram: ghidra.program.model.listing.Program, myProgram: ghidra.program.model.listing.Program, originalProgram: ghidra.program.model.listing.Program, latestProgram: ghidra.program.model.listing.Program):
        """
        Construct a new PropertyListMergeManager.
        
        :param ghidra.app.merge.ProgramMultiUserMergeManager mergeManager: manages each stage of the merge/resolve conflict process
        :param ghidra.program.model.listing.Program resultProgram: latest version of the Program that is the 
        destination for changes that will be applied from the source program
        :param ghidra.program.model.listing.Program myProgram: source of changes to apply to the result
        program
        :param ghidra.program.model.listing.Program originalProgram: program that was originally checked out
        :param ghidra.program.model.listing.Program latestProgram: program that that is the latest version; the
        resultProgram and latestProgram start out the same
        """

    def apply(self):
        ...

    def cancel(self):
        ...

    def getDescription(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getPhases(self) -> jpype.JArray[jpype.JArray[java.lang.String]]:
        ...

    def merge(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def phases(self) -> jpype.JArray[jpype.JArray[java.lang.String]]:
        ...


@typing.type_check_only
class ConflictInfo(java.lang.Object):
    """
    Container for conflicts on a property name.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["PropertyListMergePanel", "ConflictPanel", "PropertyListMergeManager", "ConflictInfo"]
