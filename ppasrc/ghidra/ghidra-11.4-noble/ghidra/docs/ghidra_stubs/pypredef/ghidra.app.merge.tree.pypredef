from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.merge
import ghidra.program.model.listing
import java.lang # type: ignore
import javax.swing # type: ignore


class ProgramTreeMergeManager(ghidra.app.merge.MergeResolver):
    """
    Manages changes and conflicts between the latest versioned Program and the
    Program that is being checked into version control.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultProgram: ghidra.program.model.listing.Program, myProgram: ghidra.program.model.listing.Program, originalProgram: ghidra.program.model.listing.Program, latestProgram: ghidra.program.model.listing.Program, latestChangeSet: ghidra.program.model.listing.ProgramChangeSet, myChangeSet: ghidra.program.model.listing.ProgramChangeSet):
        """
        Construct a new manager for merging trees
        
        :param ghidra.app.merge.ProgramMultiUserMergeManager mergeManager: the program merge manager
        :param ghidra.program.model.listing.Program resultProgram: latest version of the Program that is the 
        destination for changes applied from the source program
        :param ghidra.program.model.listing.Program myProgram: source of changes to apply to the destination
        program
        :param ghidra.program.model.listing.Program originalProgram: program that was originally checked out
        :param ghidra.program.model.listing.Program latestProgram: program that is the latest version; the
        resultProgram and latestProgram start out as being identical
        :param ghidra.program.model.listing.ProgramChangeSet latestChangeSet: change set of the destination program
        :param ghidra.program.model.listing.ProgramChangeSet myChangeSet: change set for the source program
        """


@typing.type_check_only
class NameConflictsPanel(javax.swing.JPanel):
    """
    Panel to get user input to resolve name conflicts when private name of tree
    exists in destination program.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class TreeChangePanel(javax.swing.JPanel):
    """
    Panel to show whether tree name and tree structure changed.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ProgramTreeMergePanel(javax.swing.JPanel):
    """
    Panel for getting user input to resolve tree conflicts.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class NamePanel(javax.swing.JPanel):
    """
    Panel for resolving name conflicts among program trees when private
    name of tree does not exist in destination program.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ProgramTreeMergeManager", "NameConflictsPanel", "TreeChangePanel", "ProgramTreeMergePanel", "NamePanel"]
