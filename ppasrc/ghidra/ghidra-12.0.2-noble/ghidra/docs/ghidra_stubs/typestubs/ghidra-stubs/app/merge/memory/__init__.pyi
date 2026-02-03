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


@typing.type_check_only
class MemoryMergePanel(javax.swing.JPanel):
    """
    Panel to resolve conflicts on memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class BlockConflictPanel(javax.swing.JPanel):
    """
    Panel to show radio buttons to choose a name or a set of permissions
    for a memory block, or to resolve the conflict for the image base
    of the program.
    """

    class_: typing.ClassVar[java.lang.Class]


class MemoryMergeManager(ghidra.app.merge.MergeResolver):
    """
    Merge memory blocks that have changes to the name, permissions or comments.
    """

    @typing.type_check_only
    class ConflictInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultProgram: ghidra.program.model.listing.Program, myProgram: ghidra.program.model.listing.Program, originalProgram: ghidra.program.model.listing.Program, latestProgram: ghidra.program.model.listing.Program):
        """
        Constructor
        
        :param ghidra.app.merge.ProgramMultiUserMergeManager mergeManager: merge manager
        :param ghidra.program.model.listing.Program resultProgram: program where changes will be applied to
        :param ghidra.program.model.listing.Program myProgram: source program with changes that will be applied to
        result program
        :param ghidra.program.model.listing.Program originalProgram: original program that was checked out
        :param ghidra.program.model.listing.Program latestProgram: latest program that was checked in; the result
        program and latest program are initially identical
        """


@typing.type_check_only
class CommentsConflictPanel(javax.swing.JPanel):
    """
    Panel that shows the block comments; has radio buttons to choose
    which comment to use.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["MemoryMergePanel", "BlockConflictPanel", "MemoryMergeManager", "CommentsConflictPanel"]
