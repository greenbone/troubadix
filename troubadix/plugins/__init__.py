# Copyright (C) 2021-2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from typing import Iterable, List

from troubadix.plugin import FilePlugin, FilesPlugin, Plugin

from .badwords import CheckBadwords
from .copyright_text import CheckCopyrightText
from .copyright_year import CheckCopyrightYear
from .creation_date import CheckCreationDate
from .cve_format import CheckCVEFormat
from .cvss_format import CheckCVSSFormat
from .dependencies import CheckDependencies
from .dependency_category_order import CheckDependencyCategoryOrder
from .deprecated_dependency import CheckDeprecatedDependency
from .deprecated_functions import CheckDeprecatedFunctions
from .description import CheckDescription
from .double_end_points import CheckDoubleEndPoints
from .duplicate_oid import CheckDuplicateOID
from .duplicated_script_tags import CheckDuplicatedScriptTags
from .encoding import CheckEncoding
from .forking_nasl_functions import CheckForkingNaslFunctions
from .get_kb_on_services import CheckGetKBOnServices
from .grammar import CheckGrammar
from .http_links_in_tags import CheckHttpLinksInTags
from .illegal_characters import CheckIllegalCharacters
from .log_messages import CheckLogMessages
from .misplaced_compare_in_if import CheckMisplacedCompareInIf
from .missing_desc_exit import CheckMissingDescExit
from .missing_tag_solution import CheckMissingTagSolution
from .newlines import CheckNewlines
from .no_solution import CheckNoSolution
from .overlong_script_tags import CheckOverlongScriptTags
from .prod_svc_detect_in_vulnvt import CheckProdSvcDetectInVulnvt
from .qod import CheckQod
from .reporting_consistency import CheckReportingConsistency
from .risk_factor import CheckRiskFactor
from .script_add_preference_type import CheckScriptAddPreferenceType
from .script_calls_empty_values import CheckScriptCallsEmptyValues
from .script_calls_recommended import CheckScriptCallsRecommended
from .script_category import CheckScriptCategory
from .script_copyright import CheckScriptCopyright
from .script_family import CheckScriptFamily
from .script_tag_form import CheckScriptTagForm
from .script_tag_whitespaces import CheckScriptTagWhitespaces
from .script_tags_mandatory import CheckScriptTagsMandatory
from .script_version_and_last_modification_tags import (
    CheckScriptVersionAndLastModificationTags,
)
from .script_xref_form import CheckScriptXrefForm
from .script_xref_url import CheckScriptXrefUrl
from .security_messages import CheckSecurityMessages
from .set_get_kb_calls import CheckWrongSetGetKBCalls
from .solution_text import CheckSolutionText
from .solution_type import CheckSolutionType
from .spelling import CheckSpelling
from .tabs import CheckTabs
from .todo_tbd import CheckTodoTbd
from .trailing_spaces_tabs import CheckTrailingSpacesTabs
from .using_display import CheckUsingDisplay
from .valid_oid import CheckValidOID
from .valid_script_tag_names import CheckValidScriptTagNames
from .variable_assigned_in_if import CheckVariableAssignedInIf
from .vt_file_permission import CheckVTFilePermissions
from .vt_placement import CheckVTPlacement

# plugins checking single files
_FILE_PLUGINS = [
    CheckBadwords,
    CheckCopyrightText,
    CheckCopyrightYear,
    CheckCreationDate,
    CheckCVEFormat,
    CheckCVSSFormat,
    CheckDependencies,
    CheckDependencyCategoryOrder,
    CheckDeprecatedDependency,
    CheckDeprecatedFunctions,
    CheckDescription,
    CheckDoubleEndPoints,
    CheckDuplicatedScriptTags,
    CheckEncoding,
    CheckForkingNaslFunctions,
    CheckGetKBOnServices,
    CheckGrammar,
    CheckHttpLinksInTags,
    CheckIllegalCharacters,
    CheckLogMessages,
    CheckMisplacedCompareInIf,
    CheckMissingDescExit,
    CheckMissingTagSolution,
    CheckNewlines,
    CheckOverlongScriptTags,
    CheckProdSvcDetectInVulnvt,
    CheckQod,
    CheckReportingConsistency,
    CheckRiskFactor,
    CheckScriptAddPreferenceType,
    CheckScriptCallsEmptyValues,
    CheckScriptCallsRecommended,
    CheckScriptCategory,
    CheckScriptCopyright,
    CheckScriptFamily,
    CheckScriptTagForm,
    CheckScriptTagsMandatory,
    CheckScriptTagWhitespaces,
    CheckScriptVersionAndLastModificationTags,
    CheckScriptXrefForm,
    CheckScriptXrefUrl,
    CheckSecurityMessages,
    CheckSolutionText,
    CheckSolutionType,
    CheckTabs,
    CheckTodoTbd,
    CheckTrailingSpacesTabs,
    CheckUsingDisplay,
    CheckValidOID,
    CheckValidScriptTagNames,
    CheckVariableAssignedInIf,
    CheckVTFilePermissions,
    CheckVTPlacement,
    CheckWrongSetGetKBCalls,
]

# plugins checking all files
_FILES_PLUGINS = [
    CheckDuplicateOID,
    CheckNoSolution,
    CheckSpelling,
]


class Plugins:
    def __init__(
        self,
        file_plugins: Iterable[FilePlugin] = None,
        files_plugins: Iterable[FilesPlugin] = None,
    ):
        self.file_plugins = tuple(file_plugins) or tuple()
        self.files_plugins = tuple(files_plugins) or tuple()

    def __len__(self) -> int:
        return len(self.files_plugins + self.file_plugins)

    def __iter__(self) -> Iterable[Plugin]:
        return iter(self.files_plugins + self.file_plugins)


class StandardPlugins(Plugins):
    def __init__(
        self,
        excluded_plugins: List[str] = None,
        included_plugins: List[str] = None,
    ) -> None:
        file_plugins = _FILE_PLUGINS
        files_plugins = _FILES_PLUGINS
        if excluded_plugins:
            file_plugins = self._exclude_plugins(excluded_plugins, file_plugins)
            files_plugins = self._exclude_plugins(
                excluded_plugins, files_plugins
            )

        if included_plugins:
            file_plugins = self._include_plugins(included_plugins, file_plugins)
            files_plugins = self._include_plugins(
                included_plugins, files_plugins
            )

        super().__init__(file_plugins=file_plugins, files_plugins=files_plugins)

    @staticmethod
    def _exclude_plugins(
        excluded: Iterable[str], plugins: Iterable[Plugin]
    ) -> List[Plugin]:
        return [
            plugin
            for plugin in plugins
            if plugin.__name__ not in excluded and plugin.name not in excluded
        ]

    @staticmethod
    def _include_plugins(
        included: Iterable[str], plugins: Iterable[Plugin]
    ) -> List[Plugin]:
        return [
            plugin
            for plugin in plugins
            if plugin.__name__ in included or plugin.name in included
        ]
