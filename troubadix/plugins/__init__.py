# Copyright (C) 2021-2022 Greenbone AG
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

import difflib
from typing import Iterable, List

from troubadix.plugin import FilePlugin, FilesPlugin, Plugin
from troubadix.plugins.spaces_before_dots import CheckSpacesBeforeDots

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
from .double_end_points import CheckDoubleEndPoints
from .duplicate_oid import CheckDuplicateOID
from .duplicated_script_tags import CheckDuplicatedScriptTags
from .encoding import CheckEncoding
from .forking_nasl_functions import CheckForkingNaslFunctions
from .get_kb_on_services import CheckGetKBOnServices
from .grammar import CheckGrammar
from .http_links_in_tags import CheckHttpLinksInTags
from .if_statement_syntax import CheckIfStatementSyntax
from .illegal_characters import CheckIllegalCharacters
from .log_messages import CheckLogMessages
from .malformed_dependencies import CheckMalformedDependencies
from .misplaced_compare_in_if import CheckMisplacedCompareInIf
from .missing_desc_exit import CheckMissingDescExit
from .missing_tag_solution import CheckMissingTagSolution
from .multiple_re_parameters import CheckMultipleReParameters
from .newlines import CheckNewlines
from .overlong_description_lines import CheckOverlongDescriptionLines
from .overlong_script_tags import CheckOverlongScriptTags
from .prod_svc_detect_in_vulnvt import CheckProdSvcDetectInVulnvt
from .qod import CheckQod
from .reporting_consistency import CheckReportingConsistency
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
from .severity_date import CheckSeverityDate
from .severity_format import CheckSeverityFormat
from .severity_origin import CheckSeverityOrigin
from .solution_text import CheckSolutionText
from .solution_type import CheckSolutionType
from .spaces_in_filename import CheckSpacesInFilename
from .spelling import CheckSpelling
from .tabs import CheckTabs
from .todo_tbd import CheckTodoTbd
from .trailing_spaces_tabs import CheckTrailingSpacesTabs
from .using_display import CheckUsingDisplay
from .valid_oid import CheckValidOID
from .valid_script_tag_names import CheckValidScriptTagNames
from .variable_assigned_in_if import CheckVariableAssignedInIf
from .variable_redefinition_in_foreach import CheckVariableRedefinitionInForeach
from .vt_file_permissions import CheckVTFilePermissions
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
    CheckDoubleEndPoints,
    CheckDuplicatedScriptTags,
    CheckEncoding,
    CheckForkingNaslFunctions,
    CheckGetKBOnServices,
    CheckGrammar,
    CheckHttpLinksInTags,
    CheckIllegalCharacters,
    CheckLogMessages,
    CheckMalformedDependencies,
    CheckMisplacedCompareInIf,
    CheckMissingDescExit,
    CheckMissingTagSolution,
    CheckMultipleReParameters,
    CheckNewlines,
    CheckOverlongDescriptionLines,
    CheckOverlongScriptTags,
    CheckProdSvcDetectInVulnvt,
    CheckQod,
    CheckReportingConsistency,
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
    CheckSeverityDate,
    CheckSeverityFormat,
    CheckSeverityOrigin,
    CheckSolutionText,
    CheckSolutionType,
    CheckSpacesInFilename,
    CheckTabs,
    CheckTodoTbd,
    CheckTrailingSpacesTabs,
    CheckUsingDisplay,
    CheckValidOID,
    CheckValidScriptTagNames,
    CheckVariableAssignedInIf,
    CheckVariableRedefinitionInForeach,
    CheckVTFilePermissions,
    CheckVTPlacement,
    CheckWrongSetGetKBCalls,
    CheckSpacesBeforeDots,
    CheckIfStatementSyntax,
]

# plugins checking all files
_FILES_PLUGINS = [
    CheckDuplicateOID,
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
            self._check_unknown_plugins(excluded_plugins)

            file_plugins = self._exclude_plugins(excluded_plugins, file_plugins)
            files_plugins = self._exclude_plugins(
                excluded_plugins, files_plugins
            )

        if included_plugins:
            self._check_unknown_plugins(included_plugins)

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

    @staticmethod
    def _check_unknown_plugins(selected_plugins: list[str]):
        all_plugin_names = {
            name
            for plugin in _FILE_PLUGINS + _FILES_PLUGINS
            for name in (plugin.name, plugin.__name__)
        }

        unknown_plugins = set(selected_plugins).difference(all_plugin_names)

        if not unknown_plugins:
            return

        def build_message(plugin: str):
            match = difflib.get_close_matches(plugin, all_plugin_names, n=1)
            return (
                f"'{plugin}' (Did you mean '{match[0]}'?)"
                if match
                else f"'{plugin}'"
            )

        messages = [build_message(plugin) for plugin in sorted(unknown_plugins)]
        raise ValueError(f"Unknown plugins: {', '.join(messages)}")
