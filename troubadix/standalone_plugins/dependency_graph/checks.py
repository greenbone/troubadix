# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Greenbone AG


from collections import Counter

import networkx as nx

from .models import Result, Script


def check_duplicates(scripts: list[Script]) -> Result:
    """
    checks for a script depending on a script multiple times
    """
    warnings = []
    for script in scripts:
        counter = Counter(dep.name for dep in script.dependencies)
        duplicates = [dep for dep, count in counter.items() if count > 1]

        if duplicates:
            msg = f"Duplicate dependencies in {script.name}: {', '.join(duplicates)}"
            warnings.append(msg)

    return Result(name="check_duplicates", warnings=warnings)


def check_missing_dependencies(
    scripts: list[Script], graph: nx.DiGraph
) -> Result:
    """
    Checks if any scripts that are depended on are missing from
    the list of scripts created from the local file system,
    logs the scripts dependending on the missing script
    """
    errors = []
    dependencies = {
        dep.name for script in scripts for dep in script.dependencies
    }
    script_names = {script.name for script in scripts}
    missing_dependencies = dependencies - script_names

    for missing in missing_dependencies:
        depending_scripts = graph.predecessors(missing)
        msg = f"missing dependency file: {missing}:"
        for script in depending_scripts:
            msg += f"\n  - used by: {script}"
        errors.append(msg)

    return Result(name="missing_dependencies", errors=errors)


def check_cycles(graph) -> Result:
    """
    checks for cyclic dependencies
    """
    if nx.is_directed_acyclic_graph(graph):
        return Result(name="check_cycles")

    cycles = nx.simple_cycles(graph)

    errors = [f"cyclic dependency: {cycle}" for cycle in cycles]
    return Result(name="check_cycles", errors=errors)


def cross_feed_dependencies(
    graph, is_enterprise_checked: bool
) -> list[tuple[str, str]]:
    """
    creates a list of script and dependency for scripts
    in community feed that depend on scripts in enterprise folders
    """
    cross_feed_dependencies = [
        (u, v)
        for u, v, is_enterprise_feed in graph.edges.data("is_enterprise_feed")
        if graph.nodes[u]["feed"] == "community"
        and graph.nodes[v].get("feed", "unknown") == "enterprise"
        and is_enterprise_feed == is_enterprise_checked
    ]  # unknown as standard value due to non existent nodes not having a feed value
    return cross_feed_dependencies


def check_cross_feed_dependencies(graph) -> Result:
    """
    Checks if scripts in the community feed have dependencies to enterprise scripts,
    and if they are correctly contained within a is_enterprise_feed check.
    """
    gated_cfd = cross_feed_dependencies(graph, is_enterprise_checked=True)
    warnings = [
        f"cross-feed-dependency: {dependent}(community feed) "
        f"depends on {dependency}(enterprise feed)"
        for dependent, dependency in gated_cfd
    ]

    ungated_cfd = cross_feed_dependencies(graph, is_enterprise_checked=False)
    errors = [
        f"unchecked cross-feed-dependency: {dependent}(community feed) "
        f"depends on {dependency}(enterprise feed), but the current feed is not properly checked"
        for dependent, dependency in ungated_cfd
    ]

    return Result(
        name="check_cross_feed_dependencies", warnings=warnings, errors=errors
    )


def check_category_order(graph) -> Result:
    problematic_edges = [
        (dependent, dependency)
        for dependent, dependency in graph.edges()
        if graph.nodes[dependent]["category"]
        < graph.nodes[dependency].get("category", -1)
    ]

    errors = [
        f"{dependent} depends on {dependency} which has a lower category order"
        for dependent, dependency in problematic_edges
    ]
    return Result(name="check_category_order", errors=errors)


def check_deprecated_dependencies(graph) -> Result:
    errors = [
        f"{dependent} depends on deprecated script {dependency}"
        for dependent, dependency in graph.edges()
        if graph.nodes[dependency].get("deprecated", False)
    ]
    return Result(name="check_deprecated_dependencies", errors=errors)
