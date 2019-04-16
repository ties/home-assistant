"""Validate manifests."""
import argparse
import pathlib
import sys

import networkx as nx

from typing import Dict, Optional

from .model import Integration, Config
from . import dependencies, manifest, codeowners

PLUGINS = [
    manifest,
    dependencies,
    codeowners,
]

ROOT = '[ROOT]'

def get_config() -> Config:
    """Return config."""
    if not pathlib.Path('requirements_all.txt').is_file():
        raise RuntimeError("Run from project root")

    return Config(
        root=pathlib.Path('.').absolute(),
        action='validate' if sys.argv[-1] == 'validate' else 'generate',
    )


def analyze_graph(integrations: Dict[str, Integration],
                  depending_on: Optional[str]) -> None:
    G = nx.DiGraph()

    G.add_node(ROOT)

    # Add all nodes:
    for manifest in integrations.values():
        G.add_node(manifest.manifest['domain'])

    # Add dependency edges
    #
    # In order of loading -> ROOT is the root of tree and has
    # outgoing edges (c.f. only incoming)
    for manifest in integrations.values():
        domain = manifest.manifest['domain']
        dependencies = manifest.manifest['dependencies']

        if len(dependencies) > 0:
            for dependency in dependencies:
                G.add_edge(dependency, domain)
        else:
            G.add_edge(ROOT, domain, default=True)

    n_comp = nx.number_weakly_connected_components(G)
    if n_comp is 1:
        print("[pass] all components are connected")
    else:
        print(f"[fail] dependencies are not consistent, {n_comp} components")

    found_cycle = False
    for cycle in nx.simple_cycles(G):
        found_cycle = True
        print(f"[error] cycle in dependencies ${'->'.join(cycle)}")

    # Now add number of descendants to each node:
    nx.set_node_attributes(G, {
        node: len(nx.descendants(G, node)) for node in G.nodes
    }, 'num_descendants')

    # Now mark the depth of all components:
    paths = nx.single_source_shortest_path(G, ROOT)
    for node, path in nx.single_source_shortest_path(G, ROOT).items():
        nx.set_node_attributes(G, { node: len(path) }, 'depth')

        nx.set_node_attributes(G, {
            elem: max(G.nodes[elem].get('max_depth', 0), len(path))
            for elem in path
        }, 'max_depth')

    # Get elements depending on [name]
    # first, reverse the edges, than take descendants
    if depending_on:
        if depending_on not in G.nodes:
            print(f"error: unknown component, '{depending_on}'")
            return

        dependants = nx.descendants(G, depending_on)
        print(f"dependants of '{depending_on}':")
        for dep in dependants:
            print(f"    {dep}")
                                                         

    # Delete nodes with max_depth = 1
    # deleted = 0
    # nodes = list(G.nodes.keys())
    # for node in nodes:
    #     if G.node[node]['max_depth'] <= 2:
    #         G.remove_node(node)
    #         deleted += 1

    # print("deleted", deleted)

    # nx.readwrite.graphml.write_graphml(G, 'manifest_tree.graphml')


def main(graph: bool=False, depending_on: Optional[str]=None):
    """Validate manifests."""
    try:
        config = get_config()
    except RuntimeError as err:
        print(err)
        return 1

    integrations = Integration.load_dir(
        pathlib.Path('homeassistant/components')
    )
    manifest.validate(integrations, config)
    dependencies.validate(integrations, config)
    codeowners.validate(integrations, config)

    # When we generate, all errors that are fixable will be ignored,
    # as generating them will be fixed.
    if config.action == 'generate':
        general_errors = [err for err in config.errors if not err.fixable]
        invalid_itg = [
            itg for itg in integrations.values()
            if any(
                not error.fixable for error in itg.errors
            )
        ]
    else:
        # action == validate
        general_errors = config.errors
        invalid_itg = [itg for itg in integrations.values() if itg.errors]

    print("Integrations:", len(integrations))
    print("Invalid integrations:", len(invalid_itg))

    if graph:
        analyze_graph(integrations, depending_on)

    if not invalid_itg and not general_errors:
        codeowners.generate(integrations, config)
        return 0

    print()
    if config.action == 'generate':
        print("Found errors. Generating files canceled.")
        print()

    if general_errors:
        print("General errors:")
        for error in general_errors:
            print("*", error)
        print()

    for integration in sorted(invalid_itg, key=lambda itg: itg.domain):
        print("Integration {}:".format(integration.domain))
        for error in integration.errors:
            print("*", error)
        print()

    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validate Home Assistant component manifests")
    parser.add_argument('--graph', action='store_true',
                        help='run graph analysis')
    parser.add_argument('--depending-on', type=str, default=None,
                        help='list components depending on [name]')

    args = parser.parse_args()
    sys.exit(main(graph=args.graph, depending_on=args.depending_on))
