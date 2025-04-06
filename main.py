import argparse
import logging
import os
import sys
import stat  # Import stat module

try:
    import networkx as nx
    from rich.console import Console
    from rich.table import Table
    from pathspec import PathSpec
    from pathspec.patterns import GitWildMatchPattern

except ImportError as e:
    print(f"Error importing required libraries: {e}")
    print("Please install the required packages: pip install networkx rich pathspec")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for permission analysis (can be extended)
READ_PERMISSION = "read"
WRITE_PERMISSION = "write"
EXECUTE_PERMISSION = "execute"

class PermissionExposureAnalyzer:
    """
    Analyzes potential blast radius of a permission by traversing permission dependencies
    within a file system structure represented as a graph.
    """

    def __init__(self, root_path):
        """
        Initializes the analyzer with a root path to analyze.

        Args:
            root_path (str): The root directory to start the permission analysis.
        """
        if not os.path.isdir(root_path):
            raise ValueError(f"Invalid root path: {root_path} is not a directory.")
        self.root_path = root_path
        self.graph = nx.DiGraph()  # Directed graph for permission dependencies
        self.console = Console()
        self.build_permission_graph()

    def build_permission_graph(self):
        """
        Builds the permission dependency graph by traversing the file system.
        Nodes represent files/directories, and edges represent permission relationships.
        """
        logging.info(f"Building permission graph starting from: {self.root_path}")
        for root, _, files in os.walk(self.root_path):
            # Add directory node
            self.add_node(root, "directory")
            for file in files:
                file_path = os.path.join(root, file)
                self.add_node(file_path, "file")
                self.add_edge(root, file_path, "contains")  # Directory contains file
                self.analyze_file_permissions(file_path)  # Analyze specific file permissions

    def add_node(self, path, node_type):
        """
        Adds a node to the graph, representing a file or directory.

        Args:
            path (str): The path to the file or directory.
            node_type (str): The type of node (e.g., "file", "directory").
        """
        if not self.graph.has_node(path):
            self.graph.add_node(path, type=node_type)
            logging.debug(f"Added node: {path} (type: {node_type})")

    def add_edge(self, source, target, relation):
        """
        Adds an edge to the graph, representing a relationship between two nodes.

        Args:
            source (str): The source node path.
            target (str): The target node path.
            relation (str): The type of relationship (e.g., "contains", "read_access").
        """
        if not self.graph.has_edge(source, target):
            self.graph.add_edge(source, target, relation=relation)
            logging.debug(f"Added edge: {source} -> {target} (relation: {relation})")

    def analyze_file_permissions(self, file_path):
        """
        Analyzes the permissions of a file and adds corresponding edges to the graph.
        This simplified implementation checks for read, write, and execute permissions
        for the owner, group, and others. A more comprehensive analysis would involve
        ACLs and extended attributes.

        Args:
            file_path (str): The path to the file to analyze.
        """
        try:
            st = os.stat(file_path)
            mode = st.st_mode

            # Owner permissions
            if mode & stat.S_IRUSR:  # Owner has read permission
                self.add_edge("owner", file_path, READ_PERMISSION)
            if mode & stat.S_IWUSR:  # Owner has write permission
                self.add_edge("owner", file_path, WRITE_PERMISSION)
            if mode & stat.S_IXUSR:  # Owner has execute permission
                self.add_edge("owner", file_path, EXECUTE_PERMISSION)

            # Group permissions
            if mode & stat.S_IRGRP:  # Group has read permission
                self.add_edge("group", file_path, READ_PERMISSION)
            if mode & stat.S_IWGRP:  # Group has write permission
                self.add_edge("group", file_path, WRITE_PERMISSION)
            if mode & stat.S_IXGRP:  # Group has execute permission
                self.add_edge("group", file_path, EXECUTE_PERMISSION)

            # Others permissions
            if mode & stat.S_IROTH:  # Others has read permission
                self.add_edge("others", file_path, READ_PERMISSION)
            if mode & stat.S_IWOTH:  # Others has write permission
                self.add_edge("others", file_path, WRITE_PERMISSION)
            if mode & stat.S_IXOTH:  # Others has execute permission
                self.add_edge("others", file_path, EXECUTE_PERMISSION)

        except OSError as e:
            logging.error(f"Error getting file stats for {file_path}: {e}")

    def find_affected_nodes(self, principal, permission):
        """
        Finds nodes affected by a principal having a certain permission.

        Args:
            principal (str): The principal (e.g., "owner", "group", "others").
            permission (str): The permission (e.g., "read", "write", "execute").

        Returns:
            list: A list of paths to nodes that are affected.
        """
        affected_nodes = []
        for node in self.graph.nodes():
            if self.graph.has_edge(principal, node, relation=permission):
                affected_nodes.append(node)
        return affected_nodes

    def print_affected_nodes(self, principal, permission):
        """
        Prints a table of affected nodes to the console.

        Args:
            principal (str): The principal (e.g., "owner", "group", "others").
            permission (str): The permission (e.g., "read", "write", "execute").
        """
        affected_nodes = self.find_affected_nodes(principal, permission)

        table = Table(title=f"Affected Nodes by {principal} with {permission} permission")
        table.add_column("Path", justify="left", style="cyan")
        table.add_column("Type", justify="left", style="magenta")

        for node in affected_nodes:
            node_type = self.graph.nodes[node].get("type", "unknown")
            table.add_row(node, node_type)

        self.console.print(table)

    def run_analysis(self, principal, permission):
        """
        Runs the permission exposure analysis for a given principal and permission.

        Args:
            principal (str): The principal to analyze.
            permission (str): The permission to analyze.
        """
        logging.info(f"Running analysis for principal: {principal}, permission: {permission}")
        self.print_affected_nodes(principal, permission)



def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Analyze potential blast radius of a permission.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "root_path",
        help="The root directory to start the permission analysis."
    )

    parser.add_argument(
        "--principal",
        default="owner",
        help="The principal to analyze (e.g., owner, group, others). Defaults to owner."
    )

    parser.add_argument(
        "--permission",
        default="read",
        help="The permission to analyze (e.g., read, write, execute). Defaults to read."
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO."
    )
    
    parser.add_argument(
        "--exclude",
        nargs="*",
        help="List of patterns to exclude from analysis (using gitignore syntax)."
    )

    return parser


def main():
    """
    Main function to execute the permission exposure analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level based on command-line argument
    logging.getLogger().setLevel(args.log_level)

    try:
        analyzer = PermissionExposureAnalyzer(args.root_path)
        analyzer.run_analysis(args.principal, args.permission)

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()