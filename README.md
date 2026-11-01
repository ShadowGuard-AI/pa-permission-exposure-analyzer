# pa-permission-exposure-analyzer
Analyzes potential blast radius of a permission: who/what could be affected if a principal with a certain permission is compromised. Uses a graph database (e.g., NetworkX) to traverse permission dependencies. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-exposure-analyzer`

## Usage
`python3 main.py [root_path] [params]`

## Parameters
- `-h`: Show help message and exit
- `--principal`: The principal to analyze: owner, group, or others. Defaults to owner. Any other value is rejected with an error naming the valid values.
- `--permission`: The permission to analyze: read, write, or execute. Defaults to read. Any other value is rejected with an error naming the valid values.
- `--log-level`: Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.
- `--exclude`: List of glob patterns to exclude from analysis. A pattern is matched against each path relative to the root and against each entry name; matching files are skipped and matching directories are not descended into.

## Behavior notes
- The graph holds one edge per principal and file pair, carrying every permission relation that applies, so a file the owner can both read and write is found by both a read query and a write query.
- requirements.txt names the two libraries the code imports, networkx and rich. Earlier versions omitted networkx, which the tool cannot start without, and named pathspec, which the code did not use; pathspec has been removed and exclusions are matched with the standard library.

## License
Copyright (c) ShadowStrikeHQ
