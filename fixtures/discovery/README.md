# Synthetic discovery fixtures

`layout.json` contains only invented setup files and fake credential markers.
Tests materialize the same home/project/editor layout in temporary directories
for Linux, macOS and Windows path resolution. No host agent configuration,
environment credentials, session logs, browsers or remote services are read.

Malicious paths, excluded files, malformed configs, private-key markers,
oversize inputs and symlinks are created within each test's temporary fixture.
The fixtures deliberately do not contain usable keys or credentials.
