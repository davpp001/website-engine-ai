#!/bin/bash
# ShellCheck linting for all shell scripts in the repo
find . -name '*.sh' -exec shellcheck {} +
