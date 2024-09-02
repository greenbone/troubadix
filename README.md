![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Troubadix
A linting and QA check tool for NASL files

[![GitHub releases](https://img.shields.io/github/release/greenbone/troubadix.svg)](https://github.com/greenbone/troubadix/releases)
[![PyPI release](https://img.shields.io/pypi/v/troubadix.svg)](https://pypi.org/project/troubadix/)
[![codecov](https://codecov.io/gh/greenbone/troubadix/branch/main/graph/badge.svg?token=FFMmVmAmtb)](https://codecov.io/gh/greenbone/troubadix)
[![Build and test](https://github.com/greenbone/troubadix/actions/workflows/ci-python.yml/badge.svg)](https://github.com/greenbone/troubadix/actions/workflows/ci-python.yml)


## Installation

### Requirements

Python 3.9 and later is supported.

### Install using pipx

You can install the latest stable release of **troubadix** from the Python
Package Index (pypi) using [pipx]

    python3 -m pipx install troubadix

### Install using pip

> [!NOTE]
> The `pip install` command does no longer work out-of-the-box in newer
> distributions like Ubuntu 23.04 because of [PEP 668](https://peps.python.org/pep-0668).
> Please use the [installation via pipx](#install-using-pipx) instead.

You can install the latest stable release of **troubadix** from the Python
Package Index (pypi) using [pip]

    python3 -m pip install --user troubadix

### Install using poetry

Because **troubadix** is a Python application you most likely need a tool to
handle Python package dependencies and Python environments. Therefore we
strongly recommend using [pipenv] or [poetry].

You can install the latest stable release of **troubadix** and add it as
a dependency for your current project using [poetry]

    poetry add troubadix

For installation via pipenv please take a look at their [documentation][pipenv].

## Development

**troubadix** uses [poetry] for its own dependency management and build
process.

First install poetry (see [documentation](https://python-poetry.org/docs/#installation)).

Afterwards run

    poetry install

in the checkout directory of **troubadix** (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

Afterwards activate the git hooks for auto-formatting and linting via
[autohooks].

    poetry run autohooks activate

Validate the activated git hooks by running

    poetry run autohooks check

## Maintainer

This project is maintained by [Greenbone AG][Greenbone]

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/troubadix/pulls)
on GitHub. Bigger changes need to be discussed with the development team via the
[issues section at GitHub](https://github.com/greenbone/troubadix/issues)
first.

## License

Copyright (C) 2021-2022 [Greenbone AG][Greenbone]

Licensed under the [GNU General Public License v3.0 or later](LICENSE).

[Greenbone]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[pipx]: https://pypa.github.io/pipx/
[pipenv]: https://pipenv.pypa.io/
[autohooks]: https://github.com/greenbone/autohooks
