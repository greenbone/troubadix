# NASLinter
A linting tool for NASL files

## Installation

### Requirements

Python 3.7 and later is supported.

### Install using pip

pip 19.0 or later is required.

You can install the latest stable release of **naslinter** from the Python
Package Index (pypi) using [pip]

    python3 -m pip install --user naslinter

### Install using poetry

Because **naslinter** is a Python application you most likely need a tool to
handle Python package dependencies and Python environments. Therefore we
strongly recommend using [pipenv] or [poetry].

You can install the latest stable release of **naslinter** and add it as
a dependency for your current project using [poetry]

    poetry add naslinter

For installation via pipenv please take a look at their [documentation][pipenv].

## Development

**naslinter** uses [poetry] for its own dependency management and build
process.

First install poetry via pip

    python3 -m pip install --user poetry

Afterwards run

    poetry install

in the checkout directory of **naslinter** (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

Afterwards activate the git hooks for auto-formatting and linting via
[autohooks].

    poetry run autohooks activate

Validate the activated git hooks by running

    poetry run autohooks check

## Maintainer

This project is maintained by [Greenbone Networks GmbH][Greenbone Networks]

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/naslinter/pulls)
on GitHub. Bigger changes need to be discussed with the development team via the
[issues section at GitHub](https://github.com/greenbone/naslinter/issues)
first.

## License

Copyright (C) 2020-2021 [Greenbone Networks GmbH][Greenbone Networks]

Licensed under the [GNU General Public License v3.0 or later](LICENSE).

[Greenbone Networks]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[pipenv]: https://pipenv.pypa.io/
[autohooks]: https://github.com/greenbone/autohooks
