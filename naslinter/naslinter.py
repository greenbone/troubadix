# Copyright (C) 2021 Greenbone Networks GmbH
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

""" Main module for naslinter """

from naslinter.argparser import parse_args
from naslinter.runner import Runner


def main(args=None):
    """Main process of greenbone-docker"""
    parsed_args = parse_args(args=args)

    runner = Runner()

    if parsed_args.full:
        print("Full run")

    if parsed_args.dirs:
        print("Running dirs ... ")
        if parsed_args.non_recursive:
            print("Running in not recursive mode ... ")
            for directory in parsed_args.dirs:
                runner.run(directory.glob("*.nasl"))
        else:
            for directory in parsed_args.dirs:
                runner.run(directory.glob("**/*.nasl"))
    elif parsed_args.files:
        print("Running files ... ")
        runner.run(parsed_args.files)


if __name__ == "__main__":
    main()
