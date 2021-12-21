#!/usr/bin/env python3

import subprocess, re
from time import strftime, gmtime
from sys import version_info, exit, argv
import os

if version_info < (3,):
    exit("Python < 3 is not supported")


def subprocess_cmd(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout


"""
    This function adds a modified file for commit.
    Per default, modified files are not staged for commit and thus by setting modification_date
    and script_version, the new entries would not be added when committing.
"""


def git_add_file(file):
    os.chdir("../")
    filename = os.path.join(vtdir, file)
    subprocess_cmd("git add " + filename)
    os.chdir(vtdir)


"""
    This function removes any remaining SVN $Id$ tag(s) and replaces any of the following:
    script_tag(name:"last_modification", value:"2018-06-01 10:18:42 +0200 (Fri, 01 Jun 2018)");
    script_tag(name:"last_modification", value:"$Date: 2018-06-01 10:18:42 +0700 (Fri, 01 Jun 2018) $");

    with:
    script_tag(name:"last_modification", value:"2018-06-02 10:18:42 +0000 (Sat, 01 Jun 2018)");

    It also replaces any of the following:
    script_version("$Revision: 4493 $");
    script_version("2017-12-20T08:01:27+0000");

    with:
    script_version("2018-09-25T08:01:27+0000");

    The time will be set to the current date and time (converted to +0000) whenever the script is being
    executed against the added and modified VTs.

    In addition it will "fix" any of the following:
    # Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
    script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
    script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
    script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");

    to use the following:
    # Copyright (C) 2018 Greenbone Networks GmbH
    script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");

    Args:
        file: The VT that is going to be modified
        time: The current time, timezone is GMT
"""


def replace_svn_props(file, time):

    try:
        text = open(file, encoding="iso-8859-1").read()
        changed = False

        svn_id = re.search("(\n# \$Id: .+\$\n)", text)
        if svn_id is not None and svn_id.group(1) is not None:
            text = text.replace(svn_id.group(1), "\n")
            changed = True

        version = re.search("script_version[\\s]*\([\\s]*(.+)\)[\\s]*;", text)
        if version is not None and version.group(1) is not None:
            text = text.replace(
                version.group(0),
                'script_version("'
                + strftime("%Y-%m-%dT%H:%M:%S%z", time)
                + '");',
            )
            changed = True

        last_modification = re.search(
            "script_tag[\\s]*\([\\s]*name[\\s]*:[\\s]*[\"'][\\s]*last_modification[\\s]*[\"'][\\s]*,[\\s]*value[\\s]*:[\\s]*([\"'].*[\"'])[\\s]*\)[\\s]*\;",
            text,
        )
        if (
            last_modification is not None
            and last_modification.group(1) is not None
        ):
            text = text.replace(
                last_modification.group(0),
                'script_tag(name:"last_modification", value:"'
                + strftime("%Y-%m-%d %H:%M:%S %z (%a, %d %b %Y)", time)
                + '");',
            )
            changed = True

        # TODO: Remove the following below once the whole feed is "clean" (aka not using these anymore):
        drop_text = re.search(
            '(script_tag\s*\(\s*name\s*:\s*"summary"\s*,\s*value\s*:\s*"Th(e|is)\s+host\s+is\s+(installed|running)\s+(with\s*)?([^"]+)\s+(and|,?\s*which)\s+(is\s+(prone|vulnerable|affected)\s+(to|by)\s+([^"]+))"\s*\)\s*;)',
            text,
            re.MULTILINE | re.IGNORECASE,
        )
        if drop_text is not None and drop_text.group(1) is not None:
            replacement_text = (
                'script_tag(name:"summary", value:"'
                + drop_text.group(5)
                + " "
                + drop_text.group(7)
                + '");'
            )
            # nb: A few are using newlines with two following spaces, just use one space in that case for now.
            replacement_text = re.sub("\s{2,}", " ", replacement_text)
            # nb: And if a newline is used we want to just have a space so that the pattern below are matching
            replacement_text = re.sub("\n", " ", replacement_text)
            text = text.replace(drop_text.group(0), replacement_text)
            changed = True

        # After the "host is" fixes above finally fix a few "broken" (missing a/an, missing
        # abbreviation, ...) summary tags like e.g.:
        # - prone to arbitrary code execution vulnerability.
        # - prone to denial-of-service vulnerability.
        rewrite_text = re.search(
            '(script_tag\s*\(\s*name\s*:\s*"summary"\s*,\s*value\s*:\s*"[^"]+is\s+(prone|vulnerable|affected)\s+(to|by)\s+(unspecified|XML\s+External\s+Entity|integer\s+(und|ov)erflow|DLL\s+hijacking|(hardcoded?|default)\s+credentials?|open[\s-]+redirect(ion)?|user\s+enumeration|arbitrary\s+file\s+read|memory\s+corruption|use[\s-]+after[\s-]+free|man[\s-]+in[\s-]+the[\s-]+middle(\s+attack)?|cross[\s-]+site[\s-]+(scripting|request[\s-]+forgery)|denial[\s-]+of[\s-]+service|information\s+disclosure|(path|directory)\s+traversal|(arbitrary\s+|remote\s+)?((code|command)\s+(execution|injection)|file\s+inclusion)|SQL\s+injection|security|(local )?privilege[\s-]+(escalation|elevation)|(authentication|security|access)\s+bypass|(buffer|heap)\s+overflow)\s+vulnerability\.?)',
            text,
            re.MULTILINE | re.IGNORECASE,
        )
        if rewrite_text is not None and rewrite_text.group(1) is not None:
            old_tag_content = rewrite_text.group(1)
            vuln_name = rewrite_text.group(4)
            # nb: Some are writing the "V" uppercase
            new_tag_content = old_tag_content.replace(
                " Vulnerability", " vulnerability"
            )
            # Make the vulnerability name lowercase
            new_tag_content = new_tag_content.replace(
                vuln_name, vuln_name.lower()
            )
            # Rewrite stuff like denial-of-service to denial of service
            new_tag_content = new_tag_content.replace(
                "hardcode credential ", "hardcoded credentials"
            )
            new_tag_content = new_tag_content.replace(
                "hardcoded credential ", "hardcoded credentials"
            )
            new_tag_content = new_tag_content.replace(
                "hardcode credentials", "hardcoded credentials"
            )
            new_tag_content = new_tag_content.replace(
                "default credential ", "default credentials"
            )
            new_tag_content = new_tag_content.replace(
                "open-redirection", "open redirect"
            )
            new_tag_content = new_tag_content.replace(
                "open redirection", "open redirect"
            )
            new_tag_content = new_tag_content.replace(
                "open-redirect", "open redirect"
            )
            new_tag_content = new_tag_content.replace(
                "use-after free", "use after free"
            )
            new_tag_content = new_tag_content.replace(
                "use after-free", "use after free"
            )
            new_tag_content = new_tag_content.replace(
                "use-after-free", "use after free"
            )
            new_tag_content = new_tag_content.replace(
                "cross site scripting", "cross-site scripting"
            )
            new_tag_content = new_tag_content.replace(
                "cross site-scripting", "cross-site scripting"
            )
            new_tag_content = new_tag_content.replace(
                "cross site request forgery", "cross-site request forgery"
            )
            new_tag_content = new_tag_content.replace(
                "cross site-request forgery", "cross-site request forgery"
            )
            new_tag_content = new_tag_content.replace(
                "cross site-request-forgery", "cross-site request forgery"
            )
            new_tag_content = new_tag_content.replace(
                "cross site request-forgery", "cross-site request forgery"
            )
            new_tag_content = new_tag_content.replace(
                "cross-site-request-forgery", "cross-site request forgery"
            )
            new_tag_content = new_tag_content.replace(
                "denial-of-service", "denial of service"
            )
            new_tag_content = new_tag_content.replace(
                "denial-of service", "denial of service"
            )
            new_tag_content = new_tag_content.replace(
                "remote-code-execution", "remote code execution"
            )
            new_tag_content = new_tag_content.replace(
                "remote-code execution", "remote code execution"
            )
            new_tag_content = new_tag_content.replace(
                "remote-command-execution", "remote command execution"
            )
            new_tag_content = new_tag_content.replace(
                "remote-command execution", "remote command execution"
            )
            new_tag_content = new_tag_content.replace(
                "buffer-overflow", "buffer overflow"
            )
            new_tag_content = new_tag_content.replace(
                "heap-overflow", "heap overflow"
            )
            new_tag_content = new_tag_content.replace(
                "sql-injection", "sql injection"
            )
            # SQL, DLL and XML needs to be written in uppercase
            new_tag_content = new_tag_content.replace(
                "sql injection", "SQL injection"
            )
            new_tag_content = new_tag_content.replace(
                "dll hijacking", "DLL hijacking"
            )
            new_tag_content = new_tag_content.replace(
                "xml external entity", "XML external entity"
            )
            # Some have man-in-the-middle attack vulnerability, just throw out the "attack"
            new_tag_content = new_tag_content.replace(
                "man-in-the-middle attack", "man-in-the-middle"
            )
            # We want to write the following as "privilege escalation"
            new_tag_content = new_tag_content.replace(
                "privilege elevation", "privilege escalation"
            )
            new_tag_content = new_tag_content.replace(
                "privilege-elevation", "privilege escalation"
            )
            new_tag_content = new_tag_content.replace(
                "privilege-escalation", "privilege escalation"
            )
            # Add the abbreviation if applicable
            new_tag_content = new_tag_content.replace(
                "XML external entity", "XML external entity (XXE)"
            )
            new_tag_content = new_tag_content.replace(
                "man-in-the-middle", "man-in-the-middle (MITM)"
            )
            new_tag_content = new_tag_content.replace(
                "cross-site scripting", "cross-site scripting (XSS)"
            )
            new_tag_content = new_tag_content.replace(
                "cross-site request forgery",
                "cross-site request forgery (CSRF)",
            )
            new_tag_content = new_tag_content.replace(
                "denial of service", "denial of service (DoS)"
            )
            new_tag_content = new_tag_content.replace(
                "remote code execution", "remote code execution (RCE)"
            )
            new_tag_content = new_tag_content.replace(
                "remote command execution", "remote command execution (RCE)"
            )
            new_tag_content = new_tag_content.replace(
                "SQL injection", "SQL injection (SQLi)"
            )
            # Append a final dot to the string if missing
            if not new_tag_content.endswith("."):
                new_tag_content += "."
            # And finally prepend the "a/an"
            new_tag_content = new_tag_content.replace(
                "unspecified vulnerability", "an unspecified vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "XML external entity (XXE) vulnerability",
                "an XML external entity (XXE) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "integer underflow vulnerability",
                "an integer underflow vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "integer overflow vulnerability",
                "an integer overflow vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "DLL hijacking vulnerability", "a DLL hijacking vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "hardcoded credentials vulnerability",
                "a hardcoded credentials vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "default credentials vulnerability",
                "a default credentials vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "user enumeration vulnerability",
                "a user enumeration vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "arbitrary file read vulnerability",
                "an arbitrary file read vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "memory corruption vulnerability",
                "a memory corruption vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "use after free vulnerability", "a use after free vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "man-in-the-middle (MITM) vulnerability",
                "a man-in-the-middle (MITM) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "cross-site scripting (XSS) vulnerability",
                "a cross-site scripting (XSS) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "cross-site request forgery (CSRF) vulnerability",
                "a cross-site request forgery (CSRF) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "denial of service (DoS) vulnerability",
                "a denial of service (DoS) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "information disclosure vulnerability",
                "an information disclosure vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "path traversal vulnerability", "a path traversal vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "directory traversal vulnerability",
                "a directory traversal vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "arbitrary code execution vulnerability",
                "an arbitrary code execution vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "arbitrary command execution vulnerability",
                "an arbitrary command execution vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "arbitrary code injection vulnerability",
                "an arbitrary code injection vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "arbitrary command injection vulnerability",
                "an arbitrary command injection vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "remote code execution (RCE) vulnerability",
                "a remote code execution (RCE) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "remote command execution (RCE) vulnerability",
                "a remote command execution (RCE) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "remote code injection vulnerability",
                "a remote code injection vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "remote command injection vulnerability",
                "a remote command injection vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "to code execution vulnerability",
                "to a code execution vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "to command execution vulnerability",
                "to a command execution vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "to code injection vulnerability",
                "to a code injection vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "to command injection vulnerability",
                "to a command injection vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "file inclusion vulnerability", "a file inclusion vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "SQL injection (SQLi) vulnerability",
                "an SQL injection (SQLi) vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "security vulnerability", "a security vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "to privilege escalation vulnerability",
                "to a privilege escalation vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "to local privilege escalation vulnerability",
                "to a local privilege escalation vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "authentication bypass vulnerability",
                "an authentication bypass vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "security bypass vulnerability",
                "a security bypass vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "access bypass vulnerability", "an access bypass vulnerability"
            )
            new_tag_content = new_tag_content.replace(
                "buffer overflow vulnerability",
                "a buffer overflow vulnerability",
            )
            new_tag_content = new_tag_content.replace(
                "heap overflow vulnerability", "a heap overflow vulnerability"
            )

            # And if the new tag differs from the old one write it back...
            if new_tag_content != old_tag_content:
                text = text.replace(old_tag_content, new_tag_content)
                changed = True

        # TODO: Move the following below into pandoras_box.py once the feed is "clean" (aka not using these anymore):
        copyright_text = re.search(
            "(^# (Text descriptions excerpted from a referenced source are\n# Copyright \([cC]\) of the respective author\(s\)|Text descriptions are largely excerpted from the referenced\n# advisor(y|ies), and are Copyright \([cC]\) (of )?(the |their )respective author\(s\)|Some text descriptions might be excerpted from the referenced\n# advisories, and are Copyright \(C\) by the respective right holder\(s\)))",
            text,
            re.MULTILINE,
        )
        if copyright_text is not None and copyright_text.group(1) is not None:
            text = text.replace(
                copyright_text.group(0),
                "# Some text descriptions might be excerpted from (a) referenced\n# source(s), and are Copyright (C) by the respective right holder(s).",
            )
            changed = True

        copyright_string = re.search(
            "(^# Copyright \(c\) ([0-9]+) Greenbone Networks GmbH[^\r\n]*)",
            text,
            re.MULTILINE,
        )
        if (
            copyright_string is not None
            and copyright_string.group(1) is not None
        ):
            text = text.replace(
                copyright_string.group(0),
                "# Copyright (C) "
                + copyright_string.group(2)
                + " Greenbone Networks GmbH",
            )
            changed = True

        copyright_string = re.search(
            '(^\s*script_copyright\("Copyright \(c\) ([0-9]+) Greenbone Networks GmbH[^"]*"\);)',
            text,
            re.MULTILINE,
        )
        if (
            copyright_string is not None
            and copyright_string.group(1) is not None
        ):
            text = text.replace(
                copyright_string.group(0),
                '  script_copyright("Copyright (C) '
                + copyright_string.group(2)
                + ' Greenbone Networks GmbH");',
            )
            changed = True

        copyright_string = re.search(
            '(^\s*script_copyright\("This script is Copyright \(C\) ([0-9]+) Greenbone Networks GmbH[^"]*"\);)',
            text,
            re.MULTILINE,
        )
        if (
            copyright_string is not None
            and copyright_string.group(1) is not None
        ):
            text = text.replace(
                copyright_string.group(0),
                '  script_copyright("Copyright (C) '
                + copyright_string.group(2)
                + ' Greenbone Networks GmbH");',
            )
            changed = True

        copyright_string = re.search(
            "(^# Copyright \(c\) ([0-9]+) E-Soft Inc\.[^\r\n]*)",
            text,
            re.MULTILINE,
        )
        if (
            copyright_string is not None
            and copyright_string.group(1) is not None
        ):
            text = text.replace(
                copyright_string.group(0),
                "# Copyright (C) " + copyright_string.group(2) + " E-Soft Inc.",
            )
            changed = True

        copyright_string = re.search(
            '(^\s*script_copyright\("Copyright \(c\) ([0-9]+) E-Soft Inc\.[^"]*"\);)',
            text,
            re.MULTILINE,
        )
        if (
            copyright_string is not None
            and copyright_string.group(1) is not None
        ):
            text = text.replace(
                copyright_string.group(0),
                '  script_copyright("Copyright (C) '
                + copyright_string.group(2)
                + ' E-Soft Inc.");',
            )
            changed = True

        copyright_string = re.search(
            '(^\s*script_copyright\("This script is Copyright \(C\) ([0-9]+) E-Soft Inc\.[^"]*"\);)',
            text,
            re.MULTILINE,
        )
        if (
            copyright_string is not None
            and copyright_string.group(1) is not None
        ):
            text = text.replace(
                copyright_string.group(0),
                '  script_copyright("Copyright (C) '
                + copyright_string.group(2)
                + ' E-Soft Inc.");',
            )
            changed = True

        if changed:
            to_write = open(file, "w", encoding="iso-8859-1")
            to_write.write(text)

            to_write.close()

    except Exception as e:
        print(e)


deprecated_env_var_found = False

try:
    vtdir = os.environ["NVTDIR"]
    deprecated_env_var_found = True
except:
    try:
        vtdir = os.environ["VTDIR"]
    except:
        print(
            "Global '$VTDIR' variable is not set (e.g. in your .bashrc). Exiting..."
        )
        exit(-1)

if deprecated_env_var_found:
    print(
        "Deprecated '$NVTDIR' environment variable found. Please rename the variable to '$VTDIR'"
    )

# switch from current dir into vt parent dir (since git hooks run in special dir)
os.chdir(vtdir)
os.chdir("../")
files = (
    subprocess_cmd(
        "git -c color.status=false --no-pager status --short | egrep '\.nasl$' | awk '/^\s*[RMA]/ { print $NF ; }' | sed 's/^scripts\///'"
    )
    .decode("latin-1")
    .splitlines()
)
if len(files) == 0:
    files = argv[1:]
if len(files) == 0:
    print(
        'No new or modified files detected via "git status". Replace SVN props will exit!\r\n'
    )
    exit(0)

os.chdir(vtdir)

# Calling gmtime() once before the loop
# to have equal timestamps between all added/modified VTs
time = gmtime()

try:
    for file in files:
        replace_svn_props(file, time)
        git_add_file(file)
except Exception as e:
    print(e)
    exit(-1)
else:
    print(
        "\nSuccessfully changed script_version and last_modification values in every added and modified VT.\nAlso removed any remaining $Id$ tag(s)."
    )
