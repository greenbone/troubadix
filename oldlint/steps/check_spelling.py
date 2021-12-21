#!/usr/bin/env python3

import subprocess, os, re
import sys

# https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def subprocess_codespell(command):
    """This script creates a subprocess and obtains its output

    Args:
        command: The command that is being executed inside the subprocess

    Returns:
        string: The outcome of the executed command for further processing

    """

    process = subprocess.Popen(
        str(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )
    out, err = process.communicate()

    if err and "RuntimeWarning: " not in err.decode("latin-1"):
        return err.decode("latin-1")
    if out:
        return out.decode("latin-1")


def has_spelling_errors(file, cwdir, vtdir, full, include_regex, exclude_regex):
    """'codespell' is required to execute this step!
    This script opens a shell in a subprocess and executes 'codespell' to check the VT for spelling mistakes.
    An error will be thrown if 'codespell' is not installed or corrections could be found via 'codespell'.

    Args:
        file: The VT that is going to be checked
        cwdir: The current working dir of the main script (including the codespell.exclude)
        vtdir: The directory of the VT scripts
        full: If the complete directory and not only a single script should be checked
        include_regex: A regex (passed from the main script) for files which are included in this run
        exclude_regex: A regex (passed from the main script) for files which are excluded in this run

    Returns:
        tuples: 0 => Success, no message
                1 => Success, with debug message
               -1 => Error, with error message

    """

    program = which("codespell")
    if program is None:
        return (
            -1,
            "codespell tool not found within your PATH. Please install it "
            "via e.g. 'pip3 install codespell' or 'apt-get install codespell' "
            "and make sure it is available within your PATH.",
        )

    basedir = str(vtdir) + "/"
    include = False
    exclude = False

    if include_regex is not None and len(include_regex) > 0:
        include = True
    if exclude_regex is not None and len(exclude_regex) > 0:
        exclude = True

    if full:
        codespell = subprocess_codespell(
            "codespell --hard-encoding-detection --dictionary=- --dictionary="
            + cwdir
            + "/codespell.additions --exclude-file="
            + cwdir
            + "/codespell.exclude --ignore-words="
            + cwdir
            + "/codespell.ignore --skip=bad_ssh_host_keys.inc,*.txt,*.asc --disable-colors "
            + basedir
        )
    else:
        codespell = subprocess_codespell(
            "codespell --hard-encoding-detection --dictionary=- --dictionary="
            + cwdir
            + "/codespell.additions --exclude-file="
            + cwdir
            + "/codespell.exclude --ignore-words="
            + cwdir
            + "/codespell.ignore --skip=bad_ssh_host_keys.inc --disable-colors "
            + basedir
            + str(file)
        )

    if (
        codespell is not None
        and "Traceback (most recent call last):" not in codespell
    ):
        _codespell = codespell.splitlines()
        codespell = ""
        for line in _codespell:
            if include:
                include_file = re.search(include_regex, line)
                if include_file is None:
                    continue

            if exclude:
                exclude_file = re.search(exclude_regex, line)
                if exclude_file is not None:
                    continue

            # From /Policy which is just a huge blob of text and too large for codespell.exclude:
            if "policy_file_checksums_win.nasl" in line:
                if re.search("nD\s+==>\s+and, 2nd", line) or re.search(
                    "oD\s+==>\s+of", line
                ):
                    continue

            # Same for a few other files:
            if "smtp_AV_42zip_DoS.nasl" in line and re.search(
                "BA\s+==>\s+BY, BE", line
            ):
                continue

            if "wmi_misc.inc" in line:
                if re.search("BA\s+==>\s+BY, BE", line) or re.search(
                    "OD\s+==>\s+OF", line
                ):
                    continue

            if (
                "ssl_funcs.inc" in line
                or "gb_ssl_tls_cert_details.nasl" in line
            ):
                if re.search("fpr\s+==>\s+for, far, fps", line):
                    continue

            # Name of a Huawei product
            if (
                "gb_huawei" in line
                or "telnetserver_detect_type_nd_version.nasl" in line
            ):
                if re.search(
                    "eSpace\s+==>\s+escape", line, flags=re.IGNORECASE
                ):
                    continue

            # "ure" is a Debian package, again too many hits for codespell.exclude.
            if re.search(
                "(deb_(dla_)?[0-9]+(_[0-9]+)?|gb_ubuntu_.+)\.nasl", line
            ):
                if re.search("ure\s+==>\s+sure", line):
                    continue

            # gsf/PCIDSS VTs are currently using some german text parts
            # nb: codespell seems to have some issues with german umlauts in the codespell.exclude
            # so a few of these were also excluded here instead of directly via codespell.exclude.
            if (
                "PCIDSS/" in line
                or "GSHB/" in line
                or "ITG_Kompendium/" in line
            ):
                if re.search(
                    "(sie|ist|oder|prozess|manuell|unter|funktion|alle|als|tage|lokale|uptodate|paket|unter|titel|ba|ordner|modul|interaktive|programm|explizit|normale|applikation|attributen|lokal|signatur|modell|klick|generell)\s+==>\s+",
                    line,
                    flags=re.IGNORECASE,
                ):
                    continue

            # False positives in the gsf/PCIDSS and GSHB/ VTs:
            # string('\nIn the file
            # sent\nin milliseconds
            # There are too many hits to maintain them in codespell.exclude so exclude them for now here.
            if "PCIDSS/" in line or "GSHB/" in line:
                if re.search("n[iI]n\s+==>\s+inn", line):
                    continue

            # False positive in this VT in German example responses.
            if "gb_exchange_server_CVE-2021-26855_active.nasl" in line:
                if re.search("ist\s+==>\s+is", line):
                    continue

            # Mostly a false positive in LSCs because of things like "ALSA: hda" or a codec called "Conexant".
            # There are too many hits to maintain them in codespell.exclude so exclude them for now here.
            if re.search("gb_(sles|(open)?suse)_.+\.nasl", line):
                if re.search(
                    "(hda|conexant)\s+==>\s+(had|connexant)",
                    line,
                    flags=re.IGNORECASE,
                ):
                    continue

            # Jodie Chancel is a security reseacher who is mentioned many times in Mozilla advisories
            if re.search(
                "gb_mozilla_firefox_mfsa_\d{4}-\d{2,4}_lin\.nasl", line
            ) and re.search("Chancel\s+==>\s+Cancel", line):
                continue

            codespell += line + "\n"

    if codespell is not None and "==>" in codespell:
        return -1, codespell
    elif (
        codespell is not None
        and "Traceback (most recent call last):" in codespell
    ):
        return 1, codespell
    else:
        return (0,)


if __name__ == "__main__":
    import ci_helpers

    error, debug = [], []
    files = ci_helpers.list_modified_files()
    if not files:
        sys.exit(0)

    for file in files:
        test = has_spelling_errors(file, ".", ".", False, "", "")
        if test[0] == -1:
            error.append(test[1])
        if test[0] == 1:
            debug.append(test[1])

    if len(debug) > 0:
        ci_helpers.report("Files having spelling mistakes", debug)

    if len(error) > 0:
        ci_helpers.report("Files having spelling mistakes", error)
        sys.exit(-1)

    sys.exit(0)
