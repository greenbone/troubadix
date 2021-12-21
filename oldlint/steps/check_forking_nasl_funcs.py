#!/usr/bin/env python3

import re
import sys


def is_misusing_forking_funcs(file):
    """This script checks if any of the following functions are used more then once
        or in conjunction with other mentioned functions within the same VT:

    - get_app_port();
    - get_app_port_from_list();
    - get_app_port_from_cpe_prefix();
    - service_get_port();
    - unknownservice_get_port();
    - ftp_get_port();
    - http_get_port();
    - telnet_get_port();
    - smtp_get_port();
    - pop3_get_port();
    - imap_get_port();
    - ssh_get_port();
    - tls_ssl_get_port();
    - ldap_get_port();
    - snmp_get_port();
    - sip_get_port_proto();
    - rsync_get_port();
    - nntp_get_port();
    - tcp_get_all_port();
    - udp_get_all_port();

    In addition those specific functions *might* get a port from e.g. get_app_port() passed
    and are handled separately. These shouldn't be called together as well but the check is
    done independently from the ones above:

    - get_app_version();
    - get_app_location();
    - get_app_version_from_list();
    - get_app_version_and_location_from_list();
    - get_app_version_and_location();
    - get_app_location_and_proto();
    - get_app_version_and_proto();
    - get_app_full();
    - get_app_details();

    Args:
        file: The VT that is going to be checked

    Returns:
        tuples: 0 => Success, no message
               -1 => Error, with error message

    """
    # Does only apply to NASL files.
    if not file.endswith(".nasl"):
        return (0,)

    text = open(file, encoding="latin-1").read()
    found_tags = ""

    # Those two are only calling http_get_port() if get_app_port() was "empty".
    if (
        "sw_magento_magmi_detect.nasl" in file
        or "2014/gb_apache_struts_classloader_vuln.nasl" in file
    ):
        return (0,)

    # Those two are using if/else calls between smtp_get_port/imap_get_port or get_app_port/service_get_port calls.
    if (
        "2009/zabbix_37308.nasl" in file
        or "pre2008/mailenable_imap_rename_dos.nasl" in file
    ):
        return (0,)

    # This one is using if/else calls similar to the examples above.
    if "2013/gb_sap_netweaver_portal_rce_04_13.nasl" in file:
        return (0,)

    match = re.findall(
        "\s*[=!]\s*((get_app_port|get_app_port_from_(cpe_prefix|list)|sip_get_port_proto|(tcp|udp)_get_all_port|(ftp|http|telnet|smtp|pop3|imap|ssh|tls_ssl|ldap|snmp|rsync|nntp|unknownservice|service)_get_port)\s*\([^)]*\)\s*[;\)])",
        text,
    )
    if match and len(match) > 1:
        for tag in match:
            if tag[0] is not None:
                found_tags += "\n\t" + tag[0]

    if len(found_tags) > 0:
        report = (
            "The VT '"
            + str(file)
            + "' is using the following functions multiple times or in conjunction with other forking functions. Please either use"
        )
        report += (
            " get_app_port_from_list() from host_details.inc or split your VT into several VTs for each covered protocol."
            + str(found_tags)
        )
        return -1, report

    found_tags = ""

    match = re.findall(
        "\s*[=!]\s*(get_app_(version|location|version_from_list|version_and_location_from_list|version_and_location|location_and_proto|version_and_proto|full|details)\s*\([^)]*\)\s*[;\)])",
        text,
    )
    if match and len(match) > 1:
        for tag in match:
            if tag[0] is not None:
                # some special cases, these are calling get_app_location with nofork:TRUE which returns a list instead of doing a fork.
                if (
                    "2018/phpunit/gb_phpunit_rce.nasl" in file
                    or "2018/gb_unprotected_web_app_installers.nasl" in file
                    or "2018/gb_sensitive_file_disclosures_http.nasl" in file
                ):
                    if "nofork:TRUE" in tag[0]:
                        continue
                found_tags += "\n\t" + tag[0]

    if len(found_tags) > 0:
        report = (
            "The VT '"
            + str(file)
            + "' is using the following functions multiple times or in conjunction with other forking functions. Please use e.g."
        )
        report += (
            " get_app_version_and_location(), get_app_version_and_location_from_list() or similar functions from host_details.inc."
            + str(found_tags)
        )
        return -1, report

    return (0,)


if __name__ == "__main__":
    import ci_helpers

    error = []
    files = ci_helpers.list_modified_files()
    if files:
        for file in files:
            test = is_misusing_forking_funcs(file)
            if test[0] != 0:
                error.append(file)
    else:
        sys.exit(0)

    if len(error) > 0:
        err_text = "VTs using following functions more then once or in conjunction with other mentioned functions within the same VT:\
    - get_app_port(); \
    - get_app_port_from_cpe_prefix(); \
    - service_get_port(); \
    - unknownservice_get_port(); \
    - ftp_get_port(); \
    - http_get_port(); \
    - telnet_get_port(); \
    - smtp_get_port(); \
    - pop3_get_port(); \
    - imap_get_port(); \
    - ssh_get_port(); \
    - tls_ssl_get_port(); \
    - ldap_get_port(); \
    - snmp_get_port(); \
    - sip_get_port_proto(); \
    - rsync_get_port(); \
    - nntp_get_port(); \
    - tcp_get_all_port(); \
    - udp_get_all_port(); \
    - get_app_version(); \
    - get_app_location(); \
    - get_app_port_from_list(); \
    - get_app_version_from_list(); \
    - get_app_version_and_location_from_list(); \
    - get_app_version_and_location(); \
    - get_app_location_and_proto(); \
    - get_app_version_and_proto(); \
    - get_app_full(); \
    - get_app_details();"
        ci_helpers.report(err_text, error)
        sys.exit(1)

    sys.exit(0)
