# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortianalyzer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.2.2.26.111");
  script_version("2026-08-17T14:00:37+0000");
  script_tag(name:"last_modification", value:"2026-08-17 14:00:37 +0000 (Mon, 17 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-08-17 13:12:10 +0000 (Mon, 17 Aug 2026)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C");
  script_tag(name:"severity_origin", value:"Vendor");
  script_tag(name:"severity_date", value:"2026-08-17 14:00:37 +0000 (Mon, 17 Aug 2026)");

  script_cve_id("CVE-2025-61848");

  script_name("Fortinet FortiAnalyzer: Execute Unauthorized Code Or Commands Vulnerability (FG-IR-26-111)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortianalyzer_consolidation.nasl");
  script_mandatory_keys("fortinet/fortianalyzer/detected");

  script_xref(name:"Advisory-ID", value:"FG-IR-26-111");
  script_xref(name:"URL", value:"https://fortiguard.fortinet.com/psirt/FG-IR-26-111");

  script_tag(name:"summary", value:"Fortinet FortiAnalyzer is prone to an execute unauthorized code or commands vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An improper neutralization of special elements used in an SQL command ('SQL injection') in FortiAnalyzer, FortiAnalyzer Cloud, FortiAnalyzer BigData, FortiManager and FortiManager Cloud may allow an authenticated privileged attacker to execute unauthorized code or commands via crafted requests.");

  script_tag(name:"affected", value:"Fortinet FortiAnalyzer versions 7.0.0 through 7.4.8, 7.6.0 through 7.6.4.");

  script_tag(name:"solution", value:"Update to version 7.4.9, 7.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_versionup: "7.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.9");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.6.0", test_versionup: "7.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
