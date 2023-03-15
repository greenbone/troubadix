###############################################################################
# OpenVAS Vulnerability Test
#
# HP Comware Devices Detect (SNMP)
#
# Authors:
# Dr. Who <dr@who.org>
#
# Copyright:
# Copyright (C) 2016 Greenbone AG
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.2.3.4.5.6.78909.8.7.654321");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-03-24T10:08:26+0000");
  script_tag(name:"creation_date", value:"2016-07-06 11:05:47 +0200 (Wed, 06 Jul 2016)");
  script_tag(name:"last_modification", value:"2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)");
  script_cve_id("CVE-2011-12345", "CVE-2011-54321");
  script_name("foo detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) Greenbone AG");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("foo/bar", "bar/baz");
  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.foo.org/");
  script_tag(name:"summary", value:"The remote foo foos the bar");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}
