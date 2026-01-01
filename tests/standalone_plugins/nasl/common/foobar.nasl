# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-3.0-or-later

if(description)
{
  script_category(ACT_GATHER_INFO);
  script_dependencies( "bar.nasl" );
  exit(0);
  script_tag(name:"deprecated", value:TRUE);
}
