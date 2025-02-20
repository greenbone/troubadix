if(description)
{
  script_category(ACT_ATTACK);
  script_dependencies( "foobar.nasl", "gsf/enterprise_script.nasl" );
  exit(0);
}

script_dependencies( "missing.nasl" );
