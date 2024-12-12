if(description)
{
  script_dependencies( "foobar.nasl" );
  exit(0);
}

script_dependencies( "missing.nasl" );
