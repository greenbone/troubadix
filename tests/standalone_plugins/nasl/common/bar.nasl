if(description)
{
  script_category(ACT_GATHER_INFO);
  script_dependencies( "foo.nasl", "foo.nasl" );

  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/enterprise_script.nasl");

  exit(0);
}
