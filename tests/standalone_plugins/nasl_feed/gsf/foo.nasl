if(description)
{
  script_category(ACT_ATTACK);
  script_dependencies("bar.nasl", "gsf/foobar.nasl");
  include("lib.inc");
  exit(0);
}
