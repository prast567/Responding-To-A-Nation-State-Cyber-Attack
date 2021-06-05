rule unknown_threat
{
meta:
	author = "@ptkr"
	version = "0.1"
strings:
     $domain = "darkl0rd.com:7758"
condition:
     all of them
}
