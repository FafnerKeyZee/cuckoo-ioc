from lib.cuckoo.common.abstracts import Signature
import  dns.resolver

class ProcMemDumpDns(Signature):
    name = "memdump_Dns"
    description = "Potentially malicious DNS were found in the process memory dump"
    severity = 2
    categories = ["unpacking"]
    authors = ["Fafner [_KeyZee_]"]
    minimum = "2.0"

    def on_complete(self):
	dnslist = []        
	for procmem in self.get_results("procmemory", []):
            for dnss in procmem.get("urls", []):
                #self.mark_ioc("url", url)
		dnstmp = dnss.split('/')[2]
		if dnstmp not in dnslist :
		    dnslist.append(dnstmp)
	if dnslist :
	    dnslist.sort()
	    my_resolver = dns.resolver.Resolver()
	    for dnss in dnslist:
	      listadd =""
	      try:
		answers_IPv4 = my_resolver.query(dnss,'A')
	        for rdata in answers_IPv4 :
		  listadd+=" "+rdata.address
	  	
	      except:
		pass
	      self.mark_ioc("dns", dnss+listadd)

        return self.has_marks()

