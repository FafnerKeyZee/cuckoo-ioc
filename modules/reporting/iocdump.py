import os
import json
import codecs
import calendar
import datetime

from hashlib import sha256
import ntpath
import whois

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.constants import CUCKOO_ROOT

def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000.0
    raise TypeError("%r is not JSON serializable" % obj)

class IocDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")
	domains = set()
	ips = set()
	noturi = set()
	
	for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "domain.txt")):
    	    domains.add(domain.strip())
	for ip in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "ip.txt")):
    	    ips.add(ip.strip())
	    noturi.add("http://"+ip.strip())
        try:
	    pathioc = os.path.join(self.reports_path, "ioc.json")
            response = {}
	    response["Analysis"]={}
            response["Domains"]=[]
	    response["Hosts"]=[]
	    response["Signatures"]={}
	    response["Uri"]=[]
	    response["Whois"]={}
	    respwho=[]
	    tags = {}            
            if self.task["category"] == "file":
            	f = results.get("target", {}).get("file", {})
		tags["filename"] = f["name"]
            	for field in ("md5", "sha1", "sha256", "sha512"):
                    if field in f:
                    	tags[field] = f[field]
                tags["virustotal"] = results.get("virustotal", {}).get("normalized", [])
	 	tags["virustotalurl"] = "https://www.virustotal.com/en/file/"+f["sha256"]+"/analysis/"
		response["Analysis"]=tags

	    data = dict(results)
            Result1 = data['network']['domains']
	    for rs1 in Result1:
		
		if rs1['domain'].endswith(tuple(domains)):
		    ips.add(rs1['ip'].strip())
		    noturi.add("http://"+rs1['domain'])

		else:
  		    res=rs1['domain']+" "+rs1['ip']
		    response["Domains"].append(res)
		    respwho.append(rs1['domain'])
	    Result1 = data['network']['hosts']	    
	    for rs1 in Result1:
		if not rs1.endswith(tuple(ips)):
		    response["Hosts"].append(rs1)
	    Result1 = data['signatures']

	    for sigs in Result1:
	        sig=[]
		count =0
		if sigs["description"] == "Creates executable files on the filesystem" :
		  for iocs in sigs["marks"] :
                    iocsbuf={}
		    iocsbuf['filename']=iocs['ioc']
		    try:
		      for filesdrop in data['dropped']:
			if filesdrop["name"].split('_')[-1:] == ntpath.basename(iocs['ioc']).split('_')[-1:] :
			    try:
			        iocsbuf['virustotalurl']=filesdrop["virustotal"]["permalink"]
			    except:
				pass
			    break
		      sig.append(iocsbuf)
		    except:
			pass

		elif sigs["description"] == "Potentially malicious URLs were found in the process memory dump" :	
		    for iocs in sigs["marks"] :
			sig.append(iocs['ioc'])
		    sig.sort()
		elif sigs["description"] == "Potentially malicious DNS were found in the process memory dump" :	
		    for iocs in sigs["marks"] :
			sig.append(iocs['ioc'])
			respwho.append(iocs['ioc'].split(' ')[0])
		    sig.sort()
		else:
		  for iocs in sigs["marks"] :
		    if count == 10:
	  	        sig.append("...")
		        break
		    if 'ioc' in iocs:	
	  	        sig.append(iocs['ioc'])
			count+=1
		    if 'call' in iocs:
			if 'arguments' in iocs['call']:
			    if 'oldfilepath' in iocs['call']['arguments'] and 'newfilepath' in iocs['call']['arguments']:
				sig.append(iocs['call']['arguments']['newfilepath']+" to "+iocs['call']['arguments']['oldfilepath'])
				count+=1
		
	        response["Signatures"][sigs["description"]]=sig
            Result1 = data['network']['http']
	    list_unique = []
	    for rs1 in Result1:
		if not rs1["uri"].startswith(tuple(noturi)):
		    list_unique.append(rs1["uri"])
	    response["Uri"] = list(set(list_unique))
	    response["Uri"].sort()
	    respwholist = set()
	    respwholist= list(set(respwho))
	    for res in respwholist:
		try :
		    response["Whois"][res] = whois.whois(res)
		except :
		    pass

            with codecs.open(pathioc, "w", "utf-8") as report:
		json.dump(response, report, default=default, sort_keys=True,
                          indent=int(indent), encoding=encoding)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
