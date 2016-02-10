import os
import json
import codecs
import calendar
import datetime

import ntpath

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
    """Saves analysis iocs in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")

        # Structure of the report
        response = {}
        response["Analysis"]={}
        response["Domains"]=[]
        response["Hosts"]=[]
        response["Uri"]=[]
        tags = {}            

        # Creating the whitelist for domains and ips    
        domains = set()
        ips = set()
        noturi = set()

        for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", 
                  "domain.txt")):
            domains.add(domain.strip())
        for ip in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", 
                  "ip.txt")):
            ips.add(ip.strip())
            noturi.add("http://"+ip.strip())
        # End of creation

        # First part : Analysis 
        if self.task["category"] == "file":
            f = results.get("target", {}).get("file", {})
            tags["filename"] = f["name"]
            for field in ("md5", "sha1", "sha256", "sha512"):
                if field in f:
                    tags[field] = f[field]
                    tags["virustotal"] = results.get("virustotal", 
                              {}).get("normalized", [])
                tags["virustotalurl"] = "https://www.virustotal.com/en/file/"
                tags["virustotalurl"] += f["sha256"]+"/analysis/"
                response["Analysis"]=tags

        data = dict(results)

        # Domains & hosts & URI
        if "network" in data:
            # Domains
            if "domains" in data["network"]:
                tmpresult = data["network"]["domains"]
                for actualdomain in tmpresult:
                    if actualdomain["domain"].endswith(tuple(domains)):
                        ips.add(actualdomain['ip'].strip())
                        noturi.add("http://"+actualdomain["domain"])
                    else:
                            res=actualdomain["domain"]+" "+actualdomain["ip"]
                            response["Domains"].append(res)
            # Hosts
            if "hosts" in data["network"]: 
                hosts = data["network"]["hosts"]        
                for host in hosts:
                    if not host.endswith(tuple(ips)):
                        response["Hosts"].append(host)

            # URI
            if "http" in data["network"]:
                uris = data["network"]["http"]
                list_unique = []
                for uri in uris:
                    if not uri["uri"].startswith(tuple(noturi)):
                        list_unique.append(uri["uri"])
                response["Uri"] = list(set(list_unique))
                response["Uri"].sort()


        # Save the report
        try:
            pathioc = os.path.join(self.reports_path, "ioc.json")
            with codecs.open(pathioc, "w", "utf-8") as report:
                json.dump(response, report, default=default, sort_keys=True,
                          indent=int(indent), encoding=encoding)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate ioc report: %s" % e)
