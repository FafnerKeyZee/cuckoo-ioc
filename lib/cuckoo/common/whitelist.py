# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from lib.cuckoo.common.constants import CUCKOO_ROOT

domains = set()
urls = set()
tlds = set()

def is_whitelisted_domain(domain):
    if domain.endswith(tuple(domains)):
	return True
    return False

def is_whitelisted_url(url):
    if url in urls:
	return True
    return False

def is_whitelisted_tld(tld):
    if tld in tlds:
	return True
    return False

# Initialize the domain whitelist.
for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "domain.txt")):
    domains.add(domain.strip())

for url in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "urls.txt")):
    urls.add(url.strip())

for tld in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "tld.txt")):
    tlds.add(tld.strip())
