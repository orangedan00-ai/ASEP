import json, urllib.parse, urllib.request

def nvd_cves(query, limit=5):
    query=str(query or '').strip()
    if not query: return {"ok":False,"error":"query required"}
    url='https://services.nvd.nist.gov/rest/json/cves/2.0?'+urllib.parse.urlencode({'keywordSearch':query,'resultsPerPage':max(1,min(int(limit),10))})
    req=urllib.request.Request(url,headers={'User-Agent':'ASEP-Evidence-Research/1.0'})
    with urllib.request.urlopen(req,timeout=15) as r:
        data=json.loads(r.read().decode('utf-8','replace'))
    rows=[]
    for item in data.get('vulnerabilities',[]):
        c=item.get('cve',{}); rows.append({'id':c.get('id'),'published':c.get('published'),'lastModified':c.get('lastModified'),'sourceIdentifier':c.get('sourceIdentifier')})
    return {'ok':True,'source':'NVD','query':query,'results':rows}
