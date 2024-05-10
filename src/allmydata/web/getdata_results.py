
from allmydata.interfaces import IGetdataResults
from allmydata.util import (
    jsonbytes as json,  # Supporting dumping bytes
)
from allmydata.web.common import (
    MultiFormatResource,
    render_exception
)

def json_getdata_results(r):
    sharemap = r.get_sharemap()
    shareDetails = r.get_shareDetails()
    result = {}
    for shareid, servers in sharemap.items():
        result["share_detail"] = shareDetails
        result[shareid] = {
            "server_address": sorted([s.get_rref().getLocationHints() for s in servers]),
        }
    result['version'] = r.get_version()
    return result


class GetdataResultsRender(MultiFormatResource):
    # Specify the format of the rendering
    formatArgument = "output"
    
    def __init__(self,client,results):
        super(GetdataResultsRender, self).__init__()
        self._client = client
        self._results = IGetdataResults(results)
    

    @render_exception
    def render_JSON(self, req):
        req.setHeader("content-type", "text/plain")
        data = json_getdata_results(self._results)
        return json.dumps(data, indent=1) + "\n"
    