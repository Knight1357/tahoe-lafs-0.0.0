from allmydata.scripts.common import get_alias, DEFAULT_ALIAS, escape_path, \
    UnknownAliasError
from allmydata.scripts.common_http import do_http, format_http_error

from urllib.parse import quote as url_quote




def getdata_location(options, where):
    stdout = options.stdout
    stderr = options.stderr
    nodeurl = options['node-url']
    if not nodeurl.endswith("/"):
        nodeurl += "/"
    try:
        rootcap, path = get_alias(options.aliases, where, DEFAULT_ALIAS)
    except UnknownAliasError as e:
        e.display(stderr)
        return 1
    path = str(path, "utf-8")
    if path == '/':
        path = ''
    url = nodeurl + "uri/%s" % url_quote(rootcap)

    if path:
        url += "/" + escape_path(path)
    url += "?t=getdata&output=JSON"
    resp = do_http("POST", url)
    if resp.status != 200:
        print(format_http_error("ERROR", resp), file=stderr)
        return 1
    jdata = resp.read().decode()
    stdout.write(" Getting data from Share \n")
    stdout.write(" %s \n"%(jdata))
    # TODO: 格式化输出信息 quote_output? 
    return 0


def getdata(options):
    if len(options.locations) == 0:
        errno = getdata_location(options, str())
        if errno != 0:
            return errno
        return 0
    for location in options.locations:
        errno = getdata_location(options, location)
        if errno != 0:
            return errno
    return 0