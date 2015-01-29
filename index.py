"""
fudge

Emulate some of the features of a
tracker, with some extra 'features'

Since the tracker protocol is so
poorly documented, and likely poorly
followed by all clients, the proxy
tries to make as few assumptions about
the existence of specific fields...
Only if they are required as per the
clients modification request, or if
they are disliked by the dest tracker
will an error be returned to the client.

Copyright (C) 2007, 2008, 2009 Matt Waddell
ALL RIGHTS RESERVED
"""

from mod_python import apache, psp
import os, urllib, urlparse, urllib2, httplib, copy

# Import BitTorrent library
here = os.path.dirname(__file__)
dep_module_path = [here, here + '/tryke']
client = apache.import_module('client', path = dep_module_path)
bencode = apache.import_module('bencode', path = dep_module_path)

# this is the announce interface path to the proxy.
proxyAnnounce = 'announce'

# Mime type of a torrent file
torrentMime = 'application/x-bittorrent'

# List of supported client emulations
emulators = [
    ('None', 'none'),
    ('Azureus', 'azureus'),
    ('uTorrent', 'utorrent')    
]

# List of supported upload fudging methods
fudges = [
    ('None', 'none'),
    ('Upload = N * Download', 'prop'),
    ('Upload = N * Upload', 'fudge')
]

def index(req):
    """
    Displays the torrent upload dialog,
    and instructions.
    """
    templateParams = {
        'emulators' :   emulators,
        'fudges'    :   fudges
    }
    req.content_type = 'text/html'
    template = psp.PSP(req, filename='index.template.html')
    template.run(templateParams)
    return ''

def ispresentandnotempty(key, hash):
  return key in hash and hash[key]

def upload(req):
    """
    Handles the upload of a torrent.
    Manipulates it, and provides it again
    for download.
    """

    requiredParams = [
        'emulator',
        'fudge',
        'factor',
        'ipoverride'
    ]
    
    if len(req.form) == 0:
        return 'Invalid request'

    for p in requiredParams:
        if p not in req.form:
            return 'Invalid request'


    emulator = req.form['emulator']
    factor = req.form['factor']
    fudgeAlgo = req.form['fudge']
    ipoverride = req.form['ipoverride']

    torrentName = None

    if ispresentandnotempty('torrent', req.form) and req.form['torrent'].filename:
        torrentName = os.path.basename(req.form['torrent'].filename)
        fp = req.form['torrent'].file
        raw = fp.read()
    elif ispresentandnotempty('torrenturl', req.form):
        torrentUrl = req.form['torrenturl']

        try:
            url = urlparse.urlparse(torrentUrl)
        except:
            return 'Invalid URL: ' + torrentUrl

        try:
            if not url.port:
              httpCon = httplib.HTTPConnection(url.netloc)
            else:
              httpCon = httplib.HTTPConnection(url.netloc, url.port)
        except:
            return 'Unable to connect to: ' + url.netloc

        try:
            httpCon.request('GET', url.path)
            httpResp = httpCon.getresponse()

            if httpResp.status == 200:
                raw = httpResp.read()
            elif httpResp.status == 301 or httpResp.status == 302:
                return 'Fudge-factory isn\'t able to handle redirects yet...'
            else:
                return '%s: Unable to download torrent: %s' % (httpResp.reason, url.path)
        except:
            return 'Unable to download torrent: ' + url.path

        httpCon.close()

    else:
        return 'Invalid request'

    # Decode the torrent file
    try:
        t = bencode.decode(raw)
    except Exception, msg:
        return str(msg)

    if not torrentName:
        if 'info' in t and 'name' in t['info']:
            torrentName = urllib.quote(t['info']['name'] + '.torrent')
        else:
            torrentName = 'fudge.torrent'

    # Manipulate the torrent
    #

    origTracker = t['announce']

    # Create the new tracker string(s)
    # so that the client contacts the proxy
    # instead.
    #

    svr = req.server
    path = os.path.dirname(req.uri)
   
    # Format the GET params that will be sent to the proxy
    #

    get = [
      'emulator=' + urllib.quote(emulator),
      'factor=' + urllib.quote(factor),
      'fudge=' + urllib.quote(fudgeAlgo),
      'ipoverride=' + urllib.quote(ipoverride),
    ]
    get = '&'.join(get)
    
    ot = urllib.quote(origTracker)

    # Assume proxy is running on http at port 80
    # TODO: Fix that thing I said
    proxy = ('http://%s%s/%s?tracker=%s&%s' % 
                (svr.server_hostname, path, proxyAnnounce, ot, get))

    # Update the main tracker entry
    t['announce'] = proxy

    # Do the same for all trackers in the announce-list.
    # announce-list is a list of lists of trackers.
    #

    newAnnounceList = []
    if 'announce-list' in t:
        for tier in t['announce-list']:
            newTier = []
            for tracker in tier:
                ot = urllib.quote(tracker)
                p = ('http://%s%s/%s?tracker=%s&%s' % 
                    (svr.server_hostname, path, proxyAnnounce, ot, get))
                newTier.append(p)
            newAnnounceList.append(newTier)
        t['announce-list'] = newAnnounceList

    # Modify the comment a bit
    #

    c = ['Tracker Proxied By Fudge Factory, you cheap skate. Destination Tracker: ' + origTracker]
    if fudgeAlgo and factor:
        description = ''
        for des,key in fudges:
            if fudgeAlgo == key:
                description = des
                break
        if description:
            c.append('Fudge: %s (where N = %s)' % (description,factor))
        if factor >= 2.0:
            c.append('Stop being a bitch and seed')
    if emulator != 'none':
        c.append('Emulating: %s' % emulator)
    if ipoverride:
        c.append('Your IP: %s' % ipoverride)
    if 'comment' in t:
       c.append(t['comment'])
    t['comment'] = '. '.join(c)

    # Send the torrent back to the client for download
    #

    req.content_type = torrentMime
    req.headers_out['Content-Disposition'] = 'attachment; filename=' + torrentName

    # Re-create the torrent file
    return bencode.encode(t)

def announce(req):
    """
    Announce interface of the tracker proxy.
    
    Provides a pass-through proxy interface to
    the real bt tracker.  Depending on the arguments
    provided, certain bits of information are altered
    before they are sent to the tracker.

    Tracker fields are only required if they
    are going to be modified.  I payed no attention
    to the (optional) notes in the tracker spec...
    Therefore as few assumptions as possible are
    made about the nature of the request itself.

    This function speaks bencoded data structures.
    """

    def error(reason):
        """Return a bencoded tracker error msg"""
        d = { 'failure reason' : 'Proxy Error: ' + reason }
        return bencode.encode(d)

    # Parameters expected by the proxy
    # (that were encoded in the modified torrent file)
    internalParams = [
        'tracker',
        'emulator',
        'fudge',
        'factor',
        'ipoverride'
    ]

    form = req.form

    # Make sure all the necessary params are there
    for p in internalParams:
        if p not in form:
            return error('Missing parameter: ' + p)

    # Strings
    origTracker = form['tracker'].strip()
    emulator = form['emulator'].strip()
    fudgeAlgo = form['fudge'].strip()
    ipoverride = form['ipoverride'].strip()

    # Numbers
    try:
        factor = float(form['factor'])
    except ValueError, msg:
        return error('Malformed numeric parameter')

    if origTracker == '':
        return error('No tracker specified to proxy')

    # Get user-agent of the client
    userAgent = ''
    if 'User-Agent' in req.headers_in:
        userAgent = req.headers_in['User-Agent']

    # Make a copy of the clients headers
    # so that they may be modified and sent
    # to the tracker. copy.copy doesn't seem 
    # to want to work...
    headers = {}
    for key,value in req.headers_in.items():
        headers[key] = value

    # Begin constructing the tracker request
    #

    # The dict of paramters that will be sent to 
    # the tracker.
    outparams = {}

    # Figure out which IP to use:
    # 1) ipoverride
    # 2) ip specified by the client
    # 3) ip from the host request
    #
    if ipoverride != '':
        # Specified when configuring the proxy torrent
        outparams['ip'] = ipoverride
    elif ip not in form:
        # IP not specified
        outparams['ip'] = req.connection.remote_ip

    # else if it was provided by the client
    # it will simply be passed through the proxy.
        
    # Fudge the upload/download ratio? 
    ulKey,dlKey = ('uploaded','downloaded')
    if fudgeAlgo != 'none' and ulKey in form:
        try:
            uploaded = long(form[ulKey])

            if fudgeAlgo == 'prop' and dlKey in form:
                downloaded = long(form[dlKey])

                if downloaded > uploaded:
                    uploaded = factor * downloaded

            elif fudgeAlgo == 'fudge':
                uploaded = factor * uploaded
            
            outparams[ulKey] = uploaded

        except ValueError, msg:
            return error('Malformed upload/download parameter')

    # If emulating, fake the peer_id and user-agent strings
    if emulator != 'none':
        try:
            peer_id, userAgent = client.emulateClient(emulator)
        except:
            return error('Unrecognized client emulation: ' + emulator)
        
        headers['User-Agent'] = userAgent
        outparams['peer_id'] = peer_id

    # Construct a list of paramters that should be
    # taken directly from the input. Leaves out
    # params that already exist in `outparams'
    # (because they have been overridden), and 
    # leaves out the params that are only meant
    # for the proxy.

    universe = set(form.keys())
    leaveout = set(internalParams + outparams.keys())
    passthrough = list(universe - leaveout)

    for key in passthrough:
        outparams[key] = form[key]

    # Construct the query string
    q = []
    for key,value in outparams.items():
        key,value = (urllib.quote(str(key)), urllib.quote(str(value)))
        q.append('%s=%s' % (key,value))
    q = '&'.join(q)

    # Inspect the original tracker url to see if it already
    # has a query string. If so append to it.
    #

    (scheme, dom, path, par, query, frag) = urlparse.urlparse(origTracker)
    if query:
        get = '?%s&%s' % (query, q)
    else:
        get = '?' + q 

    # While we're at it, make sure that the original tracker
    # isn't this proxy. 
    # TODO: This should be a full comparison, not just the domain
    if dom == req.server.server_hostname:
        return error('Proxy doesn\'t take kindly to looping')

    # Update the host header
    headers['Host'] = dom

    # Finally set the tracker request url
    origTracker += get

    # Make the effing request to the actual tracker
    try:
        outReq = urllib2.Request(origTracker, None, headers)
        opener = urllib2.build_opener()
        fd = opener.open(outReq)
    except:
        return error('Unable to connect to tracker')

    # Get the raw bencoded response from the tracker
    try:
        raw = fd.read()
    except:
        return error('No tracker response')

    # Gather any special headers to send back to the client.
    for keys, value in fd.info().items():
        req.headers_out[key] = str(value)

    try:
        fd.close()
    except:
        pass

    # Send the tracker headers back to the client
    req.send_http_header()

    # Send the bencoded tracker response back to the client
    return raw

