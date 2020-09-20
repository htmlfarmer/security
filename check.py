import urllib.request
def connect(host='http://moscowtv.ddns.net'):
    try:
        urllib.request.urlopen(host) #Python 3.x
        return True
    except:
        return False
# test
print( "connected" if connect() else "no internet!" )