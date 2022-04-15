from collections import OrderedDict

def sorted_by_key(d):
    return OrderedDict(sorted(d.items(), key=lambda k:k[0]))
