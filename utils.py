from collections import OrderedDict

def sorted_by_key(a):
    return OrderedDict(sorted(a.items(), key=lambda d: d[0]))
