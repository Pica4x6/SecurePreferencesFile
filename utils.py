import json, ast, hmac, hashlib
from collections import OrderedDict


def change_spf(json_file, values, sid, seed):
    # Reads the file
    json_data = open(json_file, encoding="utf-8")
    data = json.load(json_data, object_pairs_hook=OrderedDict)
    json_data.close()

    modifyDict(data, values.split('%'))
    temp = OrderedDict(sorted(data.items()))
    data = temp
    HMAChelper(data['protection']['macs'], data, "", values.split('%'), sid, seed)
    
    # Calculates and sets the super_mac
    super_msg = sid + json.dumps(data['protection']['macs']).replace(" ", "")
    hash_obj = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
    print('super_mac (BEFORE): {}'.format(data['protection']['super_mac']))
    print('super_mac (AFTER):  {}'.format(hash_obj.hexdigest().upper()))
    

def removeEmpty(d):
    if type(d) == type(OrderedDict()):
        t = OrderedDict(d)
        for x, y in t.items():
            if type(y) == (type(OrderedDict())):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif(type(y) == type({})):
                if(len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0, ""]):
                    del d[x]

    elif type(d) == type([]):
        for x, y in enumerate(d):
            if type(y) == type(OrderedDict()):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type({})):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0, ""]):
                    del d[x]

def calculateHMAC(value_as_string, path, sid, seed):
    if ((type(value_as_string) == type({})) or (type(value_as_string) == type(OrderedDict()))):
        removeEmpty(value_as_string)
    message = sid + path + json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False).replace('<', '\\u003C').replace(
        '\\u2122', '™')
    hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)

    return hash_obj.hexdigest().upper()

def HMAChelper(macs, value, path, arg, sid, seed, extension=False):
    if isinstance(value,OrderedDict):
        if(arg[0] in value):
            if arg[0] in macs:
                path += arg[0] + "."
                macs[arg[0]] = HMAChelper(macs[arg[0]], value[arg[0]] ,path, arg[1:], sid, seed)
            else:
                if not extension:
                    macs = HMAChelper(macs, value[arg[0]], path, arg[1:], sid, seed, extension=value)
                else:
                    macs = HMAChelper(macs, value[arg[0]], path, arg[1:], sid, seed, extension)
            return macs
        elif(arg[0] in macs):
            del macs[arg[0]]
            return macs
        else:
            if len(arg)>2:
                HMAChelper(macs, value[arg[0]] ,path, arg[1:], sid, seed)
            elif len(arg)==2:
                if arg[0] in value:
                    path += arg[0] + "."
                    print('Before: {}'.format(macs))
                    macs = calculateHMAC(value[arg[0]], path[:-1], sid, seed)
                else:
                    print('Before: {}'.format(macs))
                    if extension:
                        value = extension
                    macs = calculateHMAC(value, path[:-1], sid, seed)
            else:
                # print('Before: {}'.format(macs))
                macs = calculateHMAC(value,path[:-1], sid, seed)
            # print('After : {}'.format(macs))
            return macs
    else:
        print('Before: {}'.format(macs))
        if extension:
            value = extension
        macs = calculateHMAC(value, path[:-1], sid, seed)
    print('After : {}'.format(macs))
    return macs
    

def modifyDict(t, arg):
    if arg[0] in ['pinned_tabs']:
        if arg[0] in t:
            t[arg[0]].append({arg[1]:arg[2]})
        else:
            t[arg[0]] = {arg[1]:arg[2]}
            
    elif(len(arg) > 2):
        if arg[0] in t:
            modifyDict(t[arg[0]], arg[1:])
        else:
            t[arg[0]] = {arg[1]: {}}
            modifyDict(t[arg[0]], arg[1:])
        
        if "delete" not in arg:
            t[arg[0]] = OrderedDict(sorted(t[arg[0]].items()))
    elif(len(arg) == 2):
        if(arg[1].lower() == "delete"):
            if isinstance(t, list):
                if arg[0] in t:
                    index = t.index(arg[0])
                    del t[index]
        else:
            if arg[0] in ['web_accessible_resources','permissions','api','matches','ids']:
                if arg[0] in t:
                    t[arg[0]].append(arg[1])
                else:
                    t[arg[0]] = [arg[1]]
                    
            elif arg[0] in ['content_scripts']:
                if arg[0] not in t.keys():
                    t[arg[0]] = []
                if arg[1].split('.')[-1] in ['js']:
                    if t[arg[0]]:
                        if 'js' in t[arg[0]][0].keys():
                            t[arg[0]][0]['js'].append(arg[1])
                        if 'run_at' not in t[arg[0]][0].keys():
                            t[arg[0]][0]['run_at'] = "document_end"
                    else:
                        t[arg[0]].append({'js':[arg[1]],'all_frames':True,'matches':['*://*//*']})
                        
            else:
                if arg[0] in t:
                    if isinstance(t[arg[0]],str):
                        t[arg[0]] = arg[1]
                    else:
                        t[arg[0]] = ast.literal_eval(arg[1])
                else:
                    try:
                        t[arg[0]] = ast.literal_eval(arg[1])
                    except:
                        t[arg[0]] = arg[1]
