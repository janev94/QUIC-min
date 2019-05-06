import tarfile
from contextlib import closing

tar_loc = "./calheta/results_calheta_may.tar.gz"

tar = tarfile.open(tar_loc, "r:gz")

routers = {}

for tarinfo in tar:
    if 'script_combined' in tarinfo.name:
        print 'processing %s' % tarinfo.name
        # print type(tar.extractfile(tarinfo.name))
        with closing(tar.extractfile(tarinfo.name)) as f:
            linec = 0
            for line in f:
                res = eval(line)
                trace = res['trace']

                #sanatise input
                for _, hop in trace.items():
                    hop = hop.replace('* ', '')
                    hop = hop.replace('Extracted TTL from port', '')
                    #check if there are any records left
                    if ',' in hop:
                        addr = hop.split(',')[0]
                        val = routers.get(addr, set())
                        val.add('Extracted TTL' in hop)
                        routers[addr] = val


                linec += 1
                if linec == 10:
                    break
        print 'found one'
        break


# pprint.pprint(routers)

bad_routers = [x for x in routers.values() if False in x]
br = len(bad_routers)
ar = len(routers)
print ar, br, br/float(ar) 

tar.close()
