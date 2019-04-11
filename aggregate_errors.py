import os
import pprint as pp


err_list = os.listdir('errors/')

errors = {}

for fname in err_list:
    with open('errors/' + fname) as f:
        content = f.read().strip()
        errors[content] = errors.get(content, 0) + 1



pp.pprint(sorted(errors.items(), key= lambda x: x[1]))

