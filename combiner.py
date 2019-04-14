import os

root = os.environ.get('COMBINER_ROOT', '.')

with open(root + '/combined', 'a+') as sink:
	dir_list = os.listdir(root + '/res')
	fraction = int(len(dir_list) / 10)
	print fraction	
	batch_write = ''
	count = 1
	for fname in dir_list:
		with open(root + '/res/'+fname) as f:
			batch_write += f.read()
		if len(batch_write) % fraction == 0:
			sink.write(batch_write)
			batch_write = ''
			print '%d%% written' % count * 10
			count += 1
	if batch_write:
		sink.write(batch_write)



