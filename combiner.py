import os

root = os.environ.get('COMBINER_ROOT', '.')

with open(root + 'combined', 'a+') as sink:
	dir_list = os.listdir(root + 'res')
	fraction = int(len(dir_list) / 10)
	print fraction	
	batch_write = []
	written = 0
	for fname in dir_list:
		with open(root + 'res/' + fname) as f:
			batch_write.append(f.read())
			written += 1
		if written % fraction == 0:
			sink.write(''.join(batch_write))
			batch_write = []
			print '%d%% written' % (len(dir)list / written 
* 100)
	if batch_write:
		sink.write(''.join(batch_write))



