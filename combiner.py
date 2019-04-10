import os

with open('combined', 'a+') as sink:
	for fname in os.listdir('res/'):
		with open('res/'+fname) as f:
			sink.write(f.read())



