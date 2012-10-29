import hashlib

def skygen(string, options=[\
	{'size':5, 'position':8},\
	{'size':6, 'position':0},\
	{'size':5, 'position':30},\
	{'size':-1, 'position':20}]):
	# Return hash of string
	sha1=hashlib.sha1(string).hexdigest()
	md5=hashlib.md5(string).hexdigest()
	chunks={}
	for item in options:
		if item['size']==-1: chunk=md5
		else:
			chunk=md5[:item['size']]
			md5=md5[item['size']:]
		chunks[item['position']]=chunk
	keys=chunks.keys()
	keys.sort()
	delta=0
	for key in keys:
		sha1=sha1[:key+delta]+chunks[key]+sha1[key+delta:]
		delta+=len(chunks[key])
	return hashlib.sha1(sha1).hexdigest()
