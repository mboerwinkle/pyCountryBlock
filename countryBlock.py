#!/usr/bin/python
import urllib.request
import subprocess
import datetime
import time
import sys

def cidrToRange(cidr):
	num = ipToNum(cidrToMainIP(cidr))
	mask = cidrToMask(cidr)
	start = num & (~mask)
	end = num | mask
	return (start, end)
def ipToNum(ip):
	ret = 0
	b = ip.split('.')
	for x in range(0, 4):
		ret = ret << 8
		ret += int(b[x])
	return ret

def numToIP(num):
	ret = str(num%256)
	for x in range (0, 3):
		num //= 256 #double / is floor division
		ret = str(num%256)+'.'+ret
	return ret

def rangeToCidr(r):
	ret = []
	start = r[0]
	end = r[1]
	while start <= end:
		suffix = 32
		while True:
			candRange = cidrToRange(str(numToIP(start))+'/'+str(suffix-1))
			if candRange[0] == start and candRange[1] <= end:
				suffix = suffix-1
			else:
				break
		newCidr = str(numToIP(start))+'/'+str(suffix)
		ret.append(newCidr)
		start = cidrToRange(newCidr)[1]+1
	return ret
		

def cidrToMainIP(cidr):
	return cidr.split('/')[0]
def cidrToMask(cidr):	
	tail = int(cidr.split('/')[1])
	ret = 0
	for x in range(32-tail):
		ret = ret << 1
		ret = ret | 1
	#print("mask of "+str(tail)+" is "+str(ret))
	return ret
def overlapOrContigRange(x, y):
	if ((1+x[1]-x[0]) + (1+y[1]-y[0])) < (1 + max(x[1], y[1]) - min(x[0], y[0])):
		#print(str(x)+" and "+str(y)+" do not touch or overlap")
		return False
	else:
		return True

class IPMass:
	def __init__(self):
		self.chunk = []
	def addCidr(self, cidr):
		self.chunk.append(cidrToRange(cidr))
	def simplifyRange(self):
		foundSomething = True
		markForDeletion = set()
		while foundSomething:
			foundSomething = False
			additions = []
			for x in range(len(self.chunk)): #This is the wrong algorithm. FIXME: should sort, then combine adjacent
				for y in range(x+1, len(self.chunk)):
					if y in markForDeletion:
						continue
					X = self.chunk[x]
					Y = self.chunk[y]
					if overlapOrContigRange(X, Y):
						#print("overlap "+str(x)+" "+str(y))
						foundSomething = True
						markForDeletion.add(x)
						markForDeletion.add(y)
						additions.append((min(X[0], Y[0]), max(X[1], Y[1])))
						break
			while len(markForDeletion) != 0:
				rem = max(markForDeletion) #need to do max to not mess up the other indexes
				#print("deleting "+str(rem))
				markForDeletion.remove(rem)
				del self.chunk[rem]
			#print("adding "+str(additions))
			self.chunk += additions
	def toCidr(self):
		ret = []
		for r in self.chunk:
			ret += rangeToCidr(r)
		return ret
		
#This function takes a list of cidr notation ranges, combines them, and returns a list of cidr ranges.
def unifyCidr(cArray):
	#return cArray
	i = IPMass()
	for c in cArray:
		i.addCidr(c)
	i.simplifyRange()
	return i.toCidr()

def calculateIPVolume(cArray):
	vol = 0
	for c in cArray:
		vol += cidrToMask(c)+1
	return vol

def runTest():
	print("main ip of 127.0.0.1/24 is: "+cidrToMainIP("127.0.0.1/24"))
	print("num rep of 127.0.0.1 is: "+str(ipToNum("127.0.0.1")))
	print("ip rep of 2130706433 is: "+numToIP(2130706433))
	print("mask of 24 is: "+str(cidrToMask("0.0.0.0/24")))
	print("range of 127.0.0.1/24 is: "+str(cidrToRange("127.0.0.1/24")))
	print("range of 1.2.3.4/0 is: "+str(cidrToRange("1.2.3.4/0")))
	print("12345 is "+numToIP(12345)+" and 888888 is "+numToIP(888888))
	print("cidr of 12345 to 888888 is: "+str(rangeToCidr((12345, 888888))))
	print("unifyCidr of 127.0.0.0/24 "+str(cidrToRange("127.0.0.0/24"))+" and 127.0.1.0/24 "+str(cidrToRange("127.0.1.0/24"))+" is: "+str(unifyCidr(["127.0.0.0/24","127.0.1.0/24"])))
	print("unifyCidr of 127.0.0.0/24 "+str(cidrToRange("127.0.0.0/24"))+" and 127.0.2.0/24 "+str(cidrToRange("127.0.2.0/24"))+" is: "+str(unifyCidr(["127.0.0.0/24","127.0.2.0/24"])))

def getCountryBlockList(countryCode):
	time.sleep(1)
	url = "https://ipdeny.com/ipblocks/data/aggregated/"+countryCode+"-aggregated.zone"
	ret = []
	try:
		f = urllib.request.urlopen(url)
		ret = f.readlines()
		ret = [x.strip().decode() for x in ret]
	except Exception as ex:
		log("Failed to retrieve or parse \"url\". Ex: " + str(ex))
	return ret
	

def runProd(countries, pretend=False):
	sTime = datetime.datetime.utcnow()
	sTimeStr =  time.strftime("%Y-%m-%d_%H.%M.%S_%Z")
	logFName = "/var/log/nftCountryBlock.log"
	logDest = open(logFName, 'a')
	def log(x):
		logDest.write(x+"\n")
	log("Running countryBlock: " + str(countries) + " " + sTimeStr)

	content = []
	for country in countries:
		blocks = getCountryBlockList(country)
		log("Country "+country+" includes "+str(len(blocks))+" individual rules")
		content = content + blocks
	log("Total rules: "+str(len(content))+" ("+str(calculateIPVolume(content))+" ip volume)")
	content = unifyCidr(content)
	log("Total rules post combining: "+str(len(content))+" ("+str(calculateIPVolume(content))+" ip volume)")
	try:
		commandString = "nft flush chain filter countryBlock"
		if not pretend:
			ret = subprocess.run(commandString.split()).returncode
		else:
			log("Pretend: "+commandString)
		if ret != 0:
			log("Command \""+commandString+"\" ended with error code "+str(ret))
		else:
			log("Flushed countryBlock chain")
	except Exception as ex:
		log("Failed to flush countryBlock chain. Ex: " + str(ex))
	try:
		rulesAdded = 0
		for l in content:
			commandString = "nft add rule filter countryBlock ip saddr " + l + " drop"
			#log("Running: " + commandString)
			if not pretend:
				ret = subprocess.run(commandString.split()).returncode
			else:
				log("Pretend: "+commandString)
			if ret != 0:
				log("Command \""+commandString+"\" ended with error code "+str(ret))
				break;
			else:
				rulesAdded += 1
	except Exception as ex:
		log("Failed to add country block \""+commandString+"\". Ex: " + str(ex))
	finally:
		log(str(rulesAdded) + " rules added to table")
	log("countryBlock terminated.")

args = sys.argv
if "-t" in args:
	runTest()
elif "--pretend" in args:
	runProd(["cn", "ru", "iq", "nl", "sg"], pretend=True)
else:
	runProd(["cn", "ru"])
