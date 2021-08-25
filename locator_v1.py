import pickle, pyshark, matplotlib.pyplot as plt
from PIL import Image
import numpy as np
import re

#Variables
end = ''
macs = []
beacon = 'not captured'
rssi = {}
performer = 0
img = Image.open('house_plan.jpg')

#Locator function
def locator(coordinates, rssi, macs, img):
	found = []
	for coordinate, plan in coordinates.items():
		match = 0
		for mac in macs:
			if str(rssi[mac][0]) in plan[mac]:
				match += 1
				if(match == len(macs)):
					found = coordinate
					print(found)
					temp = re.findall(r'\d+',found)
					res = list(map(int,temp))
					xy2imgxy = lambda x,y: (img.size[0]*x/np.max(ticklx), img.size[1]*(np.max(tickly)-y)/np.max(tickly))
					ticklx = np.linspace(0,4,5)
					tickly = np.linspace(0,12,13)
					tickpx,tickpy = xy2imgxy(ticklx,tickly)
					fig,ax = plt.subplots()
					ax.imshow(img)
					px,py = res[0],res[1]
					imgx,imgy = xy2imgxy(px,py)
					ax.scatter(imgx,imgy,s=100,lw=5,facecolor='none',edgecolor='red')
					ax.set_xticks([])
					ax.set_yticks([])
					plt.show()
					end = str(input('Please enter quit to quit or press enter to continue: '))
					if(end == 'quit'):
						exit()
					else:
						plt.close()
			else:
				beacon = 'not captured'
	return [match, found]

#Reading the fingerprint map file
with open('coordinates.py','rb') as file:
	coordinates = pickle.load(file)

#Ectracting the MAC addresses of the map file
lists = list(coordinates.values())
for mac in lists[0].keys():
	macs.append(mac)
	rssi['%s' %mac] = []

#Sniffing and extracting the RSSI of the beacons
while(end != 'quit'):
	performer += 1
	while(beacon != 'captured'):
		print('Scanning for beacons please wait.')
		cap = pyshark.LiveCapture(interface='wlan0')
		cap.sniff(timeout=2)
		if(len(cap) == 0):
			ack = str(input('The program is unable to receive packets please check your WIFI interface setting and retry. To try again please press enter or type exit to exit the program: '))
			if(ack == 'exit'):
				exit()
			continue

		for mac in macs:
			for packet in cap:
				try:
					if(packet.wlan.sa == mac and packet.wlan.fc_type_subtype == '8'):
						rssi[mac].append(int(packet.wlan_radio.signal_dbm))
						beacon = 'captured'
						break
				except:
					pass
	cap.clear()
	cap.close()


	data = locator(coordinates,rssi,macs,img)
	if(data[0] != len(macs) and performer == 5):
		var = str(input('The program searched for 5 times and no match was found! To quit enter quit or press enter to proceed please: '))
		if(var == 'quit'):
			exit()
		performer = 0
		beacon = 'not captured'
	for mac in macs:
		rssi['%s' %mac] = []
	beacon = 'not captured'
