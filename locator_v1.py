import pickle, pyshark, matplotlib.pyplot as plt

#Variables
end = ''
macs = []
beacon = 'not captured'
rssi = {}
performer = 0

#Locator function
def locator(coordinates, rssi, macs):
	found = []
	for coordinate, map in coordinates.items():
		match = 0
		for mac in macs:
			if str(rssi[mac][0]) in map[mac]:
				match += 1
				if(match == len(macs)):
					found = coordinate
					plt.close()
					plt.plot(int(coordinate[1]),int(coordinate[4]), 'ro')
					plt.pause(0.0005)
					plt.show(block=False)
					end = str(input('Please enter quit to quit or press enter to continue: '))
					if(end == 'quit'):
						exit()
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


	data = locator(coordinates,rssi,macs)
	if(data[0] != len(macs) and performer == 5):
		var = str(input('The program searched for 5 times and no match was found! To quit enter quit or press enter to proceed please: '))
		if(var == 'quit'):
			exit()
		performer = 0
		beacon = 'not captured'
	for mac in macs:
		rssi['%s' %mac] = []
	beacon = 'not captured'
