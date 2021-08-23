import pyshark, pickle, numpy

default = str(input('Please enter default for default settings or new for using new AP MAC addresses: '))
end = ''
macs = []
coordinates = {}

if(default.lower() == 'default'):
	macs = ['ea:6d:cb:3d:f3:6e', 'b6:ce:40:8d:40:86']
else:
	finish = ''
	while(finish.lower() != 'done'):
		finish = str(input('Please enter the MAC address or enter done to proceed: '))
		if(finish != 'done'):
			macs.append(finish)

if(len(macs) == 0):
	macs = ['ea:6d:cb:3d:f3:6e', 'b6:ce:40:8d:40:86']

while(end != 'quit'):
	#Variables
	x = int(input('Please enter the x coordinate: '))
	y = int(input('Please enter the y coordinate: '))
	cor = str([x,y])
	coordinates[cor] = {}
	for mac in macs:
		coordinates[cor]['%s' %mac] = []
	beacon = 'Not captured'
	counter = 0

	while(beacon != 'captured'):
		cap = pyshark.LiveCapture(interface= 'wlan0')
		cap.sniff(timeout=2)
		for mac in macs:
			for packet in cap:
				try:
					if(packet.wlan.sa == mac and packet.wlan.fc_type_subtype == '8'):
						counter += 1
						print(counter)
						coordinates[cor][mac].append(packet.wlan_radio.signal_dbm)
						if(counter == 10):
							beacon = 'captured'
							print('broke')
							counter = 0
							break
				except:
					pass
		cap.clear()
		cap.close()
	print(coordinates)
	end = str(input('Please enter quit if you wish to end the process: '))

with open('coordinates.py','wb') as file:
	pickle.dump(coordinates,file)
