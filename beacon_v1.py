import pyshark, pickle, numpy

default = str(input('Please enter default for default settings or new for using new AP MAC addresses: '))
end = ''
macs = []
coordinates = {}
cap = pyshark.LiveCapture(interface='wlan0')

if(default.lower() == 'default'):
	macs = ['ea:6d:cb:3d:f3:6e', 'b6:ce:40:8d:40:86']
else:
	finish = ''
	while(finish.lower() != 'done'):
		finish = str(input('Please enter the MAC address or enter done to proceed: '))
		if(finish != 'done'):
			macs.append(finish)

macs = numpy.unique(macs)
macs = list(macs)
if(len(macs) <= 1):
	confirm = str(input('You have entered only one MAC address to proceed at least two MAC addresses are needed. Please either enter two MAC adresses or enter default to proceed: '))
	if(confirm.lower() == 'default'):
		macs = ['ea:6d:cb:3d:f3:6e', 'b6:ce:40:8d:40:86']
	else:
		value = str(input('Please enter the MAC addresses and then done when you are finished: '))
		while(value.lower() != 'done'):
                	value = str(input('Please enter a new MAC address or enter done to proceed: '))
                	if(value != 'done'):
                        	macs.append(value)

macs = numpy.unique(macs)
macs = list(macs)

if(len(macs) <= 1):
	print('There are not enough MAC addresses to proceed, exiting the program. We are sorry for the inconvinience.')
	exit()

while(end != 'quit'):
	#Variables
	x = ''
	y = ''
	cap.clear()
	cap.close()
	del(cap)
	while(type(x) != int):
		try:
			x = int(input('Please enter the x coordinate: '))
		except ValueError:
			print('Please enter a valid value.')
	while(type(y) != int):
		try:
			y = int(input('Please enter the y coordinate: '))
		except ValueError:
			print('Please enter a valid value.')
	cor = str([x,y])
	coordinates[cor] = {}
	for mac in macs:
		coordinates[cor]['%s' %mac] = []
	beacon = 'Not captured'
	counter = 0
	c = 0
	num = 0

	while(beacon != 'captured'):
		print('Please wait... \nCapturing...')
		cap = pyshark.LiveCapture(interface= 'wlan0')
		cap.sniff(timeout=2)
		h = 0
		c += 1
		print('Try number: ' + str(c))
		print(str(len(cap)) + ' packets have been captured.\nAnalyzing the packets...')
		for mac in macs:
			for packet in cap:
				h += 1
				if(h >= len(cap) or len(cap) == 0 or len(coordinates[cor][mac]) == 10):
					break
				try:
					if(packet.wlan.sa == mac and packet.wlan.fc_type_subtype == '8'):
						counter += 1
						coordinates[cor][mac].append(packet.wlan_radio.signal_dbm)
						if(counter == 10):
							num += 1
							if(num == len(macs)):
								beacon = 'captured'
							counter = 0
							break
				except AttributeError:
					pass
		if(c >= 5):
			c = 0
			val = str(input('It seems the AP is not in range, if you wish to continue please press enter or write quit to exit the program: '))
			if(val == 'quit'):
				exit()
		cap.clear()
		cap.close()
	print(coordinates)
	end = str(input('Please enter quit if you wish to end the process or press enter to continue: '))

with open('coordinates.py','wb') as file:
	pickle.dump(coordinates,file)
