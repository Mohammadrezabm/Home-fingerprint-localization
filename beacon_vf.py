#Importing libraries
import pyshark, pickle, numpy
from datetime import datetime

#Asking for settings and MAC addresses
default = str(input('Please enter default for default settings or new for entering new AP MAC addresses: '))
end = ''
macs = []
coordinates = {}
time = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
file_name = 'coordinates_' + time + '.py'
cap = pyshark.LiveCapture(interface='wlan0')

if(default.lower() == 'default'):
	macs = ['ea:6d:cb:3d:f3:6e', 'b6:ce:40:8d:40:86']
else:
	finish = ''
	while(finish.lower() != 'done'):
		finish = str(input('Please enter the MAC address or type done to proceed: '))
		if(finish != 'done'):
			macs.append(finish)

macs = numpy.unique(macs)
macs = list(macs)
if(len(macs) <= 1):
	confirm = str(input('You have entered less than two MAC addresses, to proceed at least two MAC addresses are needed. Please either type default to proceed or press enter to add new MAC addresses: '))
	if(confirm.lower() == 'default'):
		macs = ['ea:6d:cb:3d:f3:6e', 'b6:ce:40:8d:40:86']
	else:
		value = ''
		while(value.lower() != 'done'):
                	value = str(input('Please enter a new MAC address or type done to proceed: '))
                	if(value != 'done'):
                        	macs.append(value)

macs = numpy.unique(macs)
macs = list(macs)

if(len(macs) <= 1):
	print('There are not enough MAC addresses to proceed, exiting the program. We are sorry for the inconvinience.')
	exit()

#Main program
while(end != 'quit'):
	#Variables
	x = ''
	y = ''
	cap.clear()
	cap.close()
	del(cap)
	while(type(x) != int):	#Asks for the coordniates to record the RSSIs
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

	#Capturing data and recording the RSSIs
	while(beacon != 'captured'):
		print('Please wait... \nCapturing...')
		cap = pyshark.LiveCapture(interface= 'wlan0')
		cap.sniff(timeout=2)
		h = 0
		c += 1
		print('Attempt number: ' + str(c))
		print(str(len(cap)) + ' packets have been captured.\nAnalyzing the packets...')
		for mac in macs:
			if(len(cap) == 0):
				continue
			for packet in cap:
				h += 1
				if(h >= len(cap) or len(cap) == 0 or len(coordinates[cor][mac]) == 10):	#Breaks out of the packet search in case of 10 records or no file capture
					break
				try:
					if(packet.wlan.sa == mac and packet.wlan.fc_type_subtype == '8'):	#Checks the MAC address and the RSSIs of the APs
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
			val = str(input('It seems the APs are not in range, if you wish to continue please press enter or type quit to exit the program: '))
			if(val == 'quit'):
				exit()
		cap.clear()
		cap.close()
	print(coordinates)
	end = str(input('Please type quit if you wish to end the process or press enter to continue adding new coordinates: '))

#Saves the fingerprint map to a file
with open(file_name,'wb') as file:
	pickle.dump(coordinates,file)
