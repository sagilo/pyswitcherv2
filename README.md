![Alt text](https://github.com/sagilo/pyswitcherv2/blob/master/images/switcher.png?raw=true "Title")

PySwitcherV2
==========
#### Control your Switcher V2 water heater using Python.

Requirements
-----
The script was tested on Python 2.7 and up or Python 3.5.
Feel free to inform if you find a non compatible version.

Usage
-----
### Configuration
The script requires 4 parameters:
* Device ID
* Phone ID
* Device pass
* Switcher local IP address

If you already know these values, edit `credentials.json` accordingly.

Otherwise, you can use the pcap parsing mode to get these parameters

##### Parse pcap file to get credentials:
In order to parse pcap files you will need to install `pypcapfile` package

    $ pip install pypcapfile

Then:

    $ python switcher.py -m parse_pcap_file -f file.pcap

This will create `credentials.json` file with most of the required information.  
You will still need to update the file with Switcher local IP address (LAN)

If you need assistance in creating pcap file, use the [Wiki page tutorial](https://github.com/sagilo/pyswitcherv2/wiki/Capturing-pcap-file-using-Android-device)

### Actions
##### Turn Switcher on/off:

    $ python switcher.py -m on

It is possible to use `-t` arg with operation time in minutes (otherwise Switcher will be on for as maximum time as defined in the device settings)

    $ python switcher.py -m on -t 45   
 
This will turn on Switcher for 45 minutes

##### Get Switcher state:

    $ python switcher.py -m get_state
    
Prints the Switcher state and returns 1 if Switcher is ON and 0 otherwise

### Other
##### Help:

    $ python switcher.py -h
    
##### Debug:
In case you are experiencing any issue, please use debug mode to get more information before submitting a ticket.
Debug flag can be used with any other mode

    $ python switcher.py -m off -d
    $ python switcher.py -m get_state -d
