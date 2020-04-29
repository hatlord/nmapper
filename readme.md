# What is it?  
Sucks in NMAP xml files and spits out a formatted excel document. The sheets have a full breakdown of scan results for open ports, one with a comma separated ports list for condensed reporting, and one grouped by ports. It can easily be used to very quickly identify parts of your scope that aren't responding, or potentially access issues (low numbers of open ports per host).  
## Basic Usage  
Check out the Nokogiri gem installation instructions before doing the bundle install: https://nokogiri.org/tutorials/installing_nokogiri.html
```bash
bundle install
./nmapper.rb /path/to/nmap_xml/directory/
```
