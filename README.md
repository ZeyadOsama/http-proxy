# HTTP Proxy

<p>
  <img src="https://img.shields.io/pypi/status/Django.svg"/>
</p>

<p>
A proxy server is a server application or appliance that acts as an intermediary for requests from clients seeking resources from servers that provide those resources. A proxy server thus functions on behalf of the client when requesting service, potentially masking the true origin of the request to the resource server.
</p>

## Features
* Follows <a href="https://tools.ietf.org/html/rfc1350">RFC</a>

## Walk Through
Find the attached document for a quick walk through to how the code works. 
<a href="https://docs.google.com/document/d/1ZFZRGZsN0sbs4_xggHHus-NN5FrPgHk9UXxh8WmcYmQ/edit?usp=sharing">Link</a>


## How to test?
* Run your script in pycharm or terminal</li>

* Open telnet in another terminal window so you can test the communication between the telnet and your script</p>
<b>N.B.</b>  ```18888``` is the number we used in the ```proxy_port_number = get_arg(1, 18888``` so if you changed it the script you should then change it in the previous command

* Write a request to test
```
telnet localhost 18888
```
Example:
```
GET http://eng.alexu.edu.eg/ HTTP/1.0\r\n\r\n
```
<b>N.B.</b> You should get a response of the source code of the the page your requested in the telnet terminal 


