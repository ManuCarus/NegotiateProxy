# NegotiateProxy
NegotiateProxy is a reverse proxy that handles SPNEGO/Kerberos communication  locally and transparently on behalf of a client application that is itself not  aware of SPNEGO/Kerberos.

Usage
=====

NegotiateProxy provides a simple way to extend these client applications by the features of SPNEGO/Kerberos: instead of addressing a "kerberized" service directly, you just have to start the NegotiateProxy on your local machine,
with a forward redirection to the desired remote host, and then configure your client application to address the local proxy instead of the remote service. The proxy will then take care for Kerberos tickets automatically as required 
by the remote host.


               Client                                  Server
            +----------+                             +----------+
            |          |                             |          |
            |          |                             |          |
     +------+---- App. |                             |  App.    |       
     |local |          |Negotiate         Kerberized |    ^     |
     |host  |          |  Proxy             Service  |    |     |
     +------+-->6268---|---------> Network --------> |---443    |
            |          |  [SSL]               SSL    |          |
            |          | [X.509]             X.509   |          |
            +----------+                             +----------+

For SPNEGO and GSS-API, please refer to http://tools.ietf.org/html/.
For Kerberos, please refer to RfC 4559, 2478, 4178.



Quick Start
-----------

Say you want to call a "kerberized" web service at

    https://kerberos.intranet.de/application/addressCheck.soap2jms/1.0

Create a soapUI project and run the request against the "kerberized" endpoint.

It will fail with HTTP/401 Authorization Required:

    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>401 Authorization Required</title>
    </head><body>
    <h1>Authorization Required</h1>
    <p>This server could not verify that you are authorized to access the document requested.  Either you supplied the wrong credentials (e.g., bad password), or your browser doesn't understand how to supply the credentials required.</p>
    </body></html>

This is because the endpoint requires a Kerberos ticket, while soapUI isn't able to (automatically) react to this situation. Enter NegotiateProxy!

Go and start the reverse proxy locally on your client machine:

    NegotiateProxy kerberos.intranet.de

This proxy will, by default, listen on "localhost:6268" and forward incoming traffic to "kerberos.intranet.de:443" (https).

Now, go back to soapUI and change the endpoint of your service request to 

    http://localhost:6268/application/addressCheck.soap2jms/1.0

Please recognize that the latter endpoint now addresses "http://localhost:6268/" instead of "https://kerberos.intranet.de/".

Run the request against the local endpoint and result in HTTP/1.1 200 OK.

That's it! Mission completed...


When to use?
------------

NegotiateProxy can be used for any client software that needs to run web services against endpoints which require the use of SPNEGO/Kerberos.

There's no need for any implementation changes in the client software. It just has to set its endpoints to a local port by configuration changes.

You can run quite complex client software with support of NegotiateProxy. Smart Clients, e.g., that address several different endpoints at one, can run through different instances of NegotiateProxy: Just run one instance of NegotiateProxy for each single endpoint.


Help
----

Run NegotiateProxy without command line parameters to get help. 

The --help parameter will do either:

    NegotiateProxy --help

    NegotiateProxy - Reverse proxy to handle SPNEGO / Kerberos
                     communication locally and transparently
                     on behalf of client applications that are
                     themselves not SPNEGO/Kerberos-aware.

    Copyright (c) 2012 Manu Carus (mailto:info@manu-carus.de)

    Reverse proxy to handle SPNEGO communication according to RfC 4559, 2478, 4178 (see http://tools.ietf.org/html/ for details). Use locally to transparently support client applications which are not aware of Kerberos/SPNEGO.

    Usage: NegotiateProxy [<localport>:]<remotehost>[:<remoteport>][:<protocol>] [options]
       or: NegotiateProxy [options]

    e.g.

      NegotiateProxy kerberos.foo.com
      NegotiateProxy 8043:kerberos.foo.com:9043:https
      NegotiateProxy 8080:kerberos.foo.com:80:http

    Options:
    
      -lh,--localhost:<host>          local host to bind to (default: 127.0.0.1)
      -lp,--localport:<port>          local port to bind to (default: 6268)
      -rh,--remotehost:<host>         remote host to redirect to (mandatory)
                                      (allowed values: host name or IP address)
      -rp,--remoteport:<port>         remote port to connect to (default: 443)
      -p, --protocol:<http[s]>        protocol to use (http or https) (default: https)
      -pr,--preauthentication:<sec>   kerberos ticket cache (default: 43200 (12 hours))");
      -lc,--libcurl                   use libcurl for Kerberos/Negotiation (default)
      -c, --curl                      use curl instead of libcurl for Kerberos/Negotiation
      -l, --log:<file>                file to log to (default: stdout)
      -v, --verbose                   verbose mode (use multiple times for more details)
      -d, --dump                      dump mode (maximum verbose level, acts like -v -v -v)
      -q, --quiet                     quiet mode (default: false)
      -l, --licence                   displays the terms of licence for this software
      -h, --help                      displays this text
    
    e.g.    
    
      NegotiateProxy -rh:kerberos.foo.com -p:http
      NegotiateProxy -lh:0.0.0.0 -lp:8081 -rh:kerberos.foo.com -rp:80 -v -v
    
    SSL Options (for --libcurl only):
    
      -sv,--ssl-version:<version>     ssl version (default, TLSv1, SSLv3)
      -vh,--verify-host:<flag>        0: do not verify host
                                      1: check existence
                                      2: ensure that it matches the provided hostname (default)
      -vp,--no-verify-peer            do not verify the peer's certificate
      -ca,--ca-path:<path>            directory holding CA certificates to verify the peer with
                                      (must be prepared with the openssl c_rehash utility)
                                      (default: .\certs)

    e.g.

      NegotiateProxy 8043:kerberos.foo.com:443 --ca-path:C:\certs
      NegotiateProxy 8043:kerberos.foo.com:443 --ssl-version:TLSv1 --verify-host:1 --ca-path:C:\certs


Logging
-------

By default, all proxy messages will be logged to stdout.
You can increase the verbose level to get more details (e.g. -v -v).
The --dump parameter imposes the maximum verbose level (that is -v -v -v). 

If you need to log to a file, use the --file:<log_file> parameter.
By default, all messages will be logged to the log file as well as to stdout.
If you provide the --quiet parameter, output to stdout will be omitted.


Verbosity Levels (--verbose)
----------------------------

default:  no verbose messages will be written to the log / stdout
-v:       incoming requests and outgoing responses will be written to the log / stdout
-v -v:    additionally, important http headers from incoming requests will be written to the log / stdout (POST, Content-Type, SOAPAction, Host, as well as the curl command line parameters (in case of --curl))
-v -v -v: additionally, all inbound and outbound traffic will be dumped to local files (on a per-request basis), and filenames will be written to the log / stdout		 


Modes
-----

NegotiateProxy supports libcurl as well as curl. 

By default, all proxy communication is handeled by the libcurl dll (http://curl.haxx.se/libcurl/) which makes communication fast and reliable.

If you need to see what's happening "under the surface", please enable the --dump parameter to see all the internal libcurl verbose messages.

If you're using NegotiateProxy as a sniffer, and you need to replay service calls at a later time, then turn over to the curl mode. 

In curl mode (--curl), all proxy communication is handled by a dedicated curl process (instead of a libcurl in-process), i.e. for every service call, a new curl.exe process will be created and executed. Combine --curl with the --dump parameter to save the curl command line parameters as well as the SOAP request body to local files.

Sample:

    NegotiateProxy kerberos.intranet.de --curl --dump

    dir *addressCheck* /B
    20130205_114707_507559_addressCheck_curl.cmd.txt
    20130205_114707_507559_addressCheck_request.curl.param.txt
    20130205_114707_507559_addressCheck_request_from_client.txt
    20130205_114707_507559_addressCheck_response_from_curl.txt
    20130205_114707_507559_addressCheck_response_to_client.txt

    *_request_from_client.txt -> contains the HTTP/SOAP request received by the proxy (e.g. from soapUI)
    *_request.curl.param.txt  -> contains the SOAP request body (received by the proxy and passed to curl)
    *_curl.cmd.txt            -> contains the executed curl command line
    *_response_from_curl.txt  -> contains the raw response received by the curl process
    *_response_to_client.txt  -> contains the HTTP/SOAP response sent by the proxy (e.g. back to soapUI)

    type 20130205_114707_507559_addressCheck_curl.cmd.txt
    curl.exe --header "Content-Type: text/xml;charset=UTF-8" --header "SOAPAction: \"\"" --data @20130205_114707_507559_addressCheck_request.curl.param.txt --insecure --request POST https://kerberos.intranet.de:443/application/addressCheck.soap2jms/1.0 --include --negotiate --user


SSL
---

You may configure the reverse proxy to forward traffic via http instead of https (which is not recommended). Example:

    NegotiateProxy 8080:kerberos.foo.com:80:http

By default, the reverse proxy communicates with the remote endpoint via SSL (https), i.e. the proxy verifies the server's certificate against its trusted certificates. These trusted certificates must be located in a local directory (default: .\certs), and the filename of every certificate must be built by the openssl c_rehash utility (e.g. c0ff1f52.0). If you want to weaken down the default SSL verification rules, then please use these dedicated SSL options:

SSL Options (for --libcurl only):

    -sv,--ssl-version:<version> ssl version (default, TLSv1, SSLv3)
    -vh,--verify-host:<flag>    0: do not verify host
                                1: check existence
                                2: ensure that it matches the provided hostname (default)
    -vp,--no-verify-peer        do not verify the peer's certificate
    -ca,--ca-path:<path>        directory holding CA certificates to verify the peer with
                                (must be prepared with the openssl c_rehash utility)
                                (default: .\certs)

    e.g.
    
      NegotiateProxy 8043:kerberos.foo.com:443 --ca-path:C:\certs
      NegotiateProxy 8043:kerberos.foo.com:443 --ssl-version:TLSv1 --verify-host:1 --ca-path:C:\certs


COPYRIGHT, PERMISSION NOTICE and LICENCE TERMS: NegotiateProxy
--------------------------------------------------------------

NegotiateProxy - Reverse proxy to handle SPNEGO / Kerberos communication locally and
				 transparently on behalf of client applications that are themselves 
				 not SPNEGO/Kerberos-aware.

Copyright (c) 2012 by Manu Carus (mailto:info@manu-carus.de)

The Initial Developer of the Original Code is Manu Carus.
All rights reserved.

Permission to use, copy, modify, and distribute this software for any
purpose, subject to the provisions described below, without fee is
hereby granted, provided that this entire notice is included in all
copies of any software that is or includes a copy or modification of
this software and in all copies of the supporting documentation for
such software.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD-PARTY RIGHTS.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR INCONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in this Software without prior written permission of the copyright
holder.


Licence Terms: libcurl
----------------------
COPYRIGHT AND PERMISSION NOTICE

Copyright (c) 2004, 2005 Jeff Phillips, (jeff@jeffp.net).

All rights reserved.

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD-PARTY RIGHTS.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR INCONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in this Software without prior written permission of the copyright
holder.


Licence Terms: libcurlnet
-------------------------
The author of this software is David R. Hanson.

Copyright (c) 1994,1995,1996,1997 by David R. Hanson. All Rights Reserved.

Permission to use, copy, modify, and distribute this software for any
purpose, subject to the provisions described below, without fee is
hereby granted, provided that this entire notice is included in all
copies of any software that is or includes a copy or modification of
this software and in all copies of the supporting documentation for
such software.

THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
WARRANTY. IN PARTICULAR, THE AUTHOR DOES MAKE ANY REPRESENTATION OR
WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY OF THIS SOFTWARE OR
ITS FITNESS FOR ANY PARTICULAR PURPOSE.

David Hanson / drh@microsoft.com /
http://www.research.microsoft.com/~drh/

