/*
   COPYRIGHT AND PERMISSION NOTICE

   NegotiateProxy - Reverse proxy to handle SPNEGO / Kerberos communication locally and
                    transparently on behalf of client applications that are themselves 
                    not SPNEGO/Kerberos-aware.

   Copyright (c) 2012 by Manu Carus (mailto:manu.carus@ethical-hacking.de)

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
*/

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NegotiateProxy
{
    internal class ReverseProxy
    {
        // members
        private string localHost;
        private int localPort;
        private string remoteHost;
        private int remotePort;
        private string httpProtocol;

        private ICurlController curl;
        private ParameterSet parameterSet;
        private TraceManager.VerboseMode verboseMode;
        private TraceManager traceManager;

        // ctor
        internal ReverseProxy(ICurlController curl, ParameterSet parameterSet, TraceManager traceManager)
        {
            this.curl = curl;

            this.localHost = parameterSet.LocalHost;
            this.localPort = int.Parse(parameterSet.LocalPort, System.Globalization.NumberStyles.Integer);
            this.remoteHost = parameterSet.RemoteHost;
            this.remotePort = int.Parse(parameterSet.RemotePort, System.Globalization.NumberStyles.Integer);
            this.httpProtocol = parameterSet.HttpProtocol;

            this.parameterSet = parameterSet;
            this.traceManager = traceManager;
            this.verboseMode = parameterSet.Verbose;
        }

        // listener
        internal void Listen()
        {
            TcpListener server = null;

            try
            {
                curl.Init(this.parameterSet, this.verboseMode, this.traceManager);

                IPAddress ip = null;

                if (Utilities.IsIp(this.localHost))
                {
                    ip = IPAddress.Parse(this.localHost);
                }
                else
                {
                    IPAddress[] ips = Dns.GetHostAddresses(this.localHost);
                    if ((ips == null) || (ips.Length == 0)) throw new ArgumentException(String.Format("syntax error: invalid hostname ({0})", this.localHost));
                    ip = ips[0];
                }

                traceManager.TraceLine(String.Format("Starting server on {0}:{1}...", this.localHost, this.localPort.ToString()), TraceManager.VerboseMode.None);
                traceManager.TraceLine(String.Format("Reverse proxying to {0}:{1} [{2}]...", this.remoteHost, this.remotePort, this.httpProtocol), TraceManager.VerboseMode.None);

                server = new TcpListener(ip, this.localPort);
                server.Start();

                traceManager.TraceLine("Server is listening...", TraceManager.VerboseMode.None);

                // Buffer for reading and writing data
                byte[] buffer = new byte[256];
                byte[] httpResponse = null;

                // Enter the listening loop.
                while (true)
                {
                    TcpClient client = null;
                    NetworkStream stream = null;
                    ProcessController pc = null;

                    try
                    {
                        client = server.AcceptTcpClient();

                        IPEndPoint endPoint = (IPEndPoint)client.Client.RemoteEndPoint;
                        string localIP = endPoint.Address.ToString();
                        int localPort = endPoint.Port;

                        traceManager.TraceLine(String.Format("Accepted client connection from {0}:{1}...", localIP, localPort.ToString()), TraceManager.VerboseMode.None);
                        traceManager.TraceSeparator('=', TraceManager.VerboseMode.Verbose);

                        // Get a stream object for reading and writing
                        stream = client.GetStream();

                        string httpRequestRaw = ReadFromStream(stream, buffer);

                        traceManager.TraceLine(httpRequestRaw, TraceManager.VerboseMode.Verbose);

                        // extract information from HTTP headers
                        string[] httpRequestParts = httpRequestRaw.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        if ((httpRequestParts.Length == 0) || (httpRequestParts.Length > 2))
                        {
                            if ((httpRequestRaw == null) || (httpRequestRaw.Length == 0))
                            {
                                // Send back a response.
                                stream.Close();
                                client.Close();
                                traceManager.TraceSeparator('=', TraceManager.VerboseMode.Verbose);
                                continue; // sometimes clients connect without sending data; just ignore and go on...
                            }
                            else throw new Exception(String.Format("invalid http request: httpRequestParts.Length = {0}", httpRequestParts.Length.ToString()));
                        }

                        string httpRequestHeaders = httpRequestParts[0];
                        string httpRequestContent = (httpRequestParts.Length == 2) ? httpRequestParts[1] : String.Empty;

                        string[] httpRequestHeadersParts = httpRequestHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        if (httpRequestHeadersParts.Length == 0) throw new Exception(String.Format("invalid http request headers: httpRequestHeadersParts.Length = {0}", httpRequestHeadersParts.Length.ToString()));

                        string httpRequestHeaderPost = String.Empty;
                        string httpRequestHeaderGet = String.Empty;
                        string httpRequestHeaderContentType = String.Empty;
                        string httpRequestHeaderSoapAction = String.Empty;
                        string httpRequestHeaderHost = String.Empty;
                        string httpRequestHeaderExpect = String.Empty;

                        foreach (string http_header in httpRequestHeadersParts)
                        {
                            if (http_header.StartsWith("POST ", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderPost = http_header;
                            if (http_header.StartsWith("GET ", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderGet = http_header;
                            if (http_header.StartsWith("Content-Type:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderContentType = http_header;
                            if (http_header.StartsWith("SOAPAction:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderSoapAction = http_header;
                            if (http_header.StartsWith("Host:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderHost = http_header;
                            if (http_header.StartsWith("Expect:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderExpect = http_header;
                        }

                        // validation of mandatory headers
                        bool httpPost = (httpRequestHeaderPost.Length > 0);
                        bool httpGet = (httpRequestHeaderGet.Length > 0);

                        if (!httpPost && !httpGet) throw new Exception("invalid http verb (neither 'POST' nor 'GET')");
                        if (httpPost && httpGet) throw new Exception("invalid http verbs ('POST' as well as 'GET')");
                        if (httpPost && (httpRequestHeaderContentType.Length == 0)) throw new Exception("invalid http header 'Content-Type' (empty)");
                        if (httpPost && (httpRequestHeaderSoapAction.Length == 0)) { }; // httpRequestHeaderSoapAction = "SOAPAction: \"\""; // no problem, just insert 'SOAPAction: ""' manually; instead of: throw new Exception("invalid http header 'SOAPAction' (empty)");
                        if (httpRequestHeaderHost.Length == 0) throw new Exception("invalid http header 'Host' (empty)");

                        httpRequestHeaderHost = "Host: " + this.parameterSet.RemoteHost + ":" + this.parameterSet.RemotePort;

                        // continue to read if header "Expect: 100-continue" is present
                        if ((httpRequestHeaderExpect.Length > 0) && httpRequestHeaderExpect.Contains("100") && httpRequestHeaderExpect.ToUpper().Contains("continue".ToUpper()))
                        {
                            string httpContinue = "HTTP/1.1 100 Continue\r\n\r\n";
                            httpResponse = Encoding.Default.GetBytes(httpContinue.ToString());
                            stream.Write(httpResponse, 0, httpResponse.Length);
                            stream.Flush();

                            httpRequestContent += ReadFromStream(stream, buffer);
                        }

                        string httpRequestHeaderGetPost = httpPost ? httpRequestHeaderPost : httpRequestHeaderGet;

                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.Verbose);
                        traceManager.TraceLine(httpRequestHeaderGetPost, TraceManager.VerboseMode.None); // GET/POST

                        // fix GET/POST header for curl/libcurl, e.g.
                        // POST /<directory>/<service>.soap2jms/1.0 HTTP/1.1
                        // to 
                        // POST http://<server>:<port>/<directory>/<service>.soap2jms/1.0
                        int index = httpRequestHeaderGetPost.IndexOf(" HTTP/1.");
                        httpRequestHeaderGetPost = httpRequestHeaderGetPost.Substring(0, index); // omit " HTTP/1.x" at end
                        string httpVerb = httpPost ? "POST " : "GET ";
                        httpRequestHeaderGetPost = httpRequestHeaderGetPost.Substring(httpVerb.Length); // omit "GET " / "POST " at start
                        if (!httpRequestHeaderGetPost.StartsWith("/")) httpRequestHeaderGetPost = "/" + httpRequestHeaderGetPost;
                        httpRequestHeaderGetPost = httpVerb + String.Format("{0}://{1}:{2}", this.httpProtocol, this.remoteHost, this.remotePort) + httpRequestHeaderGetPost;

                        // log extracted HTTP headers for debug purposes
                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderGetPost, TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderContentType, TraceManager.VerboseMode.VeryVerbose);
                        if (httpRequestHeaderSoapAction.Length > 0) traceManager.TraceLine(httpRequestHeaderSoapAction, TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderHost, TraceManager.VerboseMode.VeryVerbose);

                        // save request to file and output to console
                        string logFilenamePrefix = DateTime.Now.ToString("yyyyMMdd_HHmmss_FFFFFF");

                        // POST http://<server>/<directory>/<service>.soap2jms/1.0
                        string soap2jms = ".soap2jms/1.0";
                        if (httpRequestHeaderGetPost.EndsWith(soap2jms))
                        {
                            int dashBefore = httpRequestHeaderGetPost.LastIndexOf('-');
                            int posSoap2jms = httpRequestHeaderGetPost.IndexOf(soap2jms);
                            if ((dashBefore > -1) && (posSoap2jms > -1) && (posSoap2jms > dashBefore))
                            {
                                string serviceName = httpRequestHeaderGetPost.Substring(dashBefore + 1, posSoap2jms - dashBefore - 1);
                                logFilenamePrefix += "_" + serviceName;
                            }
                        }
                        else // GET /dir/file.ext HTTP/1.x
                        {
                            string[] httpParts = httpRequestHeaderGetPost.Split(new char[] {' '});
                            if (httpParts.Length < 2) throw new Exception(String.Format("invalid http header '{0}' (must contain something like 'GET / HTTP/1.1')", httpRequestHeaderGetPost));

                            string[] pathParts = httpParts[1].Split(new char[] {'/'});

                            if (pathParts.Length == 0) logFilenamePrefix += "_" + httpParts[1];
                            else                       logFilenamePrefix += "_" + pathParts[pathParts.Length-1];
                        }

                        // log files
                        string filenameRequestRaw = logFilenamePrefix + "_request_from_client.txt";
                        string filenameResponseRaw = logFilenamePrefix + "_response_from_curl.txt";
                        string filenameResponseModified = logFilenamePrefix + "_response_to_client.txt";

                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameRequestRaw, TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameResponseRaw, TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameResponseModified, TraceManager.VerboseMode.VeryVeryVerbose);
                        }

                        // log raw request
                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            using (StreamWriter file = new StreamWriter(filenameRequestRaw)) { file.Write(httpRequestRaw); }
                        }

                        // <!------------- curl / libcurl ------------->
                        string httpResponseRaw;
                        string httpResponseError;

                        string httpResponseModified = curl.ProcessRequest(httpPost, httpRequestContent, httpRequestHeaderSoapAction, httpRequestHeaderContentType, httpRequestHeaderHost, httpRequestHeaderGetPost, logFilenamePrefix, out httpResponseRaw, out httpResponseError);
                        // <!------------- curl / libcurl ------------->

                        // log raw response
                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            using (StreamWriter file = new StreamWriter(filenameResponseRaw)) { file.Write(httpResponseRaw); }
                        }

                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.Verbose);
                        traceManager.TraceLine(httpResponseModified.ToString(), TraceManager.VerboseMode.Verbose);

                        // log correctified response
                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            using (StreamWriter file = new StreamWriter(filenameResponseModified)) { file.Write(httpResponseModified); }
                        }

                        // Send back a response.
                        httpResponse = Encoding.Default.GetBytes(httpResponseModified.ToString());
                        stream.Write(httpResponse, 0, httpResponse.Length);
                        stream.Flush();
                        stream.Close();

                        traceManager.TraceSeparator('=', TraceManager.VerboseMode.Verbose);

                        // Shutdown and end connection
                        client.Close();
                    }
                    catch (Exception ex)
                    {
                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.None);
                        traceManager.TraceLine(ex.ToString(), TraceManager.VerboseMode.None);
                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.None);

                        if ((client != null) && (client.Connected) && (stream != null) && (stream.CanWrite))
                        {
                            string errorHeaderTemplate = "HTTP/1.1 500 Internal Server Error\r\n" +
                                                         "Date: {0}\r\n" + // Wed, 22 Aug 2012 13:34:00 GMT
                                                         "Server: {1}\r\n" + // KerberosReverseProxy.exe
                                                         "Content-Length: {2}\r\n" + // length(body)
                                                         "Connection: close\r\n" +
                                                         "Content-Type: text/html; charset=iso-8859-1\r\n";

                            string errorBodyTemplate = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n" +
                                                       "<html><head>\r\n" +
                                                       "<title>500 Internal Server Error</title>\r\n" +
                                                       "</head><body>\r\n" +
                                                       "<h1>Not Found</h1>\r\n" +
                                                       "<p>{0}</p>\r\n" + // ex.ToString()
                                                       "</body></html>";

                            string errorMessage = ex.ToString();
                            string errorBody = String.Format(errorBodyTemplate, errorMessage);

                            string date = DateTime.Now.ToString("r");
                            string thisServer = Process.GetCurrentProcess().ProcessName;
                            string contentLength = errorBody.Length.ToString();
                            string errorHeader = String.Format(errorHeaderTemplate, date, thisServer, contentLength);

                            string error = errorHeader + "\r\n" + errorBody;

                            httpResponse = Encoding.Default.GetBytes(error);
                            stream.Write(httpResponse, 0, httpResponse.Length);
                            stream.Flush();
                            stream.Close();
                        }
                    }
                    finally
                    {
                        if (pc != null) pc.Close();
                        if (stream != null) stream.Close();
                        if (client != null) client.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                traceManager.TraceSeparator('=', TraceManager.VerboseMode.None);
                traceManager.TraceLine(ex.ToString(), TraceManager.VerboseMode.None);
                traceManager.TraceSeparator('=', TraceManager.VerboseMode.None);
            }
            finally
            {
                if (server != null) server.Stop();
                curl.Cleanup();
            }
        }

        private string ReadFromStream(NetworkStream stream, byte[] buffer)
        {
            if (stream == null) throw new ArgumentNullException("Invalid argument (stream is missing)!");
            if (!stream.CanRead) throw new ArgumentNullException("Invalid argument (buffer is missing)!");

            StringBuilder httpRequestData = new StringBuilder();

            // loop to receive all data sent by the client
            while (true)
            {
                int i = stream.Read(buffer, 0, buffer.Length);
                if (i == 0) break;

                // translate data bytes to string
                string data = Encoding.Default.GetString(buffer, 0, i);
                httpRequestData.Append(data);

                if (i < buffer.Length) break;
            }

            return httpRequestData.ToString();
        }
    }
}
