using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NegotiateProxy
{
    internal class CurlWrapper : IProxy
    {
        // members
        private string localHost;
        private int    localPort;
        private string remoteHost;
        private int    remotePort;
        private string httpProtocol;
        private string curlOptions;

        private TraceManager.VerboseMode verboseMode;
        private TraceManager traceManager;

        // ctor
        internal CurlWrapper(ParameterSet parameterSet, TraceManager traceManager)
        {
            this.localHost    = parameterSet.LocalHost;
            this.localPort    = int.Parse(parameterSet.LocalPort, System.Globalization.NumberStyles.Integer);
            this.remoteHost   = parameterSet.RemoteHost;
            this.remotePort   = int.Parse(parameterSet.RemotePort, System.Globalization.NumberStyles.Integer);
            this.httpProtocol = parameterSet.HttpProtocol;
            this.curlOptions  = parameterSet.CurlOptions;

            this.traceManager = traceManager;
            this.verboseMode  = parameterSet.Verbose;
        }

        // interface
        public void Start()
        {
            TcpListener server = null;

            try
            {
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
                    Process p = null;

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
                        if ((httpRequestParts.Length == 0) || (httpRequestParts.Length > 2)) throw new Exception(String.Format("invalid http request: httpRequestParts.Length = {0}", httpRequestParts.Length.ToString()));

                        string httpRequestHeaders = httpRequestParts[0];
                        string httpRequestContent = (httpRequestParts.Length == 2) ? httpRequestParts[1] : String.Empty;

                        string[] httpRequestHeadersParts = httpRequestHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        if (httpRequestHeadersParts.Length == 0) throw new Exception(String.Format("invalid http request headers: httpRequestHeadersParts.Length = {0}", httpRequestHeadersParts.Length.ToString()));

                        string httpRequestHeaderPost = String.Empty;
                        string httpRequestHeaderContentType = String.Empty;
                        string httpRequestHeaderSoapAction = String.Empty;
                        string httpRequestHeaderHost = String.Empty;
                        string httpRequestHeaderExpect = String.Empty;

                        foreach (string http_header in httpRequestHeadersParts)
                        {
                            if (http_header.StartsWith("POST ", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderPost = http_header;
                            if (http_header.StartsWith("Content-Type:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderContentType = http_header;
                            if (http_header.StartsWith("SOAPAction:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderSoapAction = http_header;
                            if (http_header.StartsWith("Host:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderHost = http_header;
                            if (http_header.StartsWith("Expect:", StringComparison.InvariantCultureIgnoreCase)) httpRequestHeaderExpect = http_header;
                        }

                        // validation of mandatory headers
                        if (httpRequestHeaderPost.Length == 0) throw new Exception("invalid http header 'POST' (empty)");
                        if (httpRequestHeaderContentType.Length == 0) throw new Exception("invalid http header 'Content-Type' (empty)");
                        if (httpRequestHeaderSoapAction.Length == 0) throw new Exception("invalid http header 'SOAPAction' (empty)");
                        if (httpRequestHeaderHost.Length == 0) throw new Exception("invalid http header 'Host' (empty)");

                        // continue to read if header "Expect: 100-continue" is present
                        if ((httpRequestHeaderExpect.Length > 0) && httpRequestHeaderExpect.Contains("100") && httpRequestHeaderExpect.ToUpper().Contains("continue".ToUpper()))
                        {
                            string httpContinue = "HTTP/1.1 100 Continue\r\n\r\n";
                            httpResponse = Encoding.Default.GetBytes(httpContinue.ToString());
                            stream.Write(httpResponse, 0, httpResponse.Length);
                            stream.Flush();

                            httpRequestContent += ReadFromStream(stream, buffer);
                        }

                        // fix POST header for curl insertion, e.g.
                        // POST /<directory>/<service>.soap2jms/1.0 HTTP/1.1
                        // to 
                        // POST http://<server>:<port>/<directory>/<service>.soap2jms/1.0
                        int index = httpRequestHeaderPost.IndexOf(" HTTP/1.");
                        httpRequestHeaderPost = httpRequestHeaderPost.Substring(0, index); // omit " HTTP/1.x" at end
                        httpRequestHeaderPost = httpRequestHeaderPost.Substring("POST ".Length); // omit "POST " at start
                        if (!httpRequestHeaderPost.StartsWith("/")) httpRequestHeaderPost = "/" + httpRequestHeaderPost;
                        httpRequestHeaderPost = "POST " + String.Format("{0}://{1}:{2}", this.httpProtocol, this.remoteHost, this.remotePort) + httpRequestHeaderPost;

                        // fix SOAPAction header for curl insertion, e.g.
                        // SOAPAction: ""
                        // to 
                        // SOAPAction: 
                        if (httpRequestHeaderSoapAction.Length > 0) httpRequestHeaderSoapAction = httpRequestHeaderSoapAction.Replace("\"\"", "");

                        // log extracted HTTP headers for debug purposes
                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderPost, TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderContentType, TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderSoapAction, TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpRequestHeaderHost, TraceManager.VerboseMode.VeryVerbose);

                        // save request to file and output to console
                        string logFilenamePrefix = DateTime.Now.ToString("yyyyMMdd_HHmmss_FFFFFF");

                        // POST http://<server>/<directory>/<service>.soap2jms/1.0
                        string soap2jms = ".soap2jms/1.0";
                        if (httpRequestHeaderPost.EndsWith(soap2jms))
                        {
                            int dashBefore = httpRequestHeaderPost.LastIndexOf('-');
                            int posSoap2jms = httpRequestHeaderPost.IndexOf(soap2jms);
                            if ((dashBefore > -1) && (posSoap2jms > -1) && (posSoap2jms > dashBefore))
                            {
                                string serviceName = httpRequestHeaderPost.Substring(dashBefore + 1, posSoap2jms - dashBefore - 1);
                                logFilenamePrefix += "_" + serviceName;
                            }
                        }

                        string filenameCurl = logFilenamePrefix + "_curl.txt";
                        string filenameRequestBody = logFilenamePrefix + "_request.txt";
                        string filenameRequestRaw = logFilenamePrefix + "_request.raw.txt";
                        string filenameResponseRaw = logFilenamePrefix + "_response.raw.txt";
                        string filenameResponseModified = logFilenamePrefix + "_response.txt";

                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameRequestRaw, TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameRequestBody, TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameCurl, TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameResponseRaw, TraceManager.VerboseMode.VeryVeryVerbose);
                            traceManager.TraceLine(filenameResponseModified, TraceManager.VerboseMode.VeryVeryVerbose);
                        }

                        // log raw request
                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            using (StreamWriter file = new StreamWriter(filenameRequestRaw)) { file.Write(httpRequestRaw); }
                        }

                        // persist http request for curl invocation
                        using (StreamWriter file = new StreamWriter(filenameRequestBody)) { file.Write(httpRequestContent); }

                        // curl
                        string cmd = "curl.exe";
                        string soapRequest = filenameRequestBody;
                        string parameter_template = "--header \"{0}\" --header \"{1}\" --data @{2} --insecure --request {3} --include --negotiate --user : {4}";
                        string parameters = String.Format(parameter_template, httpRequestHeaderContentType, httpRequestHeaderSoapAction, soapRequest, httpRequestHeaderPost, this.curlOptions);
                        // e.g. "--header \"Content-Type: text/xml; charset=utf-8\" --header \"SOAPAction:\" --data @soapreq.txt --insecure --request POST http://kerberos-ta.intralb2.de.tmo/carmen123QA/de-tmobile-cprm-acheck-services-CPRM-BusinessParty-ACheckServices-addressCheck-addressCheck.soap2jms/1.0 --include --negotiate --user :";

                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(cmd + " " + parameters, TraceManager.VerboseMode.VeryVerbose);

                        // log curl params
                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            using (StreamWriter file = new StreamWriter(filenameCurl)) { file.Write(cmd + " " + parameters); }
                        }

                        // start curl process and redirect standard output / standard error
                        p = new Process();

                        p.StartInfo.FileName = cmd;
                        p.StartInfo.Arguments = parameters;
                        p.StartInfo.CreateNoWindow = true;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;

                        bool success = p.Start();

                        if (!success) throw new Exception(String.Format("curl invocation failed: {0} (see '{1}' for details))", cmd, filenameCurl));

                        string httpResponseRaw = p.StandardOutput.ReadToEnd();
                        string httpResponseError = p.StandardError.ReadToEnd();  // WAS IST IM FEHLERFALL ZU TUN?

                        p.WaitForExit();

                        // log response (raw)
                        if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            using (StreamWriter file = new StreamWriter(filenameResponseRaw)) { file.Write(httpResponseRaw); }
                        }

                        // delete http request file for curl invocation
                        if (this.verboseMode != TraceManager.VerboseMode.VeryVeryVerbose)
                        {
                            try
                            {
                                File.Delete(filenameRequestBody);
                            }
                            catch (Exception)
                            {
                                // ignore errors and keep file
                            }
                        }

                        if ((httpResponseRaw.Length == 0) && (httpResponseError.Length != 0)) throw new Exception(String.Format("curl failed with error:\n{0}", httpResponseError));

                        // bei mehreren HTTP-Chunks: letzten Chunk extrahieren. Beispiel:

                        /*
                            HTTP/1.1 100 Continue

                            HTTP/1.1 200 OK
                            Server: Apache-Coyote/1.1
                            X-Powered-By: Some Component
                            X-Shortcut: true
                            Content-Type: text/xml;charset=utf-8
                            Transfer-Encoding: chunked
                            Date: Tue, 21 Aug 2012 14:19:54 GMT

                            <?xml version='1.0' encoding='UTF-8'?>
                            ...
                        */

                        int trueStartOfHttpResponse = httpResponseRaw.LastIndexOf("\r\nHTTP/1.");
                        if (trueStartOfHttpResponse > -1) trueStartOfHttpResponse += 2; // \r\n überspringen und ab "HTTP/1.1 200 OK" extrahieren
                        else
                        {
                            trueStartOfHttpResponse = httpResponseRaw.LastIndexOf("HTTP/1.");
                        }

                        if (trueStartOfHttpResponse > -1) httpResponseRaw = httpResponseRaw.Substring(trueStartOfHttpResponse);

                        // Replace "Transfer-Encoding: chunked" by "Content-Length: <count_of_bytes>"

                        string[] httpResponseParts = httpResponseRaw.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        if (httpResponseParts.Length != 2) throw new Exception(String.Format("invalid http raw return: httpResponseParts.Length = {0}", httpResponseParts.Length.ToString()));

                        string httpResponseHeaders = httpResponseParts[0];
                        string httpResponseContent = httpResponseParts[1];

                        int contentLength = httpResponseContent.Length;

                        // Header "Transfer-Encoding: chunked" durch "Content-Length: <count>" ersetzen
                        StringBuilder httpResponseModified = new StringBuilder();

                        string[] headers = httpResponseHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string httpResponseHeader in headers)
                        {
                            if (httpResponseHeader.StartsWith("Transfer-Encoding:", StringComparison.InvariantCultureIgnoreCase))
                            {
                                httpResponseModified.Append(String.Format("Content-Length: {0}", contentLength.ToString()) + "\r\n");
                            }
                            else
                            {
                                httpResponseModified.Append(httpResponseHeader + "\r\n");
                            }
                        }

                        httpResponseModified.Append("\r\n");
                        httpResponseModified.Append(httpResponseContent);

                        traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(httpResponseModified.ToString(), TraceManager.VerboseMode.VeryVerbose);

                        // log response (modified)
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
                        if (p != null) p.Close();
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
            }

        }

        public string ReadFromStream(NetworkStream stream, byte[] buffer)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentNullException("buffer");

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
