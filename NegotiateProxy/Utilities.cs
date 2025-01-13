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
using System.Net;
using System.Text;

namespace NegotiateProxy
{
    internal class Utilities
    {
        // helpers
        internal static bool IsFqdn(string host)
        {
            if (String.IsNullOrEmpty(host)) throw new ArgumentNullException("Invalid argument (host is missing)!");

            IPAddress[] ips = Dns.GetHostAddresses(host);

            if ((ips == null) || (ips.Length == 0)) return false;
            else return true;
        }

        internal static bool IsIp(string ip)
        {
            if (String.IsNullOrEmpty(ip)) throw new ArgumentNullException("Invalid argument (ip is missing)!");

            IPAddress ipAddress = null;

            try
            {
                ipAddress = IPAddress.Parse(ip);
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        internal static bool IsHost(string host)
        {
            return (IsIp(host) || IsFqdn(host));
        }

        internal static int ConvertToInteger(string port)
        {
            return int.Parse(port, System.Globalization.NumberStyles.Integer); // eventually throws Exception
        }

        internal static bool IsPort(string port)
        {
            try
            {
                int tmpPort = ConvertToInteger(port);
                if (!IsValidPort(tmpPort)) throw new ArgumentOutOfRangeException(String.Format("Invalid port ({0} is out of range)!", port));

                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsValidPort(int port)
        {
            if ((Constants.cMinimumPort <= port) && (port <= Constants.cMaximumPort)) return true;
            else return false;
        }

        internal static bool IsValidPort(string port)
        {
            try
            {
                int tmpPort = ConvertToInteger(port);
                return IsValidPort(tmpPort);
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsProtocol(string protocol)
        {
            if (protocol.Equals(Constants.cHttp, StringComparison.CurrentCultureIgnoreCase)) return true;
            if (protocol.Equals(Constants.cHttps, StringComparison.CurrentCultureIgnoreCase)) return true;

            return false;
        }

        internal static bool IsCacheDuration(string seconds)
        {
            try
            {
                int value = ConvertToInteger(seconds);
                if (!IsValidCacheDuration(value)) throw new ArgumentOutOfRangeException(String.Format("Invalid cache duration ({0} is out of range)!", value));

                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsValidCacheDuration(int seconds)
        {
            if ((Constants.cMinimumSeconds <= seconds) && (seconds <= Constants.cMaximumSeconds)) return true;
            else return false;
        }

        internal static bool IsValidCacheDuration(string cacheValidTo)
        {
            int seconds = ConvertToInteger(cacheValidTo);
            return IsValidCacheDuration(seconds);
        }

        internal static bool IsSsl(string protocol)
        {
            if (protocol.Equals(Constants.cHttps, StringComparison.CurrentCultureIgnoreCase)) return true;
            else return false;
        }

        internal static string CorrectifyHttpResponse(string httpResponseRaw)
        {
            // bei mehreren HTTP-Chunks: letzten Chunk extrahieren. Beispiel:

            //
            //    HTTP/1.1 100 Continue

            //    HTTP/1.1 200 OK
            //    Server: Apache-Coyote/1.1
            //    X-Powered-By: Some Component
            //    X-Shortcut: true
            //    Content-Type: text/xml;charset=utf-8
            //    Transfer-Encoding: chunked
            //    Date: Tue, 21 Aug 2012 14:19:54 GMT

            //    <?xml version='1.0' encoding='UTF-8'?>
            //    ...
            //

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

            return httpResponseModified.ToString();
        }

    }
}
