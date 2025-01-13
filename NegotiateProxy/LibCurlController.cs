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
using System.Collections.Specialized;
using System.IO;
using System.Reflection;
using System.Text;
using SeasideResearch.LibCurlNet;

namespace NegotiateProxy
{
    class LibCurlController : ICurlController
    {
        // members

        private ParameterSet parameterSet;
        private TraceManager.VerboseMode verboseMode;
        private TraceManager traceManager;
        private bool isInitialized = false;
        private string assemblyName;
        private string assemblyVersion;

        // Local Kerberos Ticket Cache
        private static KerberosTicket cachedKerberosTicket = new KerberosTicket();

        // verify dependent files
        public void ValidateDependentFiles()
        {
            if (!File.Exists(Constants.cLibCurlNetFilename)) throw new FileNotFoundException(Constants.cLibCurlNetFilename);
            if (!File.Exists(Constants.cLibCurlShimFilename)) throw new FileNotFoundException(Constants.cLibCurlShimFilename);
            if (!File.Exists(Constants.cLibCurlFilename)) throw new FileNotFoundException(Constants.cLibCurlFilename);
            if (!File.Exists(Constants.cLibCurlLicenceFilename)) throw new FileNotFoundException(Constants.cLibCurlLicenceFilename);
            if (!File.Exists(Constants.cLibCurlNetLicenceFilename)) throw new FileNotFoundException(Constants.cLibCurlNetLicenceFilename);
            if (!File.Exists(Constants.cLicenceFilename)) throw new FileNotFoundException(Constants.cLicenceFilename);
        }

        // retrieve version string
        public string GetVersion()
        {
            this.Init();
            return Curl.Version + Environment.NewLine + Environment.NewLine + GetVersionEx();
        }

        public string GetVersionEx()
        {
            this.Init();

            VersionInfoData vid = Curl.GetVersionInfo(CURLversion.CURLVERSION_NOW);

            int features = vid.Features;
            string host = vid.Host;
            string libidn = vid.LibIDN;
            string libz = vid.LibZVersion;
            string[] protocols = vid.Protocols;
            string sslVersion = vid.SSLVersion;
            string curlVersion = vid.Version;

            StringBuilder version = new StringBuilder();

            // version.AppendLine("Host:        " + host);
            // version.AppendLine("libidn:      " + libidn);
            // version.AppendLine("libz:        " + libz);
            // version.AppendLine("sslVersion:  " + sslVersion);
            // version.AppendLine("curlVersion: " + curlVersion);
            
            version.Append("Protocols:   ");
            foreach (string protocol in protocols)
            {
                version.Append(protocol + ",");
            }
            if (version[version.Length-1] == ',') version.Remove(version.Length - 1, 1);
            version.AppendLine();

            version.Append("Features:    ");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_IPV6) != 0) version.Append("IPv6,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_KERBEROS4) != 0) version.Append("Kerberos4,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_SSL) != 0) version.Append("SSL,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_LIBZ) != 0) version.Append("libz,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_NTLM) != 0) version.Append("NTLM,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_GSSNEGOTIATE) != 0) version.Append("GSS-Negotiate,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_DEBUG) != 0) version.Append("Debug,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_ASYNCHDNS) != 0) version.Append("AsynchDNS,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_SPNEGO) != 0) version.Append("SPNEGO,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_LARGEFILE) != 0) version.Append("Largefile,");
            if ((features & (int)CURLversionFeatureBitmask.CURL_VERSION_IDN) != 0) version.Append("idn,");
            if (version[version.Length - 1] == ',') version.Remove(version.Length - 1, 1);
            version.AppendLine();

            return version.ToString();
        }

        // retrieve licence files
        public NameValueCollection GetLicenceFiles()
        {
            NameValueCollection licenceFiles = new NameValueCollection();
            licenceFiles.Add(Constants.cNegotiateProxy, Constants.cLicenceFilename);
            licenceFiles.Add(Constants.cLibCurl, Constants.cLibCurlLicenceFilename);
            licenceFiles.Add(Constants.cLibCurlNet, Constants.cLibCurlNetLicenceFilename);
            return licenceFiles;
        }

        // initialization
        private void Init()
        {
            CURLcode curlCode = Curl.GlobalInit((int)CURLinitFlag.CURL_GLOBAL_ALL);
            if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("Curl.GlobalInit() failed! ({0})", Enum.GetName(typeof(CURLcode), curlCode)));

            this.assemblyName = GetAssemblyName();
            this.assemblyVersion = GetAssemblyVersion();
        }

        public void Init(ParameterSet parameterSet, TraceManager.VerboseMode verboseMode, TraceManager traceManager)
        {
            if (!this.isInitialized)
            {
                this.Init();

                this.parameterSet = parameterSet;
                this.verboseMode = verboseMode;
                this.traceManager = traceManager;
                this.isInitialized = true;
            }
        }

        // process request
        public string ProcessRequest(bool httpPost, string serviceRequestContent, string soapAction, string contentType, string host, string header, string logFilenamePrefix, out string httpResponseRaw, out string httpResponseError)
        {
            if (!this.isInitialized) throw new ApplicationException("invalid call to ProcessRequest(): no Init() until now!");

            string url = header;
            string httpVerb = httpPost ? "POST " : "GET ";

            if (url.StartsWith(httpVerb, StringComparison.CurrentCultureIgnoreCase)) url = url.Substring(httpVerb.Length);
            bool isSsl = url.StartsWith("https://", StringComparison.CurrentCultureIgnoreCase);

            Slist httpHeaders = null;

            string filenameLibCurlVerbose = logFilenamePrefix + "_response_from_curl.verbose.txt";

            if (verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
            {
                traceManager.TraceLine(filenameLibCurlVerbose, TraceManager.VerboseMode.VeryVeryVerbose);
            }

            Easy easy = null;

            try
            {
                easy = new Easy();

                Easy.WriteFunction wf = new Easy.WriteFunction(OnWriteData);
                Easy.DebugFunction df = new Easy.DebugFunction(OnDebugData);

                StringBuilder writeData = new StringBuilder();
                StringBuilder debugData = new StringBuilder();

                // libcurl
                CURLcode curlCode = easy.SetOpt(CURLoption.CURLOPT_URL, url);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_URL) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_FOLLOWLOCATION, true);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_URL) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_MAXREDIRS, 50);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_MAXREDIRS) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_USERAGENT, this.assemblyName + "/" + this.assemblyVersion);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_USERAGENT) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_NOPROGRESS, true);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_NOPROGRESS) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_HEADER, true);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_HEADER) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_VERBOSE, true);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_VERBOSE) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_WRITEFUNCTION, wf);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_WRITEFUNCTION) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_WRITEDATA, writeData);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_WRITEDATA) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_DEBUGFUNCTION, df);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_DEBUGFUNCTION) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_DEBUGDATA, debugData);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_DEBUGDATA) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_HTTPAUTH, CURLhttpAuth.CURLAUTH_GSSNEGOTIATE);
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_HTTPAUTH) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                curlCode = easy.SetOpt(CURLoption.CURLOPT_USERPWD, ":");
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_USERPWD) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                if (isSsl)
                {
                    // map ssl version
                    CURLsslVersion sslVersion = CURLsslVersion.CURL_SSLVERSION_DEFAULT;
                    if (this.parameterSet.SslVersion == SslVersion.Default) sslVersion = CURLsslVersion.CURL_SSLVERSION_DEFAULT;
                    else if (this.parameterSet.SslVersion == SslVersion.TLSv1) sslVersion = CURLsslVersion.CURL_SSLVERSION_TLSv1;
                    else if (this.parameterSet.SslVersion == SslVersion.SSLv3) sslVersion = CURLsslVersion.CURL_SSLVERSION_SSLv3;
                    else throw new Exception(String.Format("unknown ssl version ({0})", this.parameterSet.SslVersion.ToString()));

                    curlCode = easy.SetOpt(CURLoption.CURLOPT_SSLVERSION, sslVersion);
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_SSLVERSION) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                    curlCode = easy.SetOpt(CURLoption.CURLOPT_SSL_VERIFYHOST, this.parameterSet.VerifyHost);
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_SSL_VERIFYHOST) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                    curlCode = easy.SetOpt(CURLoption.CURLOPT_SSL_VERIFYPEER, this.parameterSet.VerifyPeer);
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_SSL_VERIFYPEER) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                    curlCode = easy.SetOpt(CURLoption.CURLOPT_CAPATH, this.parameterSet.CaPath);
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_CAPATH) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));
                }

                if (httpPost)
                {
                    if (httpHeaders == null) httpHeaders = new Slist();
                    httpHeaders.Append(contentType);
                    httpHeaders.Append(soapAction);
                    httpHeaders.Append(host);

                    curlCode = easy.SetOpt(CURLoption.CURLOPT_CUSTOMREQUEST, "POST");
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_CUSTOMREQUEST) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                    curlCode = easy.SetOpt(CURLoption.CURLOPT_POSTFIELDS, serviceRequestContent);
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_POSTFIELDS) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));
                }

                if (cachedKerberosTicket.IsValid())
                {
                    if (httpHeaders == null) httpHeaders = new Slist();
                    httpHeaders.Append(cachedKerberosTicket.Ticket);
                }

                if (httpHeaders != null)
                {
                    curlCode = easy.SetOpt(CURLoption.CURLOPT_HTTPHEADER, httpHeaders);
                    if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.SetOpt(CURLOPT_HTTPHEADER) failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));
                }

                curlCode = easy.Perform();
                if (curlCode != CURLcode.CURLE_OK) throw new Exception(String.Format("easy.Perform() failed! ({0}: {1})", Enum.GetName(typeof(CURLcode), curlCode), easy.StrError(curlCode)));

                httpResponseRaw = writeData.ToString();
                string httpResponseLog = debugData.ToString();
                httpResponseError = "";

                traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(httpResponseRaw, TraceManager.VerboseMode.VeryVerbose);

                traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVeryVerbose);
                traceManager.TraceLine(httpResponseLog, TraceManager.VerboseMode.VeryVeryVerbose);

                // log curl params
                if (verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
                {
                    using (StreamWriter file = new StreamWriter(filenameLibCurlVerbose)) { file.Write(httpResponseLog); }
                }

                string httpResponseModified = Utilities.CorrectifyHttpResponse(httpResponseRaw);
                return httpResponseModified;
            }
            finally
            {
                if (httpHeaders != null) httpHeaders.FreeAll();
                if (easy != null) easy.Cleanup();
            }
        }

        // cleanup
        public void Cleanup()
        {
            Curl.GlobalCleanup();
        }

        private string GetAssemblyName()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();
            return assemblyName.Name;
        }

        private string GetAssemblyVersion()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();
            return assemblyName.Version.ToString();
        }

        private Int32 OnWriteData(Byte[] buf, Int32 size, Int32 nmemb, Object extraData)
        {
            string data = System.Text.Encoding.UTF8.GetString(buf);
            StringBuilder writeData = (StringBuilder)extraData;
            writeData.Append(data);
            return size * nmemb;
        }

        private void OnDebugData(CURLINFOTYPE infoType, string message, Object extraData)
        {
            if ((infoType == CURLINFOTYPE.CURLINFO_SSL_DATA_IN) || (infoType == CURLINFOTYPE.CURLINFO_SSL_DATA_OUT)) return; // do not display encrypted binary context
            string msg = "[DEBUG] " + Enum.GetName(typeof(CURLINFOTYPE), infoType) + ": " + message;
            StringBuilder debugData = (StringBuilder)extraData;
            if (msg.EndsWith("\n")) debugData.Append(msg);
            else debugData.AppendLine(msg);
 
            // extract Kerberos ticket
            if (cachedKerberosTicket.IsValid()) return;

            string httpHeaderPrefix = "Authorization: Negotiate ";
            if ((infoType == CURLINFOTYPE.CURLINFO_HEADER_OUT) && 
                (message.IndexOf(httpHeaderPrefix, StringComparison.CurrentCultureIgnoreCase) >= 0))
            {
                string[] httpHeaders = message.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string httpHeader in httpHeaders)
                {
                    if (httpHeader.StartsWith(httpHeaderPrefix, StringComparison.CurrentCultureIgnoreCase))
                    {
                        string currentTicket = httpHeader;
                        cachedKerberosTicket.Ticket = currentTicket;
                        cachedKerberosTicket.ValidTo = DateTime.Now.AddSeconds(this.parameterSet.CacheValidToAsInteger);

                        traceManager.TraceLine(String.Format("Caching Kerberos Ticket (valid until {0})", cachedKerberosTicket.ValidTo.ToString("dd.MM.yyyy HH:mm:ss")), TraceManager.VerboseMode.None);
                        traceManager.TraceLine(cachedKerberosTicket.Ticket, TraceManager.VerboseMode.None);

                        return;
                    }
                }
            }
        }

    }
}
