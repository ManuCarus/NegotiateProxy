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

namespace NegotiateProxy
{
    class CurlController : ICurlController
    {
        // members
        private ParameterSet parameterSet;
        private TraceManager.VerboseMode verboseMode;
        private TraceManager traceManager;
        private bool isInitialized = false;
        private string assemblyName;
        private string assemblyVersion;

        // verify dependent files
        public void ValidateDependentFiles()
        {
            if (!File.Exists(Constants.cCurlFilename)) throw new FileNotFoundException(Constants.cCurlFilename);
            if (!File.Exists(Constants.cCurlLicenceFilename)) throw new FileNotFoundException(Constants.cCurlLicenceFilename);
            if (!File.Exists(Constants.cLicenceFilename)) throw new FileNotFoundException(Constants.cLicenceFilename);
        }

        // retrieve version string
        public string GetVersion()
        {
            ProcessController pc = new ProcessController();

            string standardOutput;
            string standardError;

            bool success = pc.Start(Constants.cCurlFilename, Constants.cCurlVersion, out standardOutput, out standardError);
            if (!success) throw new Exception(String.Format("curl failed: {0} {1})", Constants.cCurlFilename, Constants.cCurlVersion));

            string version = standardOutput;
            return version;
        }

        // retrieve licence files
        public NameValueCollection GetLicenceFiles()
        {
            NameValueCollection licenceFiles = new NameValueCollection();
            licenceFiles.Add(Constants.cNegotiateProxy, Constants.cLicenceFilename);
            licenceFiles.Add(Constants.cCurl, Constants.cCurlLicenceFilename);
            return licenceFiles;
        }

        // initialization
        public void Init(ParameterSet parameterSet, TraceManager.VerboseMode verboseMode, TraceManager traceManager)
        {
            if (!this.isInitialized)
            {
                this.parameterSet = parameterSet;
                this.verboseMode = verboseMode;
                this.traceManager = traceManager;
                this.isInitialized = true;

                this.assemblyName = GetAssemblyName();
                this.assemblyVersion = GetAssemblyVersion();
            }
        }

        // process request
        public string ProcessRequest(bool httpPost, string serviceRequestContent, string soapAction, string contentType, string host, string header, string logFilenamePrefix, out string httpResponseRaw, out string httpResponseError)
        {
            if (!this.isInitialized) throw new ApplicationException("invalid call to ProcessRequest(): no Init() until now!");

            string filenameCurl = logFilenamePrefix + "_curl.cmd.txt";
            string filenameRequestBody = logFilenamePrefix + "_request.curl.param.txt";
            // string filenameCurlRawOutput = logFilenamePrefix + "_curl.raw.output.txt"; // see curlVerbose below

            if (verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
            {
                traceManager.TraceLine(filenameCurl, TraceManager.VerboseMode.VeryVeryVerbose);
                traceManager.TraceLine(filenameRequestBody, TraceManager.VerboseMode.VeryVeryVerbose);
                // traceManager.TraceLine(filenameCurlRawOutput, TraceManager.VerboseMode.VeryVeryVerbose); // see curlVerbose below
            }

            // persist http request for curl invocation
            if ((serviceRequestContent != null) && (serviceRequestContent.Length > 0))
            {
                using (StreamWriter file = new StreamWriter(filenameRequestBody)) { file.Write(serviceRequestContent); }
            }

            // fix SOAPAction header for curl insertion, e.g.
            // SOAPAction: ""
            // to 
            // SOAPAction: \"\"
            if (soapAction.Length > 0) soapAction = soapAction.Replace(@"""", @"\""");

            // curl
            string cmd = Constants.cCurlFilename;
            string parameters = String.Empty;
            string userAgent = this.assemblyName + "/" + this.assemblyVersion;
            string curlVerbose = (this.parameterSet.Verbose == TraceManager.VerboseMode.VeryVeryVerbose) ? "--verbose" : String.Empty;
            curlVerbose = String.Empty; // don't support "curl --verbose" since this results in a deadlock at ProcessController.Start() in command "standardOutput = process.StandardOutput.ReadToEnd();"!

            if (httpPost)
            {
                string soapRequest = filenameRequestBody;
                string parameter_template_with_soap_action = "--header \"{0}\" --header \"{1}\" --header \"{2}\" --user-agent \"User-Agent: {3}\" --data @{4} --insecure --request {5} --include --negotiate --user : {6}";
                string parameter_template_without_soap_action = "--header \"{0}\" --header \"{1}\" --user-agent \"{2}\" --data @{3} --insecure --request {4} --include --negotiate --user : {5}";
                if (soapAction.Length > 0) parameters = String.Format(parameter_template_with_soap_action, contentType, soapAction, host, userAgent, soapRequest, header, curlVerbose);
                else parameters = String.Format(parameter_template_without_soap_action, contentType, host, userAgent, soapRequest, header, curlVerbose);
                // e.g. "--header \"Content-Type: text/xml; charset=utf-8\" --header \"SOAPAction:\" --header \"Host: wsg2soabp-pr.intralb.de.tmo:9080\" --data @soapreq.txt --insecure --request POST http://kerberos-ta.intralb2.de.tmo/carmen123QA/de-tmobile-cprm-acheck-services-CPRM-BusinessParty-ACheckServices-addressCheck-addressCheck.soap2jms/1.0 --include --negotiate --user :";
            }
            else // httpGet
            {
                string parameter_template = "--header \"{0}\" --user-agent \"{1}\" --insecure --include --negotiate --user : {2} {3}";
                string url = header;
                if (url.StartsWith("GET ")) url = url.Substring("GET ".Length);
                parameters = String.Format(parameter_template, host, userAgent, curlVerbose, url);
                // e.g. "--header \"Host: kerberos-ta.intralb2.de.tmo:443\" --insecure --include --negotiate --user : http://kerberos-ta.intralb2.de.tmo:443/";
            }

            traceManager.TraceSeparator('-', TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(cmd + " " + parameters, TraceManager.VerboseMode.VeryVerbose);

            // log curl params
            if (verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
            {
                using (StreamWriter file = new StreamWriter(filenameCurl)) { file.Write(cmd + " " + parameters); }
            }

            // start curl process and redirect standard output / standard error
            ProcessController pc = new ProcessController();

            string standardOutput;
            string standardError;

            bool success = pc.Start(cmd, parameters, out standardOutput, out standardError);
            if (!success) throw new Exception(String.Format("curl invocation failed: {0} (see '{1}' for details))", cmd, filenameCurl));

            httpResponseRaw = standardOutput;
            httpResponseError = standardError;

            // delete http request file for curl invocation
            if (verboseMode == TraceManager.VerboseMode.VeryVeryVerbose)
            {
                if ((httpResponseError != null) && (httpResponseError.Length > 0))
                {
                    // using (StreamWriter file = new StreamWriter(filenameCurlRawOutput)) { file.Write(httpResponseError); } // see curlVerbose below
                }
            }
            else
            {
                try
                {
                    File.Delete(filenameRequestBody);
                }
                catch 
                {
                    // ignore errors and keep file
                }
            }

            if ((httpResponseRaw.Length == 0) && (httpResponseError.Length != 0)) throw new Exception(String.Format("curl failed with error:\n{0}", httpResponseError));

            string httpResponseModified = Utilities.CorrectifyHttpResponse(httpResponseRaw);
            return httpResponseModified;
        }

        // cleanup
        public void Cleanup()
        {
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

    }
}
