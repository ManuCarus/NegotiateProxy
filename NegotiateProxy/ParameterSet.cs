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
using System.IO;
using System.Net;

namespace NegotiateProxy
{
    internal enum SslVersion { Default, TLSv1, SSLv3}
    internal enum VerifyHost { NoVerify = 0, CheckExistence = 1, EnsureMatch = 2 }

    internal sealed class ParameterSet
    {
        // defaults
        private static string cDefaultLocalHost     = "localhost";
        private static string cDefaultLocalPort     = "6268";
        private static string cDefaultRemotePort    = "443";
        private static string cDefaultProtocol      = Constants.cHttps;
        private static string cDefaultCacheValidTo  = "43200"; // 12 hours

        // command line options
        private const string cLocalHost         = "--localhost";
        private const string cLocalHostAbbr     = "-lh";
        private const string cLocalPort         = "--localport";
        private const string cLocalPortAbbr     = "-lp";
        private const string cRemoteHost        = "--remotehost";
        private const string cRemoteHostAbbr    = "-rh";
        private const string cRemotePort        = "--remoteport";
        private const string cRemotePortAbbr    = "-rp";
        private const string cProtocol          = "--protocol";
        private const string cProtocolAbbr      = "-p";
        private const string cCacheValidTo      = "--preauthentication";
        private const string cCacheValidToAbbr  = "-pr";
        private const string cLibCurl           = "--libcurl";
        private const string cLibCurlAbbr       = "-lc";
        private const string cCurl              = "--curl";
        private const string cCurlAbbr          = "-c";
        private const string cLog               = "--log";
        private const string cLogAbbr           = "-l";
        private const string cSslVersion        = "--ssl-version";
        private const string cSslVersionAbbr    = "-sv";
        private const string cVerifyHost        = "--verify-host";
        private const string cVerifyHostAbbr    = "-vh";
        private const string cNoVerifyPeer      = "--no-verify-peer";
        private const string cNoVerifyPeerAbbr  = "-vp";
        private const string cCaPath            = "--ca-path";
        private const string cCaPathAbbr        = "-ca";
        private const string cQuiet             = "--quiet";
        private const string cQuietAbbr         = "-q";
        private const string cLicence           = "--licence";
        private const string cLicense           = "--license";
        private const string cLicenceAbbr       = "-l";
        private const string cHelp              = "--help";
        private const string cHelpAbbr          = "-h";
        private const string cHelpQuestionMark  = "/?";
        private const string cVerbose           = "--verbose";
        private const string cVerboseAbbr       = "-v";
        private const string cDump              = "--dump";
        private const string cDumpAbbr          = "-d";

        internal const char cOptionDelimiter = ':';

        // private members
        private string     localHost;
        private string     localPort;
        private string     remoteHost;
        private string     remotePort;
        private string     httpProtocol;
        private string     cacheValidTo;
        private bool       libcurl;
        private string     logFile;
        private SslVersion sslVersion;
        private VerifyHost verifyHost;
        private bool       verifyPeer;
        private string     caPath;
        private bool       quiet;
        private bool       licence;
        private bool       help;

        private TraceManager.VerboseMode verboseMode;


        // ctor
        internal ParameterSet()
        {
            localHost    = cDefaultLocalHost;
            localPort    = cDefaultLocalPort;
            remoteHost   = String.Empty;
            remotePort   = cDefaultRemotePort;
            httpProtocol = cDefaultProtocol;
            cacheValidTo = cDefaultCacheValidTo;
            libcurl      = true;
            logFile      = String.Empty;
            sslVersion   = SslVersion.Default;
            verifyHost   = VerifyHost.EnsureMatch;
            verifyPeer   = true;
            caPath       = Environment.CurrentDirectory + "\\" + Constants.cCaPath;
            quiet        = false;
            licence      = false;
            help         = false;

            verboseMode = TraceManager.VerboseMode.None;
        }

        // getter/setter

        internal string LocalHost
        {
            get { return localHost; }
        }

        internal string LocalPort
        {
            get { return localPort; }
        }

        internal string RemoteHost
        {
            get { return remoteHost; }
        }

        internal string RemotePort
        {
            get { return remotePort; }
        }

        internal string HttpProtocol
        {
            get { return httpProtocol; }
        }

        internal string CacheValidTo
        {
            get { return cacheValidTo; }
        }

        internal int CacheValidToAsInteger
        {
            get { return Utilities.ConvertToInteger(cacheValidTo); }
        }

        internal bool LibCurl
        {
            get { return libcurl; }
        }

        internal string LogFile
        {
            get { return logFile; }
        }

        internal SslVersion SslVersion
        {
            get { return sslVersion; }
        }

        internal VerifyHost VerifyHost
        {
            get { return verifyHost; }
        }

        internal bool VerifyPeer
        {
            get { return verifyPeer; }
        }

        internal string CaPath
        {
            get { return caPath; }
        }

        internal bool Quiet
        {
            get { return quiet; }
        }

        internal bool Licence
        {
            get { return licence; }
        }

        internal bool Help
        {
            get { return help; }
        }

        internal TraceManager.VerboseMode Verbose
        {
            get { return verboseMode; }
        }

        internal bool Dump
        {
            get { return (verboseMode == TraceManager.VerboseMode.VeryVeryVerbose); }
        }

        // look ahead for command line parameters
        internal static void LookAheadCommandLineParameters(string[] args, out bool libcurl, out bool quiet, out bool licence, out bool help)
        {
            if (args == null) throw new NullReferenceException("arguments not set!");

            libcurl = false;
            quiet = false;
            licence = false;
            help = false;

            bool tmpLibCurl = false;
            bool tmpCurl = false;

            foreach (string arg in args)
            {
                if (String.Compare(arg, cLibCurl, true) == 0)          tmpLibCurl = true;
                if (String.Compare(arg, cLibCurlAbbr, true) == 0)      tmpLibCurl = true;
                if (String.Compare(arg, cCurl, true) == 0)             tmpCurl = true;
                if (String.Compare(arg, cCurlAbbr, true) == 0)         tmpCurl = true;
                if (String.Compare(arg, cQuiet, true) == 0)            quiet = true;
                if (String.Compare(arg, cQuietAbbr, true) == 0)        quiet = true;
                if (String.Compare(arg, cLicence, true) == 0)          licence = true;
                if (String.Compare(arg, cLicense, true) == 0)          licence = true;
                if (String.Compare(arg, cLicenceAbbr, true) == 0)      licence = true;
                if (String.Compare(arg, cHelp, true) == 0)             help = true;
                if (String.Compare(arg, cHelpAbbr, true) == 0)         help = true;
                if (String.Compare(arg, cHelpQuestionMark, true) == 0) help = true;
            }

            libcurl = VerifyCurlMode(tmpLibCurl, tmpCurl);
        }

        // parse command line
        internal void ParseCommandLine(string[] args)
        {
            if (args == null) throw new NullReferenceException("arguments not set!");

            bool tmpLibCurl = false;
            bool tmpCurl = false;

            foreach (string arg in args)
            {
                if (arg.StartsWith(cLocalHost + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                    arg.StartsWith(cLocalHostAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --localhost:<host>
                    string localHost = GetOptionValue(arg);
                    this.localHost = localHost;
                }
                else if (arg.StartsWith(cLocalPort + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cLocalPortAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --localport:<port>
                    string localPort = GetOptionValue(arg);
                    this.localPort = localPort;
                }
                else if (arg.StartsWith(cRemoteHost + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cRemoteHostAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --remotehost:<host>
                    string remoteHost = GetOptionValue(arg);
                    this.remoteHost = remoteHost;
                }
                else if (arg.StartsWith(cRemotePort + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cRemotePortAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --remoteport:<port>
                    string remotePort = GetOptionValue(arg);
                    this.remotePort = remotePort;
                }
                else if (arg.StartsWith(cProtocol + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cProtocolAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --protocol:<protocol>
                    string httpProtocol = GetOptionValue(arg);
                    this.httpProtocol = httpProtocol;
                }
                else if (arg.StartsWith(cCacheValidTo + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cCacheValidToAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --preauthentication:<sec>
                    string cacheValidTo = GetOptionValue(arg);
                    this.cacheValidTo = cacheValidTo;
                }
                else if (arg.Equals(cLibCurl, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cLibCurlAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --libcurl
                    tmpLibCurl = true;
                }
                else if (arg.Equals(cCurl, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cCurlAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --curl
                    tmpCurl = true;
                }
                else if (arg.StartsWith(cLog + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cLogAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --log:<file>
                    string logFile = GetOptionValue(arg);
                    this.logFile = logFile;
                }
                else if (arg.StartsWith(cSslVersion + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cSslVersionAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --ssl-version:<version>
                    string sslVersion = GetOptionValue(arg);
                    this.sslVersion = (SslVersion)Enum.Parse(typeof(SslVersion), sslVersion, true);
                }
                else if (arg.StartsWith(cVerifyHost + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cVerifyHostAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --verify-host:<flag>
                    string verifyHost = GetOptionValue(arg);
                    if (verifyHost.Equals("0")) this.verifyHost = VerifyHost.NoVerify;
                    else if (verifyHost.Equals("1")) this.verifyHost = VerifyHost.CheckExistence;
                    else if (verifyHost.Equals("2")) this.verifyHost = VerifyHost.EnsureMatch;
                    else throw new ArgumentException(String.Format("invalid value for --verify-host ({0})", verifyHost));
                }
                else if (arg.Equals(cNoVerifyPeer, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cNoVerifyPeerAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --no-verify-peer
                    this.verifyPeer = false;
                }
                else if (arg.StartsWith(cCaPath + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith(cCaPathAbbr + cOptionDelimiter, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --ca-path:<path>
                    string caPath = GetOptionValue(arg);
                    this.caPath = caPath;
                }
                else if (arg.Equals(cQuiet, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cQuietAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --quiet
                    this.quiet = true;
                }
                else if (arg.Equals(cLicence, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cLicense, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cLicenceAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --licence
                    this.licence = true;
                }
                else if (arg.Equals(cHelp, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cHelpAbbr, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cHelpQuestionMark, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --help
                    this.help = true;
                }
                else if (arg.Equals(cVerbose, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cVerboseAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --verbose
                    IncreaseVerboseLevel();
                }
                else if (arg.Equals(cDump, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cDumpAbbr, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --dump
                    this.verboseMode = TraceManager.VerboseMode.VeryVeryVerbose;
                }
                else if (arg.StartsWith("-", StringComparison.CurrentCultureIgnoreCase) ||
                         arg.StartsWith("/", StringComparison.CurrentCultureIgnoreCase))
                {
                    // unknown option
                    throw new ArgumentException(String.Format("syntax error: invalid command line parameter {0}!", arg));
                }
                else
                {
                    // short proxy notation: [<localport>:]<remotehost>[:<remoteport>][:<protocol>]
                    string[] parts = arg.Split(new char[] { cOptionDelimiter });

                    if ((parts == null) || (parts.Length == 0)) throw new ArgumentException(String.Format("syntax error: invalid short notation [<localport>:]<remotehost>[:<remoteport>][:<protocol>] ({0})!", arg));
                    else if (parts.Length == 1)
                    {
                        // e.g. kerberos-ta.intralb2.de.tmo
                        this.localHost = cDefaultLocalHost;
                        this.localPort = cDefaultLocalPort;
                        this.remoteHost = arg;
                        this.remotePort = cDefaultRemotePort;
                        this.httpProtocol = cDefaultProtocol;
                    }
                    else if (parts.Length == 2)
                    {
                        // e.g. 8080:kerberos-ta.intralb2.de.tmo
                        // or   kerberos-ta.intralb2.de.tmo:9043
                        // or   kerberos-ta.intralb2.de.tmo:https

                        if (Utilities.IsPort(parts[0]) && Utilities.IsHost(parts[1]))
                        {
                            // e.g. 8080:kerberos-ta.intralb2.de.tmo
                            this.localHost = cDefaultLocalHost;
                            this.localPort = parts[0];
                            this.remoteHost = parts[1];
                            this.remotePort = cDefaultRemotePort;
                            this.httpProtocol = cDefaultProtocol;
                        }
                        else if (Utilities.IsHost(parts[0]) && Utilities.IsPort(parts[1]))
                        {
                            // e.g. kerberos-ta.intralb2.de.tmo:9043
                            this.localHost = cDefaultLocalHost;
                            this.localPort = cDefaultLocalPort;
                            this.remoteHost = parts[0];
                            this.remotePort = parts[1];
                            this.httpProtocol = cDefaultProtocol;
                        }
                        else if (Utilities.IsHost(parts[0]) && Utilities.IsProtocol(parts[1]))
                        {
                            // e.g. kerberos-ta.intralb2.de.tmo:https
                            this.localHost = cDefaultLocalHost;
                            this.localPort = cDefaultLocalPort;
                            this.remoteHost = parts[0];
                            this.remotePort = cDefaultRemotePort;
                            this.httpProtocol = parts[1];
                        }
                        else
                        {
                            throw new ArgumentException(String.Format("syntax error: invalid short notation [<localport>:]<remotehost>[:<remoteport>][:<protocol>] ({0})!", arg));
                        }
                    }
                    else if (parts.Length == 3)
                    { 
                        // e.g. 8080:kerberos-ta.intralb2.de.tmo:9043
                        // or   8080:kerberos-ta.intralb2.de.tmo:https
                        // or   kerberos-ta.intralb2.de.tmo:9043:https

                        if (Utilities.IsPort(parts[0]) && Utilities.IsHost(parts[1]) && Utilities.IsPort(parts[2]))
                        {
                            // e.g. 8080:kerberos-ta.intralb2.de.tmo:9043
                            this.localHost = cDefaultLocalHost;
                            this.localPort = parts[0];
                            this.remoteHost = parts[1];
                            this.remotePort = parts[2];
                            this.httpProtocol = cDefaultProtocol;
                        }
                        else if (Utilities.IsPort(parts[0]) && Utilities.IsHost(parts[1]) && Utilities.IsProtocol(parts[2]))
                        {
                            // e.g. 8080:kerberos-ta.intralb2.de.tmo:https
                            this.localHost = cDefaultLocalHost;
                            this.localPort = parts[0];
                            this.remoteHost = parts[1];
                            this.remotePort = cDefaultRemotePort;
                            this.httpProtocol = parts[2];
                        }
                        else if (Utilities.IsHost(parts[0]) && Utilities.IsPort(parts[1]) && Utilities.IsProtocol(parts[2]))
                        {
                            // e.g. kerberos-ta.intralb2.de.tmo:9043:https
                            this.localHost = cDefaultLocalHost;
                            this.localPort = cDefaultLocalPort;
                            this.remoteHost = parts[0];
                            this.remotePort = parts[1];
                            this.httpProtocol = parts[2];
                        }
                        else
                        {
                            throw new ArgumentException(String.Format("syntax error: invalid short notation [<localport>:]<remotehost>[:<remoteport>][:<protocol>] ({0})!", arg));
                        }
                    }
                    else if (parts.Length == 4)
                    {
                        // e.g. 8080:kerberos-ta.intralb2.de.tmo:9043:https
                        this.localHost = cDefaultLocalHost;
                        this.localPort = parts[0];
                        this.remoteHost = parts[1];
                        this.remotePort = parts[2];
                        this.httpProtocol = parts[3];
                    }
                    else // (parts.Length > 4)
                    {
                        throw new ArgumentException(String.Format("syntax error: invalid short notation [<localport>:]<remotehost>[:<remoteport>][:<protocol>] ({0})!", arg));
                    }

                    if (String.IsNullOrEmpty(this.localHost)) this.localHost = cDefaultLocalHost;
                }
            }

            this.libcurl = VerifyCurlMode(tmpLibCurl, tmpCurl);
        }

        // helper: split "--option:value"
        private string GetOptionValue(string arg)
        {
            if (String.IsNullOrEmpty(arg)) throw new NullReferenceException("argument not set!");
            if (arg.IndexOf(cOptionDelimiter) < 0) throw new ArgumentException(String.Format("syntax error: invalid option ({0}) -> use '{1}' as delimiter!", arg, cOptionDelimiter.ToString()));

            string optionValue = arg.Substring(arg.IndexOf(cOptionDelimiter) + 1); // e.g. "--remotehost:10.100.20.30"
            if (String.IsNullOrEmpty(optionValue)) throw new ArgumentException(String.Format("syntax error: no value specified for option ({0})!", arg));
            return optionValue;
        }

        // helper
        private void IncreaseVerboseLevel()
        {
            if (this.verboseMode == TraceManager.VerboseMode.None) this.verboseMode = TraceManager.VerboseMode.Verbose;
            else if (this.verboseMode == TraceManager.VerboseMode.Verbose) this.verboseMode = TraceManager.VerboseMode.VeryVerbose;
            else if (this.verboseMode == TraceManager.VerboseMode.VeryVerbose) this.verboseMode = TraceManager.VerboseMode.VeryVeryVerbose;
            else if (this.verboseMode == TraceManager.VerboseMode.VeryVeryVerbose) this.verboseMode = TraceManager.VerboseMode.VeryVeryVerbose;
        }

        private static bool VerifyCurlMode(bool tmpLibCurl, bool tmpCurl)
        {
            if (tmpLibCurl && tmpCurl) throw new ArgumentException("invalid parameters (--libcurl and --curl cannot be used together)!");

            bool libcurl = false;
            if (!tmpLibCurl && !tmpCurl) libcurl = true; // if not specified, --libcurl is default 
            else libcurl = tmpLibCurl;

            return libcurl;
        }

        // validate parameter set
        internal void Validate()
        {
            // mandatory fields
            if (String.IsNullOrEmpty(this.localHost)) throw new ArgumentException(String.Format("syntax error: --localhost must be set!", this.localHost));
            if (String.IsNullOrEmpty(this.localPort)) throw new ArgumentException(String.Format("syntax error: --localport must be set!", this.localPort));
            if (String.IsNullOrEmpty(this.remoteHost)) throw new ArgumentException(String.Format("syntax error: --remotehost must be set!", this.remoteHost));
            if (String.IsNullOrEmpty(this.remotePort)) throw new ArgumentException(String.Format("syntax error: --remoteport must be set!", this.remotePort));

            // --localHost:<host>
            if (!Utilities.IsHost(this.localHost)) throw new ArgumentException(String.Format("syntax error: --localhost must be FQDN or IP (invalid value '{0}')!", this.localHost));

            // --localport:<port>
            ValidatePort(this.localPort, "--localport");

            // --remoteHost:<host>
            if (!Utilities.IsHost(this.remoteHost)) throw new ArgumentException(String.Format("syntax error: --remotehost must be FQDN or IP (invalid value '{0}')!", this.remoteHost));

            // --remoteport:<port>
            ValidatePort(this.remotePort, "--remoteport");

            // --httpProtocol:<protocol>
            if (!Utilities.IsProtocol(this.httpProtocol)) throw new ArgumentException(String.Format("syntax error: --protocol must be HTTP or HTTPS (invalid value '{0}')!", this.httpProtocol));

            // --preauthentication:<sec>
            ValidateCacheDuration(this.cacheValidTo, "--preauthentication");

            // --log:<file>
            if (!String.IsNullOrEmpty(this.logFile))
            {
                try
                {
                    StreamWriter sw = File.CreateText(this.logFile);
                    if (sw != null) sw.Close();
                    try { File.Delete(this.logFile); }
                    catch { }
                }
                catch (Exception)
                {
                    throw new ArgumentException(String.Format("syntax error: cannot create log file ('{0}')", this.logFile));
                }
            }

            // SSL Options
            if (this.libcurl && Utilities.IsSsl(this.httpProtocol))
            {
                // ssl-version and verify-host have already been validated in ParseCommandLine()
                
                // ca-path
                if (!Directory.Exists(this.caPath)) throw new ArgumentException(String.Format("invalid CA path ('{0}' does not exist)", this.caPath));
            }
        }

        internal void ValidatePort(string port, string parameter)
        {
            if (String.IsNullOrEmpty(port)) throw new NullReferenceException("port not set!");
            if (String.IsNullOrEmpty(parameter)) throw new NullReferenceException("parameter not set!");

            if (!Utilities.IsPort(port)) throw new ArgumentException(String.Format("syntax error: {0} must be a valid number between {1} and {2} (invalid value '{3}')!", parameter, Constants.cMinimumPort.ToString(), Constants.cMaximumPort.ToString(), port));
        }

        internal void ValidateCacheDuration(string seconds, string parameter)
        {
            if (String.IsNullOrEmpty(seconds)) throw new NullReferenceException("seconds not set!");
            if (String.IsNullOrEmpty(parameter)) throw new NullReferenceException("parameter not set!");

            if (!Utilities.IsCacheDuration(seconds)) throw new ArgumentException(String.Format("syntax error: {0} must be a valid number between {1} and {2} (invalid value '{3}')!", parameter, Constants.cMinimumSeconds.ToString(), Constants.cMaximumSeconds.ToString(), seconds));
        }

    }
}
