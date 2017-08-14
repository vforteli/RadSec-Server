using Flexinets.Radius.Core;
using log4net;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Radius
{
    public class RadSecServer
    {
        private static readonly ILog _log = LogManager.GetLogger(typeof(RadSecServer));
        private readonly TcpListener _server;
        private readonly RadiusDictionary _dictionary;
        private readonly Dictionary<String, (IPacketHandler packetHandler, String secret)> _clients = new Dictionary<String, (IPacketHandler, String)>();
        private readonly X509Certificate _serverCertificate;
        private readonly Boolean _trustClientCertificate;


        /// <summary>
        /// Create a new server on endpoint
        /// </summary>
        /// <param name="localEndpoint"></param>
        /// <param name="serverCertificate"></param>
        /// <param name="dictionary"></param>        
        /// <param name="trustClientCertificate">If set to true, client certificates will not be validated. This can be useful for testing with self signed certificates</param>
        public RadSecServer(IPEndPoint localEndpoint, X509Certificate serverCertificate, RadiusDictionary dictionary, Boolean trustClientCertificate = false)
        {
            _server = new TcpListener(localEndpoint);
            _serverCertificate = serverCertificate;
            _dictionary = dictionary;
            _trustClientCertificate = trustClientCertificate;
        }


        /// <summary>
        /// Add packet handler for client
        /// </summary>
        /// <param name="certificateThumbprint">SHA1 thumbprint of certificate</param>
        /// <param name="sharedSecret"></param>
        /// <param name="packetHandler"></param>
        public void AddClientPacketHandler(String certificateThumbprint, String sharedSecret, IPacketHandler packetHandler)
        {
            _log.Info($"Adding packet handler of type {packetHandler.GetType()} for remote IP");
            _clients.Add(certificateThumbprint, (packetHandler, sharedSecret));
        }


        /// <summary>
        /// Start listening for requests
        /// </summary>
        public void Start()
        {
            _log.Info($"Starting Radius RadSec server on {_server.LocalEndpoint}");
            _server.Start();
            var receiveTask = StartAcceptingClientsAsync();
            _log.Info("Server started");
        }


        /// <summary>
        /// Start the loop used for accepting clients
        /// </summary>
        /// <returns></returns>
        private async Task StartAcceptingClientsAsync()
        {
            while (_server.Server.IsBound)
            {
                try
                {
                    var client = await _server.AcceptTcpClientAsync();
                    var task = Task.Factory.StartNew(() => HandleClient(client), TaskCreationOptions.LongRunning);
                }
                catch (ObjectDisposedException) { } // Thrown when server is stopped while still receiving. This can be safely ignored
                catch (Exception ex)
                {
                    _log.Fatal("Something went wrong accepting client", ex);
                }
            }
        }


        /// <summary>
        /// Stop listening
        /// </summary>
        public void Stop()
        {
            _log.Info("Stopping server");
            _server.Stop();
            _log.Info("Stopped");
        }


        /// <summary>
        /// Receive packets
        /// </summary>
        /// <param name="ar"></param>
        private void HandleClient(TcpClient client)
        {
            try
            {
                _log.Debug($"Connection from {client.Client.RemoteEndPoint}");

                var sslStream = new SslStream(client.GetStream(), false, ValidateClientCertificate);
                sslStream.AuthenticateAsServer(_serverCertificate, true, SslProtocols.Tls12, false);

                if (_clients.TryGetValue(sslStream.RemoteCertificate.GetCertHashString(), out var handler))
                {
                    _log.Debug($"Handling client with {handler.packetHandler.GetType()}");

                    while (RadiusPacket.TryParsePacketFromStream(sslStream, out var requestPacket, _dictionary, Encoding.UTF8.GetBytes(handler.secret)))
                    {
                        _log.Debug(GetPacketDump(requestPacket));

                        var sw = Stopwatch.StartNew();
                        var responsePacket = handler.packetHandler.HandlePacket(requestPacket);
                        sw.Stop();
                        _log.Debug($"Id={responsePacket.Identifier}, Received {responsePacket.Code} from handler in {sw.ElapsedMilliseconds}ms");

                        if (requestPacket.Attributes.ContainsKey("Proxy-State"))
                        {
                            responsePacket.Attributes.Add("Proxy-State", requestPacket.Attributes.SingleOrDefault(o => o.Key == "Proxy-State").Value);
                        }

                        var responsePacketBytes = responsePacket.GetBytes(_dictionary);
                        sslStream.Write(responsePacketBytes, 0, responsePacketBytes.Length);
                    }

                    _log.Debug($"Connection closed to {client.Client.RemoteEndPoint}");
                }
                else
                {
                    _log.Error($"No packet handler found for remote endpoint {client.Client.RemoteEndPoint}");
                }
            }
            catch (AuthenticationException ex)
            {
                _log.Warn($"TLS handshake failed for client with {ex.Message}");
            }
            catch (IOException ioex)
            {
                _log.Warn("oops", ioex);
            }
            catch (Exception ex)
            {
                _log.Error("Something went wrong", ex);
            }
            finally
            {
                client?.Dispose();
            }
        }


        /// <summary>
        /// Validate client certificate
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        private Boolean ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            _log.Debug($"Validating certificate with hash: {certificate.GetCertHashString()}");
            // todo figure out what authentication should be based on, and if CA certificate needs to be installed PKI etc...
            return _trustClientCertificate || sslPolicyErrors == SslPolicyErrors.None;
        }


        /// <summary>
        /// Get a nicely formatted packet attribute dump
        /// </summary>
        /// <param name="packet"></param>
        private static String GetPacketDump(IRadiusPacket packet)
        {
            var sb = new StringBuilder();
            if (packet != null)
            {
                sb.AppendLine($"Packet dump for {packet.Identifier}:");
                foreach (var attribute in packet.Attributes)
                {
                    if (attribute.Key == "User-Password")
                    {
                        sb.AppendLine($"{attribute.Key} length : {attribute.Value.First().ToString().Length}");
                    }
                    else
                    {
                        attribute.Value.ForEach(o => sb.AppendLine($"{attribute.Key} : {o} [{o.GetType()}]"));
                    }
                }
            }
            return sb.ToString();
        }
    }
}