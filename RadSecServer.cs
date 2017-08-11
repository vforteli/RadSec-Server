using Flexinets.Radius.Core;
using log4net;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Radius
{
    public class RadSecServer
    {
        private static readonly ILog _log = LogManager.GetLogger(typeof(RadSecServer));
        private readonly TcpListener _server;
        private readonly RadiusDictionary _dictionary;
        private readonly Dictionary<IPAddress, (IPacketHandler packetHandler, String secret)> _packetHandlers = new Dictionary<IPAddress, (IPacketHandler, String)>();


        /// <summary>
        /// Create a new server on endpoint
        /// </summary>
        /// <param name="localEndpoint"></param>
        /// <param name="dictionary"></param>
        /// <param name="serverType"></param>
        public RadSecServer(IPEndPoint localEndpoint, RadiusDictionary dictionary)
        {
            _server = new TcpListener(localEndpoint);
            _dictionary = dictionary;
        }


        /// <summary>
        /// Add packet handler for remote endpoint
        /// </summary>
        /// <param name="remoteAddress"></param>
        /// <param name="sharedSecret"></param>
        /// <param name="packetHandler"></param>
        public void AddPacketHandler(IPAddress remoteAddress, String sharedSecret, IPacketHandler packetHandler)
        {
            _log.Info($"Adding packet handler of type {packetHandler.GetType()} for remote IP");
            _packetHandlers.Add(remoteAddress, (packetHandler, sharedSecret));
        }


        /// <summary>
        /// Add packet handler for multiple remote endpoints
        /// </summary>
        /// <param name="remoteAddresses"></param>
        /// <param name="sharedSecret"></param>
        /// <param name="packetHandler"></param>
        public void AddPacketHandler(List<IPAddress> remoteAddresses, String sharedSecret, IPacketHandler packetHandler)
        {
            foreach (var address in remoteAddresses)
            {
                _packetHandlers.Add(address, (packetHandler, sharedSecret));
            }
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

                // todo figure out of this is a known client
                // todo add tls and certificate authentication...
                if (_packetHandlers.TryGetValue(IPAddress.Parse("127.0.0.1"), out var handler))
                {
                    _log.Debug($"Handling client with {handler.packetHandler.GetType()}");

                    var stream = client.GetStream();
                    while (RadiusPacket.TryParsePacketFromStream(stream, out var requestPacket, _dictionary, Encoding.UTF8.GetBytes(handler.secret)))
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
                        stream.Write(responsePacketBytes, 0, responsePacketBytes.Length);
                    }

                    _log.Debug($"Connection closed to {client.Client.RemoteEndPoint}");
                }
                else
                {
                    _log.Error($"No packet handler found for remote endpoint {client.Client.RemoteEndPoint}");
                }
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