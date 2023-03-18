﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using static CloudSync.Util;

namespace CloudSync
{
    public class RoleManager
    {
        public RoleManager(Sync sync)
        {
            Sync = sync;
            LoadAll();
        }

        private readonly Sync Sync;
        public readonly Dictionary<ulong, Client> Clients = new Dictionary<ulong, Client>();
        public readonly Dictionary<ulong, Client> TmpClients = new Dictionary<ulong, Client>();
        public List<Client> ClientsConnected()
        {
            var clients = new List<Client>();
            foreach (var client in Clients.Values)
            {
                if (client.IsConnected)
                    clients.Add(client);
            }
            ; return clients;
        }

        /// <summary>
        /// The server initiate an authentication request for new client and send it (Function callable only by the server)
        /// </summary>
        /// <param name="clientPubKey">The publicKey/ID of the client, which is used to authenticate the client-side request</param>
        /// <param name="sendRequestOfValidationToClient">The action to send the validation request to the client</param>
        /// <param name="host">Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes</param>
        /// <param name="userAgent">Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes</param>
        public void LoginRequest(Action<Client, byte[]> sendRequestOfValidationToClient, byte[] clientPubKey = null, ulong? id = null, string host = null, string userAgent = null, int? chunkSizeSetting = null, short thumnailSize = 0)
        {
#if DEBUG
            if (!Sync.IsServer)
                Debugger.Break();
#endif 
            if (clientPubKey != null && id == null)
                id = PublicKeyToUserId(clientPubKey);

            var pins = GetPins(Sync.Context);
            if (pins == null || pins.Count == 0)
                return;
            var randomBitesForAuthenticationProof = new byte[32];
            new Random().NextBytes(randomBitesForAuthenticationProof);
            var authenticationProof = CryptographicProofOfPinKnowledge(randomBitesForAuthenticationProof, pins);
            if (TryToGetCient((ulong)id, out var client, out var isTemp))
            {
                if (!isTemp)
                {
                    client.AddNewAccess(host, userAgent);
                }
                client.SetAuthenticationProof(authenticationProof);
            }
            else
            {
                if (clientPubKey != null)
                {
                    var generateAesKey = (userAgent != null && userAgent.Contains("Mozilla/")); // If it is a browser then it communicates encrypted with the generated AES keys, while for reacr applications it uses xorAB encryption using the key generated by the client
                                                                                                // =====================
                                                                                                // generateAesKey = false;
                                                                                                // =====================
                    client = new Client(Sync, clientPubKey, authenticationProof, host, userAgent, generateAesKey);
                }
                else
                    client = new Client(Sync, (ulong)id, authenticationProof, host, userAgent);
            }
            client.ChunkSize = chunkSizeSetting == 0 ? null : chunkSizeSetting;
            client.ThumbanailSize = thumnailSize;
            sendRequestOfValidationToClient(client, randomBitesForAuthenticationProof);
        }

        internal static ProofOfPin CryptographicProofOfPinKnowledge(byte[] randomBitesForAuthenticationProof, IEnumerable<OneTimeAccess> pins)
        {
            return new ProofOfPin()
            {
                RandomBitesForAuthenticationProof = randomBitesForAuthenticationProof,
                Pins = pins
            };
        }

        public class ProofOfPin
        {
            internal byte[] RandomBitesForAuthenticationProof;
            internal IEnumerable<OneTimeAccess> Pins;
            public bool Validate(uint ProofOfPinKnowledge, out string pin, out string label)
            {
                foreach (var p in Pins)
                {
                    var Proof = CryptographicProofOfPinKnowledge(RandomBitesForAuthenticationProof, p.Pin);
                    if (Proof == ProofOfPinKnowledge)
                    {
                        pin = p.Pin;
                        label = p.Label;
                        return true;
                    }
                }
                pin = null;
                label = null;
                return false;
            }
        }

        internal static uint CryptographicProofOfPinKnowledge(byte[] randomBitesForAuthenticationProof, string pin)
        {
            var baseHash = randomBitesForAuthenticationProof.Combine(BitConverter.GetBytes(int.Parse(pin)));
            var hash = Hash256(baseHash);
            return BitConverter.ToUInt32(hash, 0);
        }

        internal static ulong PublicKeyToUserId(byte[] publicKey)
        {
            var clientId = Hash256(publicKey).Take(8);
            return BitConverter.ToUInt64(clientId, 0);
        }

        public bool TryToGetCient(ulong id, out Client client, out bool isTemp)
        {
            if (TmpClients.TryGetValue(id, out client))
            {
                client.LastInteraction = DateTime.UtcNow;
                isTemp = true;
                return true;
            }
            if (Clients.TryGetValue(id, out client))
            {
                client.LastInteraction = DateTime.UtcNow;
                isTemp = false;
                return true;
            }
            client = null;
            isTemp = false;
            return false;
        }

        public void LoadAll()
        {
            var objs = Sync.Context.SecureStorage.ObjectStorage.GetAllObjects(typeof(Client));
            foreach (var obj in objs)
            {
                var client = obj as Client;
                client.Sync = Sync;
                Clients[client.Id] = client;
            }
        }


    }
}
