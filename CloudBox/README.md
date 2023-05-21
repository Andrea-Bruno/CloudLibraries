# CloudBox

Multi-purpose multi-platform library to create both server and client cloud systems on the fly, this library allows you to virtualize a cloud system on the fly.
This library has been created to provide all the functions of both client and server cloud storage, both for small embedded systems and for large infrastructures: The possibility of being able to mount cloud units on the fly (hot create and destroy) allows you to create powerful infrastructures cloud as well as simple cloud si minilali systems.
The prerogative of this library is that it is a symmetric library for server and client, i.e. this library is valid for both server and client cloud functions, as the platform was designed to be symmetric, i.e., the same code allows to create instances of cloud client and cloud server, giving rise to great flexibility as, for example, machines that using this library can act as both clients and servers with little intervention on the part of the developer.
CloudBox through the underlying CloudSync library implements a low-level data synchronization system between client and server which saves on transmitted data, as the packets are minimalistic, it is a purely binary protocol which does not add anything to the bare essentials for transmission and data synchronization, which does not happen, for example, for protocols that encapsulate data in json or xml structures.
The underlying encrypted messaging libraries add to this library an extreme security based on symmetric key protocols deriving from bitcoin technology and from bitcoin derive all the concepts in terms of security and trustless: Both client and server machines, when instantiated, do not require any user account, therefore there is no place where user databases and authentication data are kept, the client and the server are instantiated with exactly the same system used for bitcoin wallets (and to do this we use the same technology), i.e. at when the instance is created, a passphrase is randomly generated which allows account recovery, and which acts as a generator for the cryptographic keys (public and private), the private cryptographic key will never leave the device while the public one is used by the client for be able to access the server with a PIN. In this type of technology, the private key as generated also represents a sort of inviolable digital identity, which also has a digital signature to authenticate documents and data packets, in fact, during the synchronization procedure, the data, in addition to being encrypted, sees the addition of the digital signature to ensure maximum certainty on the origin.
This type of technology is known and appreciated by users of cryptocurrency cold wallets such as Ledger and Trezor, who are considered among the most secure IT solutions for storing digital coins: Since the violation of digital wallets represents a great reward for hackers who succeeded, and therefore it is reasonable to believe that this is the best technology to secure the data.
In practice, the server generates a QR code that represents its public key which allows a client to establish a cryptographic connection with the server and communicate with it in a secure manner.
To ensure that the private key can never leave the device, we have developed a special library (SecureStorage), which uses the best possible technologies to prevent private data from being accessible, including the hardware components present in modern devices to save key-data pairs.
The communication protocols implemented by the cloud through this library are two, a binary socket that represents the best possible technology in terms of performance, and one derived from the Rest API technology, to which we have added an encryption level that would not be present in standard technologies which relies on https requests to secure data, a bad solution because it allows the machine receiving the https requests to see the data in clear text, risking the security of everything that passes through: Https protects the point-to-point traffic on the internet but not inside the machine that receives the data or sends them through, having added an encryption layer we are going to create a protected tunnel that is not simply from machine to machine, but from client application to server application and vice versa, none of everything in the middle can intercept in plain text what passes through.
The main functions provided by the library are:
      
+ Instantiate cloud clients and servers on the fly.
          
+ Establish connection between client and server using a software router as a hub.
          
+ Provide real-time data on synchronization status, data transmission and network problems.
          
+ Automatically manage synchronization by means of a specific underlying library.
          
+ Administrative functions of instanced clouds (server and client).
          
+ Create sub clouds for internal areas.
          
+ Digital signature functions on documents using the private key that represents the digital ID of the instance.
      
Notes: This library, to work as a server, needs the CloudServer library which adds small aspects that are not necessary in the client for obvious reasons, such as for example the generation of thumbnails, the exposure of encrypted APIs and the management of a proxy to directly expose the machine to internet while using the API.