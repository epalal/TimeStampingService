# TimeStampingService
Foundation of Cybersecurity/Advanced Cryptography project

FoC Project 2025-26 Timestamping Service:
A timestamping service (TSS) is a trusted third-party service that provides a legally valid, cryptographically signed record proving that specific electronic data (documents, code, logs) existed at a precise date and time.
Users send a hash of the data (not the actual data) to the Time Stamping Authority (TSA), which returns a signed token binding the time to that hash.
Users typically purchase a specific volume of timestamps, often sold as a package or a subscription. Upon purchase, the service provider will supply service details, which may include a username and password.
Assume that a user has already registered and paid the fee. Upon registration, the user received a username and a password binding their identity to a valid account. The user also received the volume of timestamps they may request. The user now can authenticate
to the service and request protected timestamping operations:
- <hash, time, signature> ß Timestamp(hash), with signature the digital signature by the service on the bundle (hash || time). The operation fails if the user has exhausted their timestamp volume.
- (nc, nr) ß Balance() which returns the number of timestamps the user has already consumed and the number of timestamps the user can still request.

The timestamp service is equipped with two pairs of public-private keys:
- the (pubKc,privKc) pair which is used to establish a secure connection with the service;
- the (pubKts, privKts) pair which is used to digitally sign the timestamp.

Users interact with the TSS through a secure channel that must be established before issuing operations.
The secure channel must fulfil perfect forward secrecy (PFS), integrity, no-replay and non-malleability. A user authenticates the service by means of the service’s public key (pubKc). A user authenticates to the service by means of its
credentials, namely (username, password).
Deliverables:
- A report that describes:
  i) specifications and design;
  ii) format of all the exchangedmessages;
  iii) sequence Diagrams of every used communication protocol.
- A demo which shows:
  i) a successful timestamping;
  ii) an unsuccessfully timestamping;
  iii) a verification of a timestamp.

