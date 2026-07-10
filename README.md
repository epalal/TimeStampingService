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



## Piano operativo 
Ottima scelta. Lavorare a questo livello ti darà una comprensione profonda di come i byte diventano protocolli sicuri, permettendoti di sostenere una discussione tecnica molto solida con il tuo professore, equivalente (se non superiore) a quella che avresti avuto usando OpenSSL in C.

Ecco il piano d'azione dettagliato e ristrutturato per implementare l'intero stack crittografico "da zero" utilizzando i socket raw e le primitive `hazmat` di Python.

### Architettura di Rete e Crittografia

| Componente | Implementazione Basso Livello (Python) |
| --- | --- |
| **Livello di Trasporto** | Socket TCP (`socket.AF_INET`, `socket.SOCK_STREAM`) |
| **Serializzazione Messaggi** | Modulo standard `struct` (`struct.pack`, `struct.unpack`) |
| **Scambio Chiavi (PFS)** | ECDHE (Curve Ellittiche, es. `SECP384R1`) |
| **Derivazione Chiave Sessione** | HKDF-SHA256 |
| **Cifratura Simmetrica** | AES-256-CBC con Padding manuale PKCS7 |
| **Integrità e Non-malleabilità** | HMAC-SHA256 (Paradigma Encrypt-then-MAC) |
| **Firme Digitali Server e TSS** | RSA con schema di padding PSS |

---

### Fase 1: Setup e Strutture Dati di Rete

* Inizializza i file `server.py` e `client.py` creando le connessioni tramite socket TCP nudi e crudi.
* Definisci il protocollo binario usando il modulo `struct`, stabilendo un header fisso (ad esempio 5 byte totali: 1 byte per definire il tipo di messaggio e 4 byte per la lunghezza del payload).
* Genera e salva in formato PEM le due coppie di chiavi asimmetriche a lungo termine per il server: $pubK_c$ e $privK_c$ per l'autenticazione del canale, $pubK_{ts}$ e $privK_{ts}$ per firmare i timestamp.
* Inizializza il database utenti lato server contenente per ogni utente le credenziali (hashate) e i contatori di bilancio $n_c$ (consumati) e $n_r$ (rimanenti).

### Fase 2: Handshake e Perfect Forward Secrecy (PFS)

* Genera le chiavi effimere per la sessione corrente sia lato client che lato server: $privK_{eff}$ e $pubK_{eff}$ utilizzando l'algoritmo ECDH.
* Firma la chiave pubblica effimera del server $pubK_{eff}$ utilizzando la chiave privata a lungo termine $privK_c$ tramite lo schema RSA-PSS, garantendo così l'autenticazione del server.
* Invia la chiave pubblica effimera firmata al client tramite socket; il client verificherà la firma utilizzando la chiave pubblica nota $pubK_c$.
* Calcola il segreto condiviso su entrambi i nodi sfruttando la matematica delle curve ellittiche: $S = ECDH(privK_{eff}, pubK_{peer\_eff})$.
* Deriva due chiavi simmetriche distinte a 256 bit elaborando il segreto condiviso $S$ attraverso l'algoritmo HKDF: $K_{enc}$ per l'algoritmo AES e $K_{mac}$ per l'algoritmo HMAC.

### Fase 3: Il Canale Sicuro (Cifratura, Integrità e No-Replay)

* Applica il padding PKCS7 ai dati in chiaro per far sì che la loro lunghezza sia un multiplo esatto di 16 byte (dimensione del blocco AES).
* Genera un Vettore di Inizializzazione (IV) casuale per ogni nuovo messaggio inviato.
* Cifra i dati "paddati" utilizzando l'algoritmo AES-CBC inizializzato con la chiave $K_{enc}$ e l'IV.
* Calcola il codice di autenticazione del messaggio (MAC) applicando HMAC-SHA256 alla concatenazione dell'IV e del testo cifrato: $T = HMAC(K_{mac}, IV \parallel C)$.
* Concatena IV, testo cifrato $C$ e tag $T$ per l'invio sul socket, implementando rigorosamente il paradigma Encrypt-then-MAC per prevenire attacchi di malleabilità.
* Integra un Sequence Number progressivo all'interno del payload prima di cifrarlo per rilevare e scartare matematicamente i tentativi di attacco replay.

### Fase 4: Autenticazione Utente

* Impacchetta le credenziali dell'utente (username e password) nel formato binario concordato e inviale attraverso il canale AES-CBC+HMAC appena stabilito.
* Verifica lato server la validità della password confrontandola con l'hash memorizzato nel database tramite una funzione di derivazione sicura (come PBKDF2).
* Marca logicamente il thread o l'istanza del socket lato server come "autenticato" per quello specifico utente, abilitando l'accesso ai servizi TSS.

### Fase 5: Operazioni del Servizio (Balance e Timestamp)

* Elabora la richiesta `Balance()` andando a leggere il database e restituendo al client, sempre sul canale cifrato, i valori interi $(n_c, n_r)$.
* Ricevi la richiesta `Timestamp(Hash)` e verifica immediatamente che il contatore dei crediti residui rispetti la condizione $n_r > 0$.
* Genera il tempo di sistema attuale convertendolo in un formato binario standard (come il timestamp Unix a 64 bit).
* Costruisci il bundle di dati crittografici concatenando strettamente l'hash inviato dal client con il tempo generato: $Bundle = Hash \parallel Time$.
* Firma crittograficamente il bundle utilizzando la chiave privata dedicata al servizio: $\sigma = Sign(privK_{ts}, Bundle)$.
* Aggiorna lo stato del database incrementando i consumati ($n_c = n_c + 1$) e decrementando i residui ($n_r = n_r - 1$).
* Impacchetta e restituisci al client il token finale nel formato $<Hash, Time, \sigma>$.

### Fase 6: Deliverables e Documentazione Finale

* Disegna i Sequence Diagram (utilizzando strumenti come PlantUML) per modellare visivamente lo scambio dei pacchetti binari del tuo Handshake personalizzato.
* Documenta nel report il formato esatto di ogni messaggio scambiato, specificando le dimensioni in byte di ogni campo definito nel tuo protocollo `struct`.
* Registra uno script di Demo che mostri il flusso completo e con successo della richiesta di un timestamp.
* Registra uno script di Demo per il fallimento intenzionale, causato dall'esaurimento del volume di timestamp acquistati.
* Crea uno script di verifica indipendente che accetti in input il token generato e dimostri matematicamente la validità della firma $\sigma$ utilizzando esclusivamente $pubK_{ts}$.
