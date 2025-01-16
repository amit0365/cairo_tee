TEE Remote Attestation Verification in Cairo (Porting [Automata's DCAP Rust implementation](https://github.com/automata-network/dcap-rs) to Cairo) - Idea credit and helpful resources from Tarrence from Cartridge.

## Short Introduction to TEE's and Remote Attestations (WIP)

### WHY Remote Attestation?
A Trusted Execution Environment (TEE) is an environment where the code executed and the data accessed are isolated and protected in terms of confidentiality (no one has access to the data except the code running inside the TEE) and integrity (no one can change the code and its behavior). Intel Software Guard Extensions (SGX) and Trusted Domain (TDX) are two different types of Trusted Execution environments. They have an attestation and sealing capability that can be used to remotely provision (deliver) secrets and secure secrets to an enclave. 

These trusted execution environment are composed of different enclaves. These enclaves are created without secrets. Secrets can be delivered after the enclave has been instantiated and verified on the platform. Intel provides a remote attestation as a way to prove the integrity of the SGX application execution on the cloud. In other words, it ensures the user that the application is running on an authentic trusted SGX hardware, running the correct code and processing the sensitive data securely.

Use cases:
- Store secret keys for a user's wallet which is used by an Agent.
- Storing and processing of sensitive data, such as financial & health institutes or communication privacy (like Signal)
- In blockchain and cryptocurrency, e.g., keeping the bidding auction safe from tampering as well as not leaking sensitive information which can prevent frontrunning.
- Also, it could potentially help improve consensus protocols (e.g. BFT protocols SplitBFT, Hybster) since trusted hardware might potentially decrease some intermediary steps or nodes that were introduced for security reasons.(You can ask yourself the question do we need relay nodes if builders and proposers are both running in TEEs ? maybe not ?) Check out these by Flashbots [blog](https://writings.flashbots.net/geth-inside-sgx) and [blog](https://writings.flashbots.net/block-building-inside-sgx) for more information.


### DIFF Between SGX and TDX?

#### Intel® SGX (Software Guard Extensions)

- Process-level or application-level isolation (enclaves).
- Typically uses frameworks like Gramine (formerly Graphene), SCONE, Occlum, etc. to port standard applications into an enclave. This includes singing a hash of the binary. The developer provides a manifest file which contains the files and dependencies to be mounted into the enclave[1]. The network calls are executed outside the enclave, but the encrypted data is returned and decrypted inside the enclave.

reference: [Gramine](https://github.com/gramineproject/gramine/blob/master/CI-Examples/redis/redis-server.manifest.template)

#### Intel® TDX (Trust Domain Extensions)

- VM-level isolation (called Trust Domains, or “TDs”).
- An entire guest OS runs inside a TD, protected from the untrusted hypervisor.
- You usually run unmodified applications inside the protected VM.
- Remote attestation and secret provisioning happen at the VM (TD) boundary.
- Key difference: TDX isolates the entire VM from the host/hypervisor, whereas SGX enclaves isolate a specific process (or portion of a process) from the untrusted OS.


### What's Inside a TEE?

TEE's are made up of Architectural Enclaves (AEs) which are a set of “system” enclaves concerned with starting and attesting other enclaves.

#### Quoting Enclave (QE)
The Quoting Enclave receives an SGX Report and produces a corresponding SGX Quote. The identity of the Quoting Enclave is publicly known (its signer, its measurement and its attributes) and is signed by Intel.

#### Provisioning Enclave (PE) for EPID attestation
The Provisioning Enclave is used in EPID based remote attestation. This enclave communicates with the Intel Provisioning Service (IPS) to perform EPID provisioning. The result of this provisioning procedure is the private EPID key securely accessed by the Provisioning Enclave. This procedure happens only during the first deployment of the SGX machine (or, in rare cases, to provision a new EPID key after TCB upgrade). The main user of the Provisioning Enclave is the Quoting Enclave.

#### Provisioning Certification Enclave (PCE) for DCAP attestation
The Provisioning Certification Enclave is used in DCAP based remote attestation. This enclave communicates with the Intel Provisioning Certification Service (PCS) to perform DCAP provisioning. The result of this provisioning procedure is the DCAP/ECDSA attestation collateral (mainly the X.509 certificate chains rooted in a well-known Intel certificate and Certificate Revocation Lists). This procedure happens during the first deployment of the SGX machine and then periodically to refresh the cached attestation collateral. Typically, to reduce the dependency on PCS, an on-chain provider introduces an intermediate caching service (Provisioning Certification Caching Service, or PCCS) that stores all the attestation collateral obtained from Intel. The main user of the Provisioning Certification Enclave is the Quoting Enclave.


### Workflow of Remote Attestations

There are two types of remote attestations, Enhanced Privacy Identifier (EPID) and Data Center Attestation Primitives (DCAP). The former relies on Intel’s infrastructure for launching enclaves, while the latter came to support the deployment of enclaves without relying on Intel’s infrastructure. 

Note Intel EPID remote attestation has been deprecated and will be offline in early 2025. Note that DCAP currenlty uses ECDSA which will be deprecated by 2030 by NIST and will likely be replaced by a lattice hash-based signatures which are Post Quantum secure. Currently, only ECDSA ON secp-256 curve is supported.

#### EPID Attestation:

To provision secrets to an enclave, Alice wants to start a secure communication channel with the SGX App and requests remote attestation first to verify its integrity. 

1) Where are the messages decrypted inside the SGX enclave?

The SGX app creates an SGX report that includes metadata, such as the enclave measurement (MRENCLAVE), and sends it to the quoting enclave to generate an attested SGX quote. 

The quoting enclave uses the EPID key that was provisioned to it at the initial deployment of the SGX machine by Intel Provisioning Service (PCS). Afterwards, the signed quote is sent back to Alice which she forwards to Intel’s Attestation Service (IAS) for verification. Based on the returned result, Alice could decide to proceed and initiate a secure communication channel with the SGX app.

To verify EPID attestation:

1) The root public key from Intel is hardcoded (but can be independently found from many other places, i.e. gramine source code, web archive snapshot)
2) The attestation is parsed into a report and signature from abi encoded bytes.
3) The signature is verified against the root public key, as a signature over the report data.
4) The MRENCLAVE value from the report, which is a hash over the enclave program, is matched to a reference we pass in
5) The “userReportData”, which is set by the enclave when running, is also matched against a reference.

#### DCAP Attestation:

DCAP processes are similar at the start but instead of using EPID key to sign the attestation, it uses Public Key Infrastructure (PKI) and X.509 certificate chains instead. In essence, upon first deployment of the SGX machine, the Provisioning Certificate Enclave (PCE) fetches the attestation certificates and revocation list from another service, Intel Provisioning Certification Service. The quoting enclave would be talking with the PCE instead. Alice doesn’t need to consult the IAS anymore but rather she periodically fetches the DCAP certificates and revocation lists and caches them locally. Subsequently, when she receives the quote, she can compare the embedded certificates with the ones she cached and verify directly.


## Acknowledgements:
https://collective.flashbots.net/t/flashwares-i-tees-feat-intel-sgx/3405
https://collective.flashbots.net/t/demystifying-remote-attestation-by-taking-it-on-chain/2629
https://gramine.readthedocs.io/en/stable/sgx-intro.html
