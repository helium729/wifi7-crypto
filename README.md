# **Cryptography in IEEE 802.11be (Wi-Fi 7\) Security Architecture**

## **1\. Introduction: The Paradigm Shift in Wireless Trust**

The introduction of the IEEE 802.11be amendment, commercially designated as Wi-Fi 7, marks a watershed moment in the history of wireless local area network (WLAN) security. While previous generations of the protocol focused primarily on throughput enhancements—pushing the envelope of Quadrature Amplitude Modulation (QAM) and channel bonding—Wi-Fi 7 arrives at a juncture where the physical layer and the security layer are inextricably linked. The expansion into the 6 GHz spectrum, a pristine frequency band free from the legacy interference of microwave ovens and cordless phones, has allowed the Wi-Fi Alliance and IEEE standards bodies to implement a "scorched earth" policy regarding security debt. Unlike the 2.4 GHz and 5 GHz bands, where backward compatibility often shackled administrators to vulnerable protocols like WPA2-Personal, the 6 GHz band mandates the use of WPA3 (Wi-Fi Protected Access 3\) and Protected Management Frames (PMF) as a baseline requirement for operation.[1]

This report provides an exhaustive, expert-level analysis of the cryptographic underpinnings of Wi-Fi 7\. It explores the mechanisms of identity verification through Simultaneous Authentication of Equals (SAE), dissects the mathematical rigor of the Hash-to-Element (H2E) algorithm designed to mitigate side-channel attacks, and details the complex key management hierarchies necessitated by Multi-Link Operation (MLO). Furthermore, it examines the transition from AES-CCMP to the higher-throughput AES-GCMP-256 for data confidentiality and the mandatory enforcement of 802.11w Protected Management Frames to secure the control plane against denial-of-service attacks.

### **1.1 The Security Landscape Pre-Wi-Fi 7**

To appreciate the architectural decisions within Wi-Fi 7, one must understand the deficiencies it aims to correct. For over a decade, WPA2-Personal (based on IEEE 802.11i) served as the global standard. It relied on a 4-way handshake that derived encryption keys directly from a Pre-Shared Key (PSK) and the SSID. This design contained a critical cryptographic flaw: the lack of forward secrecy and susceptibility to offline dictionary attacks. An attacker capturing the handshake could attempt to brute-force the password offline at millions of guesses per second without ever interacting with the target network again. Furthermore, the "KRACK" (Key Reinstallation Attack) vulnerability exposed inherent weaknesses in the state machine of the handshake itself.[3]

Wi-Fi 7 addresses these systemic risks by integrating WPA3 as a mandatory component. WPA3 fundamentally alters the "Identity Verification" phase. It replaces the simple PSK exchange with a zero-knowledge proof known as the Dragonfly Key Exchange (SAE). This protocol allows parties to prove knowledge of the password without ever transmitting a hash of it that could be cracked offline, and importantly, it establishes a shared secret that is mathematically independent of the password's quality, ensuring forward secrecy.[4]

### **1.2 The Multi-Link Operation (MLO) Complexity**

The most significant architectural shift in Wi-Fi 7 is MLO, which allows a client (Non-AP MLD) to maintain simultaneous physical layer connections across multiple bands (e.g., 5 GHz and 6 GHz) with a single Access Point (AP MLD). This creates a unique security challenge: managing a unified security association (identity) while handling disparate encryption contexts for broadcast traffic on different physical mediums. The report will detail how Wi-Fi 7 resolves this by decoupling the Pairwise Master Key (PMK) from the physical link, anchoring it instead to the MLD MAC address, while maintaining link-specific keys for multicast integrity.[6]

## **2\. Identity Verification: The Mechanics of Trust**

In the context of Wi-Fi 7, "verifying identity" is no longer a matter of simply checking if a user knows a password. It is a cryptographic assertion of possession of a shared secret, executed through a protocol that reveals nothing about the secret itself. This section analyzes the Simultaneous Authentication of Equals (SAE) protocol, the mandatory authentication method for Wi-Fi 7 Personal networks.

### **2.1 Simultaneous Authentication of Equals (SAE)**

SAE is an implementation of the Dragonfly Key Exchange, defined in IETF RFC 7664\. Unlike WPA2-PSK, where the Pre-Shared Key (PSK) was used directly to seed the encryption keys, SAE uses the password only as a seed to negotiate a fresh, high-entropy Pairwise Master Key (PMK) for every session.[4]

#### **2.1.1 Mathematical Primitives: ECC vs. FFC**

The Dragonfly handshake can operate over Finite Field Cryptography (FFC) or Elliptic Curve Cryptography (ECC). Wi-Fi 7 implementations overwhelmingly favor ECC due to its efficiency—offering equivalent security strength with significantly smaller key sizes. The standard typically utilizes NIST curves such as P-256 (for standard security) or P-384 (for 192-bit security mode).[9]

In ECC, the security relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP). The system operates on the algebraic structure of elliptic curves over finite fields. The curve equation is typically defined as:

$$y^2 \= x^3 \+ ax \+ b \\pmod p$$

where $p$ is a large prime number. The core operation is scalar multiplication, where a point $P$ on the curve is "multiplied" by an integer (scalar) $k$ to produce another point $Q \= k \\cdot P$. While calculating $Q$ is computationally trivial, determining $k$ given $P$ and $Q$ is computationally infeasible.[11]

### **2.2 The Password Element (PWE) Derivation**

The first step in the SAE handshake is converting the user's ASCII password into a cryptographic element, the Password Element (PWE), which must be a valid point on the chosen elliptic curve. This conversion process has been the subject of intense scrutiny and evolution, leading to the mandatory adoption of the Hash-to-Element (H2E) method in Wi-Fi 7\.

#### **2.2.1 The Legacy "Hunting and Pecking" Vulnerability**

Initial WPA3 implementations used a "Hunting and Pecking" algorithm. The device would append a counter to the password, hash it, and check if the resulting value corresponded to a valid x-coordinate on the curve.

1. $$Hash(Password | Counter | MACs) \\rightarrow x$$  
2. Check if $x^3 \+ ax \+ b$ is a quadratic residue modulo $p$.  
3. If yes, calculate $y$. If no, increment $Counter$ and repeat.

**The Flaw:** This probabilistic loop introduced a timing side-channel. A password that resulted in a valid point on the first try would generate a response faster than a password that required ten iterations. Attackers could measure these minute timing differences (the "Dragonblood" attack) to partition the password space and accelerate dictionary attacks.[12]

#### **2.2.2 The Wi-Fi 7 Mandate: Hash-to-Element (H2E)**

To eliminate this vulnerability, Wi-Fi 7 (and WPA3 in the 6 GHz band generally) mandates the **Hash-to-Element (H2E)** mechanism described in RFC 9380 and RFC 9383\.14 H2E employs a deterministic "map\_to\_curve" function that operates in constant time.

**The H2E Algorithm Flow:**

1. **Blind Mask Generation:** A random seed is not used; instead, the password and specific context data are passed through a hash function (e.g., SHA-256) to generate a uniform string.  
2. **Field Element Mapping:** The hash output is mapped to an element $u$ in the finite field $F\_q$.  
3. **Curve Mapping:** A deterministic function (such as the Simplified Shallue-van de Woestijne-Ulas (SSWU) method) maps the field element $u$ to a point $P$ on the elliptic curve.[16]
   $$PWE \= map\\\_to\\\_curve(Hash(Password, SSID, ID))$$

Because this mathematical mapping involves a fixed sequence of operations with no conditional loops dependent on the input data, the execution time is constant. This renders timing analysis useless, securing the derivation process against side-channel attacks.[18]

### **2.3 The Commit Exchange: Creating the Shared Secret**

Once the PWE is derived, the router (Authenticator) and user (Supplicant) engage in the **Commit Exchange**. This phase is a variant of the Diffie-Hellman exchange but, crucially, it uses the derived PWE as the base rather than the standard generator point of the curve group. This ensures that the resulting shared key can only be computed by someone who derived the correct PWE (i.e., knows the password).

**Step-by-Step Commit Flow:**

1. **Randomness:** The client generates two random secret scalars: private ($r$) and mask ($m$).  
2. Scalar Calculation: The client computes a scalar value to send:

   $$scalar \= (r \+ m) \\pmod q$$

   where $q$ is the order of the curve group.[19]
3. Element Calculation: The client computes a Finite Field Element (point) to send. This effectively "masks" the PWE:

   $$Element \= \-m \\cdot PWE$$

   (Note: This is the inverse of the mask multiplied by the PWE point).[20]
4. **Transmission:** The client constructs an SAE Commit frame containing:  
   * **Group ID:** (e.g., 19 for NIST P-256).  
   * **Scalar:** The calculated $scalar$.  
   * **Finite Field Element:** The coordinates of the $Element$ point.[21]
5. **Peer Processing:** The router receives this frame. It performs the exact same process to generate its own scalar and Element and sends them back.

The "Magic" of Zero Knowledge:  
Upon receiving the peer's values, each side calculates the Shared Secret ($K$).

* The client calculates: $K \= r\_{client} \\cdot (Element\_{peer} \+ scalar\_{peer} \\cdot PWE)$  
* Mathematically, this expands to:

  $$K \= r\_{client} \\cdot (-m\_{peer} \\cdot PWE \+ (r\_{peer} \+ m\_{peer}) \\cdot PWE) \\\\ K \= r\_{client} \\cdot (r\_{peer} \\cdot PWE) \\\\ K \= (r\_{client} \\cdot r\_{peer}) \\cdot PWE$$

  Since the Router performs the symmetrical calculation, both arrive at the exact same point $K$. An attacker observing the exchange sees only the scalar and Element values, which appear random because they are blinded by the random mask values. Without the mask or the private scalars, the shared secret $K$ cannot be derived.[22]

### **2.3.1 Security Analysis: Why the Password Cannot be Sniffed**

A frequent security concern is whether capturing the Commit Exchange frames over the air allows an attacker to extract the password. In legacy WPA2, the handshake transmitted a hash derived directly from the password, allowing offline brute-force attacks. In WPA3-SAE, however, the password is **never transmitted**—neither in plain text nor as a direct hash.

The security relies on the blinding properties of the Scalar and Element calculation. As detailed in the steps above, the values sent over the air are the result of operations involving the mask ($m$) and private ($r$) random numbers, which are generated freshly for each session and kept local to the device.[20]

An attacker who captures the air traffic possesses three variables:

1. The **Scalar** ($r \+ m$).  
2. The **Element** ($-m \\cdot PWE$).  
3. The **Curve Parameters** (public knowledge).

However, the attacker faces two critical unknowns: the random mask and the random private key. To reverse the math and isolate the **PWE** (and thus the password), the attacker would have to solve the Discrete Logarithm Problem, which is computationally infeasible.24 Because the mask effectively "locks" the PWE inside the Element point, and the mask itself is hidden inside the Scalar, the captured packets appear as statistically random noise to any observer who does not already know the password.12 This property, known as **Zero-Knowledge Proof**, ensures that passive sniffing yields no data that can be used to reverse-engineer the user's credentials.

### **2.4 The Confirm Exchange: Proof of Possession**

The Commit phase generates the key; the **Confirm Exchange** proves that both parties generated the *same* key. This prevents "active" attacks where an adversary might inject random values to desynchronize the state.

1. **Key Derivation (KDF):** Both parties derive a Key Confirmation Key (KCK) and a Pairwise Master Key (PMK) from the shared secret $K$ using a **Key Derivation Function (KDF)**.  
   * **Definition:** A KDF is a cryptographic algorithm that derives one or more secret keys from a secret value. In WPA3-SAE, this is typically an HMAC-based KDF (such as **HKDF**, defined in RFC 5869).  
   * **Purpose:** The raw Shared Secret ($K$) generated during the Commit phase is a point on a curve or a large integer. It is not suitable to be used directly as an encryption key because it may not be uniformly random or have the correct bit length. The KDF "smooths" this data to produce cryptographically strong keys.[4]
   * Operation:

     $$PMK \= KDF(K,...)$$  
     $$KCK \= KDF(K,...)$$  
2. HMAC Calculation: The client calculates a verification token using the derived KCK.

   $$Confirm \= HMAC(KCK, Send\\\_Scalar, Send\\\_Element, Recv\\\_Scalar, Recv\\\_Element)$$

   This HMAC covers the entire transcript of the Commit exchange.[22]
3. **Transmission:** The client sends an SAE Confirm frame. This frame contains a field Send-Confirm which acts as a sequence counter (set to 1 usually, then increments).  
4. **Verification:** The router computes the expected HMAC. If it matches the received value, the router knows the client possesses the correct KCK (and thus the correct password). The router then sends its own Confirm frame.  
5. **State Transition:** Upon successful verification, both parties transition their state machine to "Authenticated" and install the PMK into their key management module.[27]

## **3\. Key Hierarchy and Management in 802.11be**

With the PMK established via SAE, the system moves to the 4-Way Handshake to derive the keys used for actual encryption. Wi-Fi 7 introduces significant complexity here due to **Multi-Link Operation (MLO)**.

### **3.1 The MLD-Centric Security Association**

In legacy Wi-Fi, a device connecting to 2.4 GHz and 5 GHz would act as two separate entities with two separate security associations. In Wi-Fi 7, a Multi-Link Device (MLD) acts as a single logical entity.

The MLD MAC Address:  
Wi-Fi 7 drivers must handle multiple MAC addresses: the link-specific MACs (for the PHY radios) and the MLD MAC (for the logical management). Security keys are derived using the MLD MAC Address.

$$PTK \= KDF(PMK, ANonce, SNonce, AP\\\_MLD\\\_MAC, Client\\\_MLD\\\_MAC)$$

This design choice is critical. It implies that the Pairwise Temporal Key (PTK)—the key used to encrypt unicast traffic—is shared across all links. A packet transmitted on the 6 GHz link uses the same encryption key as a packet on the 5 GHz link. This facilitates seamless "Simultaneous Transmit and Receive" (STR) and rapid link switching without the need for re-handshaking or key rotation latency.[6]

### **3.2 The Link-Specific Group Keys**

While the PTK is global to the MLD, broadcast and multicast traffic is inherently bound to a specific physical medium. A broadcast frame sent on channel 36 (5 GHz) cannot be received by a radio listening on channel 1 (2.4 GHz). Therefore, Wi-Fi 7 mandates **Link-Specific Group Keys**.

| Key Type | Scope | Purpose |
| :---- | :---- | :---- |
| **PMK** (Pairwise Master Key) | MLD Global | Root of trust; derived from SAE/EAP. |
| **PTK** (Pairwise Temporal Key) | MLD Global | Encrypts unicast data/mgmt frames across all links. |
| **GTK** (Group Temporal Key) | **Per-Link** | Encrypts broadcast/multicast *data* frames on a specific link. |
| **IGTK** (Integrity GTK) | **Per-Link** | Protects broadcast *management* frames (PMF) on a specific link. |
| **BIGTK** (Beacon Integrity GTK) | **Per-Link** | Protects Beacon frames on a specific link. |

6

### **3.3 Enhanced 4-Way Handshake with MLO KDEs**

To distribute these multiple keys efficiently, Wi-Fi 7 enhances the standard 4-Way Handshake by leveraging the **Key Data Encapsulation (KDE)** mechanism. This allows the Access Point to provision the keys for *every* active radio link (e.g., 5GHz and 6GHz) within a single handshake execution.

**Step-by-Step Handshake Flow:**

1. **Message 1 (AP $\\to$ Client):**  
   * **Payload:** The AP sends a random nonce (**ANonce**) to the client.  
   * **Purpose:** This triggers the client to derive the Pairwise Temporal Key (PTK). The client combines the PMK (from SAE), the received ANonce, its own SNonce, and the **MLD MAC addresses** of both parties to calculate the PTK.[2]
2. **Message 2 (Client $\\to$ AP):**  
   * **Payload:** The client sends its own random nonce (**SNonce**) and the **RSN Information Element (RSN IE)** (confirming supported ciphers).  
   * **Security:** This message includes a **Message Integrity Code (MIC)** calculated using the KCK (part of the newly derived PTK). This proves to the AP that the client holds the PMK.[2]
3. **Message 3 (AP $\\to$ Client):** *Crucial MLO Step*  
   * **Payload:** The AP sends the **Group Temporal Keys (GTKs)**.  
   * **MLO Specifics:** Instead of sending a single GTK, the AP constructs separate **MLO KDEs** for every link:  
     * **MLO GTK KDE:** Contains the multicast data key for Link 1, Link 2, etc.  
     * **MLO IGTK KDE:** Contains the management integrity key for Link 1, Link 2, etc.  
     * **MLO BIGTK KDE:** Contains the beacon protection key for Link 1, Link 2, etc.  
   * **Security:** The entire payload is encrypted using the Key Encryption Key (KEK, part of the PTK) and authenticated with a MIC.[22]
4. **Message 4 (Client $\\to$ AP):**  
   * **Payload:** A simple acknowledgement.  
   * **Purpose:** Confirms that the keys have been successfully installed. Once this message is received, the "Control Port" opens, and encrypted data traffic begins flowing across all established links.[2]

This "batch distribution" capability allows an MLD to bring up multiple links instantly after a single handshake, significantly reducing the "time-to-connect" metric that is vital for user experience.

## **4\. WPA3-Enterprise 192-bit Mode: The High-Assurance Stack**

For enterprise deployments handling classified or highly sensitive data, standard WPA3 is insufficient. Wi-Fi 7 supports **WPA3-Enterprise 192-bit Mode**, a profile designed to align with the Commercial National Security Algorithm (CNSA) Suite.

### **4.1 Strict Cipher Suite Requirements**

Unlike the "Personal" modes or standard Enterprise modes which allow for cryptographic agility (negotiating down to weaker supported ciphers), 192-bit mode is prescriptive.

* **Authentication:** Must use **EAP-TLS**. Password-based tunneling methods like PEAP or EAP-TTLS are prohibited because they rely on MSCHAPv2 or other primitives that do not meet the 192-bit security strength.[33]
* **Key Exchange:** Must use ECDH over **NIST P-384** (secp384r1) or RSA with 3072-bit modulus or greater.  
* **Hashing:** All Key Derivation Functions (KDFs) must use **HMAC-SHA-384**. The use of SHA-256 is disallowed as it provides only 128 bits of collision resistance.  
* **Cipher Suites:** The only allowed pairwise ciphers are:  
  * TLS\_ECDHE\_ECDSA\_WITH\_AES\_256\_GCM\_SHA384  
  * TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384  
  * TLS\_DHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384.[35]

### **4.2 Certificate Management Implications**

The requirement for 192-bit security ripples back to the Public Key Infrastructure (PKI). A client cannot simply "turn on" this mode; they must possess a client certificate signed by a Certificate Authority (CA) that itself uses keys of sufficient strength (RSA $\\ge$ 3072 or P-384). If a user attempts to connect with a standard 2048-bit RSA certificate, the handshake will fail at the TLS layer before Wi-Fi keys are even derived.[33]

## **5\. Data Confidentiality: AES-GCMP-256**

Wi-Fi 7's headline feature is speed. With PHY rates exceeding 30 Gbps, the encryption engine becomes a potential bottleneck. The legacy AES-CCMP (Counter Mode with CBC-MAC) protocol is ill-suited for these speeds due to its serial nature.

### **5.1 The Move to Galois/Counter Mode Protocol (GCMP)**

Wi-Fi 7 mandates the use of GCMP-256 for WPA3-Enterprise 192-bit mode and strongly encourages it for all high-throughput links.

**GCMP Architecture:**

* **Encryption (CTR Mode):** AES is used in Counter Mode to generate a keystream. This is XORed with the plaintext. Since the counter values are predictable, the keystream blocks can be pre-calculated in parallel or pipelined efficiently in hardware.[37]
* **Integrity (GMAC):** Instead of the serial CBC-MAC used in CCMP, GCMP uses a Galois Field (GF) multiplier (GHASH) for the Message Integrity Code (MIC). GHASH operations are associative, meaning the integrity tag calculation can also be parallelized.

**Comparison of Throughput Efficiency:**

| Protocol | Encryption | Integrity | Parallelizable? | Key Size |
| :---- | :---- | :---- | :---- | :---- |
| **CCMP-128** | AES-CTR | AES-CBC-MAC | No (Integrity is serial) | 128-bit |
| **GCMP-256** | AES-CTR | GHASH (Galois) | **Yes** (Fully parallel) | 256-bit |

### **5.2 Replay Protection and Nonces**

To prevent replay attacks, where an adversary records a valid encrypted packet and re-transmits it later (e.g., to cause a denial of service or duplicate a transaction), GCMP utilizes a strict **Packet Number (PN)** sequence.

* The PN is a 48-bit counter incremented for every packet transmitted.  
* The PN is combined with the Transmitter Address (TA) to form the Nonce used in the AES-CTR encryption.

  $$Nonce \= PN \\parallel TA$$  
* **Receiver Logic:** The receiver maintains the last\_seen\_PN for every associated station. If a packet arrives with a received\_PN \<= last\_seen\_PN, the hardware decryptor discards it silently before passing it to the driver. This check happens at line-rate in the Wi-Fi chipset.[38]

## **6\. Management Plane Security: 802.11w (PMF) Deep Dive**

In early Wi-Fi standards, management frames (Deauthentication, Disassociation, Action frames) were completely unauthenticated. This allowed trivial Denial-of-Service (DoS) attacks: an attacker could simply spoof the AP's MAC address and broadcast a "Deauth" packet, disconnecting all users.

Wi-Fi 7 makes **Protected Management Frames (PMF)**, standardized as 802.11w, mandatory.

### **6.1 Unicast Management Protection**

For frames directed to a specific client (e.g., a request to measure radio noise), the protection is identical to data frames.

* The payload is encrypted using the PTK.  
* The header is authenticated.  
* An attacker without the PTK cannot forge these frames, nor can they read the contents.[39]

### **6.2 Broadcast Management Protection: BIP**

Frames sent to everyone (like Beacons or Channel Switch Announcements) cannot be encrypted with a unique PTK. Instead, they are protected using the **Broadcast Integrity Protocol (BIP)**.

**The Mechanism:**

1. **IGTK:** During the 4-way handshake, the client receives the **Integrity Group Temporal Key (IGTK)**.  
2. **MME Generation:** When the AP sends a broadcast management frame, it calculates a keyed hash (CMAC or GMAC) of the frame body using the IGTK.  
3. **Encapsulation:** This hash is appended to the frame as the **Management MIC Element (MME)**.[40]
4. **Verification:** The client computes the hash of the received frame using its copy of the IGTK. If it matches the MME, the frame is accepted.

New in Wi-Fi 7: BIP-GMAC-256  
While legacy PMF used AES-128-CMAC, Wi-Fi 7 introduces BIP-GMAC-256. This aligns the management frame protection strength with the data protection strength (GCMP-256). It ensures that the control plane is not the "weakest link" in the cryptographic chain.[37]

### **6.3 Beacon Protection and the IoT Battery Challenge**

A specific vulnerability in previous PMF implementations was that **Beacon frames** were often left unprotected because verifying a Message Integrity Code (MIC) on every beacon (transmitted every \~100ms) is computationally expensive. For battery-powered IoT devices, this constant cryptographic hashing would drain the battery rapidly.

Wi-Fi 7 addresses this through two complementary mechanisms:

1\. Beacon Integrity Group Temporal Key (BIGTK)  
Wi-Fi 7 mandates Beacon Protection using a dedicated key, the BIGTK. This prevents "Fake AP" attacks where an adversary spoofs a beacon to advertise false capabilities or force clients to switch to a noisy channel. The BIGTK is distributed in the same MLO KDE bundle during the 4-way handshake.[6]
2\. BSS Parameter Change Count (BPCC)  
To solve the battery drain issue, Wi-Fi 7 utilizes a "Critical Update" mechanism tracked by the BSS Parameter Change Count (BPCC).

* **Optimization:** The AP includes a counter (BPCC) in the unencrypted portion of the beacon (or Reduced Neighbor Report). This counter increments *only* when critical network parameters change (e.g., channel switch, new security settings).  
* **Client Logic:** A low-power client wakes up and checks the plaintext BPCC. If the counter matches the last known value, the client knows the secure content of the beacon has not changed. It can then **skip** the expensive MIC verification and immediately return to sleep. The client performs the cryptographic verification only when it sees an incremented BPCC.

### **6.4 SA Query: Defending Against Association Spoofing**

PMF also introduces the **SA (Security Association) Query** mechanism.

* *Attack:* An attacker spoofs an "Association Request" from an already connected client. The AP, thinking the client rebooted, tears down the existing secure connection.  
* *Defense:* With PMF, if the AP receives an Association Request from a connected client, it does *not* immediately tear down the link. Instead, it sends an **SA Query Request** to the client (encrypted with the existing PTK).  
  * If the "real" client is still there, it responds with an **SA Query Response** (encrypted). The AP ignores the fake Association Request.  
  * If the client does not respond, the AP assumes the client essentially did reboot (or crashed) and proceeds with the new association.  
    This mechanism effectively neutralizes the "Association Request flood" DoS attack.[41]

## **7\. Transition Modes and the 6 GHz "Clean Break"**

A major challenge in Wi-Fi security is handling the transition from legacy protocols. Wi-Fi 7 handles this differently depending on the frequency band.

### **7.1 WPA3-Transition Mode (2.4/5 GHz)**

In the legacy bands, APs must often support older clients. **WPA3-Transition Mode** allows an SSID to accept both WPA2-PSK and WPA3-SAE connections.

* **Vulnerability:** This is susceptible to **Downgrade Attacks**. An attacker can jam the WPA3 negotiation messages, forcing the client to fall back to WPA2.  
* **Defense (Transition Disable):** WPA3 capable APs send a "Transition Disable" indication (CSA bit) in the beacon. If a WPA3-compliant client sees this, it marks the network profile as "WPA3-Only" and will silently refuse any future WPA2 connections to that SSID, effectively "pinning" the security level.[2]

### **7.2 The 6 GHz Mandate**

In the 6 GHz band, there is no legacy debt.

* **Rule:** WPA2 is **prohibited**. Open (unencrypted) networks are **prohibited**.  
* **OWE (Enhanced Open):** For public hotspots where password authentication is impractical (coffee shops, airports), Wi-Fi 7 uses **Opportunistic Wireless Encryption (OWE)**.  
  * OWE performs an unauthenticated Diffie-Hellman exchange during the association process.  
  * This generates a unique PMK and PTK for the session, encrypting the data traffic.  
  * *Result:* Passive sniffers cannot read the user's data (unlike open networks today). However, it does not provide authentication—users are still vulnerable to "Evil Twin" active MitM attacks, but their data is safe from passive eavesdropping.[1]

## **8\. Conclusion**

The security architecture of IEEE 802.11be (Wi-Fi 7\) represents a maturation of wireless cryptography. It moves away from the "bolt-on" security model of the past, where encryption was an optional layer atop an insecure transport, to a model where security is intrinsic to the protocol's operation.

By mandating **SAE with H2E**, Wi-Fi 7 ensures that user identity verification is mathematically robust against both offline brute-force capabilities and sophisticated side-channel analysis. The adoption of **AES-GCMP-256** aligns wireless encryption standards with top-tier military and government requirements, ensuring that the physical layer's massive throughput does not compromise data confidentiality.

Furthermore, the **MLO security model** demonstrates a sophisticated approach to state management, balancing the need for a unified identity (MLD PTK) with the physical realities of radio frequency separation (Link-Specific GTKs). For network engineers and security architects, Wi-Fi 7 offers a toolkit that, when properly implemented, eliminates entire classes of attacks—from Deauth flooding to KRACK—that have plagued wireless networks for decades. The 6 GHz band, in particular, stands as a fortress of modern cryptography, free from the vulnerabilities of the legacy WPA2 era.

| Component | Wi-Fi 6 / Legacy | Wi-Fi 7 (802.11be) | Insight |
| :---- | :---- | :---- | :---- |
| **Authentication** | WPA2-PSK (Weak) / WPA3-SAE | **WPA3-SAE (Mandatory 6GHz)** | Eliminates offline dictionary attacks. |
| **PWE Derivation** | Hunting & Pecking | **H2E (Hash-to-Element)** | Mitigates "Dragonblood" timing attacks. |
| **Key Hierarchy** | Single Link | **Unified MLD PMK / Split GTK** | Enables seamless multi-band aggregation. |
| **Mgmt Protection** | Optional (802.11w) | **Mandatory (PMF)** | Prevents Deauth/Disassoc DoS attacks. |
| **Encryption** | CCMP-128 | **GCMP-256** | Supports \>30 Gbps; Quantum-resistant key size. |

#### **Works cited**

1. Wi-Fi 7 (802.11be) Technical Guide \- Cisco Meraki Documentation, accessed January 14, 2026, [https://documentation.meraki.com/Wireless/Design\_and\_Configure/Architecture\_and\_Best\_Practices/Wi-Fi\_7\_(802.11be)\_Technical\_Guide](https://documentation.meraki.com/Wireless/Design_and_Configure/Architecture_and_Best_Practices/Wi-Fi_7_\(802.11be\)_Technical_Guide)  
2. Security Enhancements in Wi-Fi 7 \- White Paper \- Arista, accessed January 14, 2026, [https://www.arista.com/assets/data/pdf/Whitepapers/Arista-Security-Enhancements-in-Wi-Fi-7.pdf](https://www.arista.com/assets/data/pdf/Whitepapers/Arista-Security-Enhancements-in-Wi-Fi-7.pdf)  
3. Wi-Fi 7 Security: Essential Information You Need | RUCKUS Networks, accessed January 14, 2026, [https://www.ruckusnetworks.com/blog/2023/wi-fi-7-and-security-what-you-need-to-know/](https://www.ruckusnetworks.com/blog/2023/wi-fi-7-and-security-what-you-need-to-know/)  
4. WPA3 Dragonfly Handshake \- \- SarWiki, accessed January 14, 2026, [https://sarwiki.informatik.hu-berlin.de/WPA3\_Dragonfly\_Handshake](https://sarwiki.informatik.hu-berlin.de/WPA3_Dragonfly_Handshake)  
5. Help me understand SAE for WPA3 \- Information Security Stack Exchange, accessed January 14, 2026, [https://security.stackexchange.com/questions/194740/help-me-understand-sae-for-wpa3](https://security.stackexchange.com/questions/194740/help-me-understand-sae-for-wpa3)  
6. September | 2025 | mrn-cciew, accessed January 14, 2026, [https://mrncciew.com/2025/09/](https://mrncciew.com/2025/09/)  
7. WiFi7 Multi-Link Operation(MLO) \- Arista Community Central, accessed January 14, 2026, [https://arista.my.site.com/AristaCommunity/s/article/WiFi7-Multi-Link-Operation](https://arista.my.site.com/AristaCommunity/s/article/WiFi7-Multi-Link-Operation)  
8. RFC 7664 \- Dragonfly Key Exchange \- IETF Datatracker, accessed January 14, 2026, [https://datatracker.ietf.org/doc/rfc7664/](https://datatracker.ietf.org/doc/rfc7664/)  
9. WPA3 and DragonFly (SAE) \- Wireless, accessed January 14, 2026, [https://balramdot11b.com/2020/05/17/wpa3-and-dragonfly-sae/](https://balramdot11b.com/2020/05/17/wpa3-and-dragonfly-sae/)  
10. Model based fuzzing of the WPA3 Dragonfly handshake \- Humboldt-Universität zu Berlin, accessed January 14, 2026, [https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2020-01/SAR-PR-2020-01\_.pdf](https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2020-01/SAR-PR-2020-01_.pdf)  
11. Finite fields and ECC \- elliptic curves \- Cryptography Stack Exchange, accessed January 14, 2026, [https://crypto.stackexchange.com/questions/10024/finite-fields-and-ecc](https://crypto.stackexchange.com/questions/10024/finite-fields-and-ecc)  
12. Dragonblood: Analysing WPA3's Dragonfly Handshake, accessed January 14, 2026, [https://wpa3.mathyvanhoef.com/](https://wpa3.mathyvanhoef.com/)  
13. Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd \- Publications \- Mathy Vanhoef, accessed January 14, 2026, [https://papers.mathyvanhoef.com/dragonblood.pdf](https://papers.mathyvanhoef.com/dragonblood.pdf)  
14. RFC 9383: SPAKE2+, an Augmented Password-Authenticated Key Exchange (PAKE) Protocol, accessed January 14, 2026, [https://www.rfc-editor.org/rfc/rfc9383](https://www.rfc-editor.org/rfc/rfc9383)  
15. WPA3 enhancements to support H2E only and SAE-PK 7.2.1 \- Fortinet Document Library, accessed January 14, 2026, [https://docs.fortinet.com/document/fortigate/7.2.0/new-features/645349/wpa3-enhancements-to-support-h2e-only-and-sae-pk-7-2-1](https://docs.fortinet.com/document/fortigate/7.2.0/new-features/645349/wpa3-enhancements-to-support-h2e-only-and-sae-pk-7-2-1)  
16. Hash to Curve \- Elligator, accessed January 14, 2026, [https://elligator.org/hash-to-curve](https://elligator.org/hash-to-curve)  
17. draft-irtf-cfrg-hash-to-curve-12 \- Hashing to Elliptic Curves \- IETF Datatracker, accessed January 14, 2026, [https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/12/](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/12/)  
18. Why we transitioned from Hunting-and-Pecking to Hash-to-Element in WPA3-SAE Password Element Derivation | WizardFi, accessed January 14, 2026, [https://wizardfi.com/security/2024/03/29/hash-to-curve.html](https://wizardfi.com/security/2024/03/29/hash-to-curve.html)  
19. Support \- WPA3 Technology White Paper-6W100 \- H3C, accessed January 14, 2026, [https://www.h3c.com/en/Support/Resource\_Center/EN/Home/Switches/00-Public/Trending/Technology\_White\_Papers/WPA3\_TWP-6W100/](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Switches/00-Public/Trending/Technology_White_Papers/WPA3_TWP-6W100/)  
20. Dissecting WPA3 \- SharkFest, accessed January 14, 2026, [https://sharkfest.wireshark.org/retrospective/sfus/presentations22/03DissectingWPA3.pdf](https://sharkfest.wireshark.org/retrospective/sfus/presentations22/03DissectingWPA3.pdf)  
21. Password Identifier \- IEEE Mentor, accessed January 14, 2026, [https://mentor.ieee.org/802.11/dcn/18/11-18-0202-03-000m-identifying-a-password.docx](https://mentor.ieee.org/802.11/dcn/18/11-18-0202-03-000m-identifying-a-password.docx)  
22. SAECRED: A State-Aware, Over-the-Air Protocol Testing Approach for Discovering Parsing Bugs in SAE Handshake Implementations of \- Publications, accessed January 14, 2026, [https://papers.mathyvanhoef.com/ieeesp2025.pdf](https://papers.mathyvanhoef.com/ieeesp2025.pdf)  
23. WPA3 Personal \- Simultaneous Authentication of Equals(SAE) \- Arista Community Central, accessed January 14, 2026, [https://arista.my.site.com/AristaCommunity/s/article/WPA3-Personal-Simultaneous-Authentication-of-Equals-SAE?nocache=https%3A%2F%2Farista.my.site.com%2FAristaCommunity%2Fs%2Farticle%2FWPA3-Personal-Simultaneous-Authentication-of-Equals-SAE](https://arista.my.site.com/AristaCommunity/s/article/WPA3-Personal-Simultaneous-Authentication-of-Equals-SAE?nocache=https://arista.my.site.com/AristaCommunity/s/article/WPA3-Personal-Simultaneous-Authentication-of-Equals-SAE)  
24. How does Dragonfly key exchange work, in non-white-paper terms?, accessed January 14, 2026, [https://crypto.stackexchange.com/questions/64546/how-does-dragonfly-key-exchange-work-in-non-white-paper-terms](https://crypto.stackexchange.com/questions/64546/how-does-dragonfly-key-exchange-work-in-non-white-paper-terms)  
25. RFC 9380: Hashing to Elliptic Curves, accessed January 14, 2026, [https://www.rfc-editor.org/rfc/rfc9380.html](https://www.rfc-editor.org/rfc/rfc9380.html)  
26. RFC 7664: Dragonfly Key Exchange, accessed January 14, 2026, [https://www.rfc-editor.org/rfc/rfc7664.html](https://www.rfc-editor.org/rfc/rfc7664.html)  
27. WPA3 Deep Dive \- Wireless, accessed January 14, 2026, [https://balramdot11b.com/2020/11/08/wpa3-deep-dive/](https://balramdot11b.com/2020/11/08/wpa3-deep-dive/)  
28. WPA3-SAE Mode \- mrn-cciew, accessed January 14, 2026, [https://mrncciew.com/2019/11/29/wpa3-sae-mode/](https://mrncciew.com/2019/11/29/wpa3-sae-mode/)  
29. 11-20-1445-06-00be-pdt-mac-mlo-setup-security.docx \- IEEE Mentor, accessed January 14, 2026, [https://mentor.ieee.org/802.11/dcn/20/11-20-1445-06-00be-pdt-mac-mlo-setup-security.docx](https://mentor.ieee.org/802.11/dcn/20/11-20-1445-06-00be-pdt-mac-mlo-setup-security.docx)  
30. WiFiCx Wi-Fi 7 feature requirements \- Windows drivers \- Microsoft Learn, accessed January 14, 2026, [https://learn.microsoft.com/en-us/windows-hardware/drivers/netcx/wificx-wi-fi-7](https://learn.microsoft.com/en-us/windows-hardware/drivers/netcx/wificx-wi-fi-7)  
31. Wi-Fi 7 – Multi-Link Association | mrn-cciew, accessed January 14, 2026, [https://mrncciew.com/2025/09/08/wi-fi-7-multi-link-association/](https://mrncciew.com/2025/09/08/wi-fi-7-multi-link-association/)  
32. WPA-3 Dragonfly: Out of the Frying Pan, and into the Fire | by Prof Bill Buchanan OBE FRSE | ASecuritySite: When Bob Met Alice | Medium, accessed January 14, 2026, [https://medium.com/asecuritysite-when-bob-met-alice/wpa-3-dragonfly-out-of-the-frying-pan-and-into-the-fire-35240aef4376](https://medium.com/asecuritysite-when-bob-met-alice/wpa-3-dragonfly-out-of-the-frying-pan-and-into-the-fire-35240aef4376)  
33. WPA3 Enterprise \- Zebra Technologies, accessed January 14, 2026, [https://docs.zebra.com/us/en/mobile-computers/software/bm-6ghz-for-aruba-wlan-best-practices-guide-ditamap/c-6ghz-security-recommendations-while-deploying-zebra-clients-in-6ghz-network/r-6ghz-wpa3-enterprise.html](https://docs.zebra.com/us/en/mobile-computers/software/bm-6ghz-for-aruba-wlan-best-practices-guide-ditamap/c-6ghz-security-recommendations-while-deploying-zebra-clients-in-6ghz-network/r-6ghz-wpa3-enterprise.html)  
34. What Are the EAP Method Requirements For WPA3-Enterprise? \- SecureW2, accessed January 14, 2026, [https://www.securew2.com/blog/eap-method-requirements-for-wpa3-enterprise](https://www.securew2.com/blog/eap-method-requirements-for-wpa3-enterprise)  
35. WPA3 Encryption and Configuration Guide \- Cisco Meraki Documentation, accessed January 14, 2026, [https://documentation.meraki.com/Wireless/Design\_and\_Configure/Configuration\_Guides/Encryption\_and\_Authentication/WPA3\_Encryption\_and\_Configuration\_Guide](https://documentation.meraki.com/Wireless/Design_and_Configure/Configuration_Guides/Encryption_and_Authentication/WPA3_Encryption_and_Configuration_Guide)  
36. Advice to eduroam® Identity Providers and Service Providers following the release of Wi-Fi CERTIFIED WPA3™ Security, accessed January 14, 2026, [https://www.eduroam.org/wp-content/uploads/eduroam-advice-for-WiFi-Alliance-WPA3.pdf](https://www.eduroam.org/wp-content/uploads/eduroam-advice-for-WiFi-Alliance-WPA3.pdf)  
37. Analysis and Evaluation of WPA3 Security Enhancements with Implementation Guidelines for Secure SOHO Network Deployment \- Digikogu, accessed January 14, 2026, [https://digikogu.taltech.ee/en/Download/c694a06d-f438-400a-bd3a-91439cd77d00](https://digikogu.taltech.ee/en/Download/c694a06d-f438-400a-bd3a-91439cd77d00)  
38. Establishing wireless robust security networks: a guide to IEEE 802.11i \- NIST Technical Series Publications, accessed January 14, 2026, [https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-97.pdf](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-97.pdf)  
39. Pre-Association Management Frame Protection \- IEEE Mentor, accessed January 14, 2026, [https://mentor.ieee.org/802.11/dcn/22/11-22-1666-02-00bi-pre-association-management-frame-protection.pptx](https://mentor.ieee.org/802.11/dcn/22/11-22-1666-02-00bi-pre-association-management-frame-protection.pptx)  
40. IEEE 802.11w-2009 \- Wikipedia, accessed January 14, 2026, [https://en.wikipedia.org/wiki/IEEE\_802.11w-2009](https://en.wikipedia.org/wiki/IEEE_802.11w-2009)  
41. WAP\_820\_840 Series Access Points \- TELDAT, accessed January 14, 2026, [https://support.teldat.com/images/content/docs/10-Dm3167-I\_Wireless\_Security\_Configuration.pdf](https://support.teldat.com/images/content/docs/10-Dm3167-I_Wireless_Security_Configuration.pdf)
