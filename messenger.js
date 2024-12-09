
'use strict'
/** ******* Imports ********/

const {
  /* cryptographic primatives used.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/


const MAX_SKIP = 256;

// Key Derivation Function (KDF) for generating a key from a root key (RK) 
// and a Diffie-Hellman output.
async function KDF_RK(rk, dh_out){
  return await HKDF(rk, dh_out, "arbitaryConstant")
}

async function KDF_CK(ck) {
  // Flag indicating whether to export the key as an ArrayBuffer.
  const exportToArrayBuffer = false;
  // Derive a salt from the chaining key using HMAC.
  const salt = await HMACtoHMACKey(ck, "salt");
  // Use HKDF to derive salts for the message key and chain key.
  const [mkSalt, chainKeySalt] = await HKDF(salt, salt, "randomString");
  // Derive the new chain key from the chain key salt.
  const new_chainKey = await HMACtoHMACKey(chainKeySalt, "randomString");
  // Derive the message key using the message key salt.
  const message_key = await HMACtoAESKey(mkSalt, "randomString", exportToArrayBuffer);
  // Generate a buffer representation of the message key.
  const mk_Buf = await HMACtoAESKey(mkSalt, "randomString", !exportToArrayBuffer);
  // Return the newly derived keys as an array.
  return [new_chainKey, message_key, mk_Buf];
}

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey

    this.conns = {} // data for each active state
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    // generate a key pair 
    this.EGKeyPair = await generateEG();
    //construct the certificate using username and public key
    const certificate = {"username": username,"pub" : this.EGKeyPair.pub,};
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const verification = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature);
    //interrupt if invalid certificate
    if (!verification) {
      throw ("Invalid Cerificate");
    }
    //add certificate to certificate of other users
    this.certs[certificate.username] = certificate;
  }

  async TrySkippedMessageKeys(name, state, header, ciphertext) {
    // Check if the combination of header's DH (Diffie-Hellman public key) and N (nonce) 
    // exists in the state's skipped message key dictionary (MKSKIPPED).
    if ((header.dh, header.N) in state.MKSKIPPED) {
      // Retrieve the message key (mk) from MKSKIPPED using the (header.dh, header.N) tuple.
      const mk = state.MKSKIPPED[(header.dh, header.N)];
      // Remove the used key from the skipped keys dictionary to avoid reuse.
      delete state.MKSKIPPED[(header.dh, header.N)];
      try {
        // Attempt to decrypt the ciphertext using the retrieved message key (mk), 
        // the receiver's IV (initialization vector), and the header (as associated data).
        const plaintextBuffer = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
        // Convert the decrypted buffer to a string and return it as the plaintext message.
        const plaintext = bufferToString(plaintextBuffer);
        return plaintext;
      } catch (error) {
        // If decryption fails, throw an error with a descriptive message.
        throw new Error("Decryption failed: " + error.message);
      } 
    }
    else{
      // If no applicable skipped message key is found, return null.
      return null;
    }
    
  }
  
  async SkipMessageKeys(state, until) {
    // Check if the current nonce (Nr) plus the maximum number of skips (MAX_SKIP)
    // is less than the specified until value. If so, throw an exception as it indicates
    // that too many keys are being skipped without processing.
    if (state.Nr + MAX_SKIP < until) {
      throw new Error(`Cannot skip messages: requested skip until ${until} exceeds the maximum limit of ${state.Nr + MAX_SKIP}.`) 
    }
    // Check if the current chain key (CKr) is not null, indicating that keys can be generated.
    if (state.CKr !== null) {
      // Loop until the current nonce (Nr) reaches the until value
      while (state.Nr < until) {
        // Generate a new chain key and message key using the current chain key (CKr).
        const [ckr, mk] = await KDF_CK(state.CKr);
        // Update the current chain key in the state.
        state.CKr = ckr;
        // Store the generated message key in the skipped message keys dictionary (MKSKIPPED)
        // using the tuple of the current Diffie-Hellman public key (DHr) and nonce (Nr).
        state.MKSKIPPED[(state.DHr, state.Nr)] = mk;
        // Increment the nonce (Nr) to indicate that a new key has been processed.
        state.Nr += 1;
      }
    }
    // Return the updated state after processing.
    return state;
  }

  async createConnection(name) {
    // Check if a connection for the specified user name already exists.
    if (!(name in this.conns)) { 
      // Retrieve the user's certificate from the stored certificates.
      let certif = this.certs[name]
       // Generate a new DH key pair for the connection.
      const dhs = await generateEG();
      // Compute the root key by performing a Diffie-Hellman exchange with the user's public key.
      const RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      // Compute a second Diffie-Hellman value using the new DH key pair and the user's public key.
      const dhhs = await computeDH(dhs.sec, certif.pub);
      // Derive a root key and chain key from the root key and the second Diffie-Hellman value.
      const [rk, cks] = await KDF_RK(RootKey, dhhs);

  
      // Initialize the connection state for the user with relevant parameters.
      this.conns[name] = {
        DHkeyPair: this.EGKeyPair,// Store the user's key pair.
        RK: rk, // Root key for encryption.
        DHs: dhs, // Sender's DH key.
        DHr: certif.pub,// Recipient's public DH key from the certificate.
        CKs: cks, // Chain key for message encryption.
        CKr: null, // Chain key for the recipient, initialized to null.
        Ns: 0, // Sender's nonce counter, initialized to zero.
        Nr: 0, // Recipient's nonce counter, initialized to zero.
        PN: 0, // A counter for the number of messages sent in the previous chain, initialized to zero.
        isSender : false, // Flag to indicate if the current instance is the sender.
        MKSKIPPED: {}, // Dictionary to store skipped message keys.
      };
    }
  
    // Retrieve the state of the connection for the specified user.
    const state = this.conns[name];
    // If the connection state does not yet have a chain key (CKs), generate one.
    if (!state.CKs) {
      // Retrieve the user's certificate again.
      let certif = this.certs[name]
      // Compute the root key for the connection.
      const RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      // Generate a new DH key pair for this connection.
      const dhs = await generateEG();
      // Compute a new Diffie-Hellman value using the new DH key pair.
      const dHS = await computeDH(dhs.sec, certif.pub);
      // Derive a root key and chain key using the root key and the new Diffie-Hellman value.
      const [rk, cks] = await KDF_RK(RootKey, dHS);
      // Update the connection state with the new ephemeral key pair and chain key.
      state.DHs = dhs
      state.CKs = cks
    }
  }
  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage(name, plaintext) {
    // Ensure that a connection exists for the recipient before sending a message.
    await this.createConnection(name);
    // Retrieve the current state of the connection for the recipient.
    const state = this.conns[name];
    // Derive new chain keys and message keys from the current chain key.
    const [CKs, mk, mkBuf] = await KDF_CK(state.CKs);
    // Update the current chain key in the connection state.
    state.CKs = CKs;

    // Generate random salt and IV for encryption purposes.
    const salt = genRandomSalt();
    const ivGov = genRandomSalt();
    // Generate a new DH key pair for government-level encryption.
    const dhGov = await generateEG();
    // Compute the shared key for government encryption using the public key provided by the government.
    const kGov = await computeDH(dhGov.sec, this.govPublicKey);
    // Derive an AES key for government encryption from the computed key and predefined constant.
    const aesGov = await HMACtoAESKey(kGov, govEncryptionDataStr, false);
    // Encrypt the message key buffer using GCM with the derived AES key
    const cGov = await encryptWithGCM(aesGov, mkBuf, ivGov)
    // Construct the header for the message, including necessary identifiers.
    const header = {
      DH: state.DHs.pub,// Sender's public DH key
      N: state.Ns,// Sender's nonce.
      receiverIV: salt,// IV for the receiver's encryption.
      vGov: dhGov.pub,// Government's public DH key.
      cGov: cGov,// Encrypted government data.
      ivGov: ivGov,// IV for the government encryption.
    }
    // Increment the sender's nonce for the next message.
    state.Ns = state.Ns + 1

    // Encrypt the plaintext message using GCM with the message key and additional header data.
    const ciphertext = await encryptWithGCM(mk, plaintext, salt, JSON.stringify(header));
    // Return the header and the ciphertext for sending.
    return [header, ciphertext]
  }
  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */

    //Receive an encrypted message from the user specified by name
  async receiveMessage (name, [header, ciphertext]) {
    // Check if a connection for the specified sender already exists.
    if (!(name in this.conns)) { 
      // Retrieve the sender's certificate to compute keys
      let certif = this.certs[name]
      // Compute the root key for the sender's public key.
      let RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      // Compute the Diffie-Hellman value based on the sender's DH key from the header.
      let dhSS = await computeDH(this.EGKeyPair.sec, header.DH);
      // Derive the root key and the current chain key using the computed keys.
      let [rk, ckr] = await KDF_RK(RootKey, dhSS);

      // Initialize the connection state for the sender
      this.conns[name] = {
        DHr: header.DH,// Recipient's DH key from the header.
        RK: RootKey,// Root key for encryption.
        CKr: ckr, // Current chain key for decryption.
        Nr: 0, // Initialize recipient's nonce counter.
        MKSKIPPED: {}, // Dictionary for skipped message keys.
      };
    }
    // Retrieve the current state of the connection for the sender.
    let state = this.conns[name];
    // If the current chain key for the recipient is not set, compute it.
    if (!state.CKr) {
      // Retrieve the sender's certificate again for key computation.
      let certif = this.certs[name]
      // Compute the root key for the sender's public key.
      let RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      // Compute the Diffie-Hellman value using the sender's DH key from the header.
      let dhhs = await computeDH(this.EGKeyPair.sec, header.DH);
      // Derive the root key and current chain key for the recipient.
      let [rk, ckr] = await KDF_RK(RootKey, dhhs);
      // Update the state with the new chain key and DH key
      state.CKr = ckr;
      state.DHr = header.DH;
    }

    // Attempt to decrypt the message using any skipped message keys
    let plaintext = await this.TrySkippedMessageKeys(name, state, header, ciphertext);
    // If decryption was successful with skipped keys, return the plaintext.
    if (plaintext !== null) return plaintext;
    // Otherwise, generate any necessary keys up to the nonce specified in the header.
    state = await this.SkipMessageKeys(state, header.N);
    // Derive the new current chain key and message key
    let [CKr, mk] = await KDF_CK(state.CKr);
    // Update the current chain key in the connection state.
    state.CKr = CKr;
    // Increment the recipient's nonce counter.
    state.Nr = state.Nr + 1;

    try {
      // Decrypt the ciphertext using the derived message key, the receiver's IV, and additional header data.
      let plaintextBuffer = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
      // Convert the decrypted buffer to a string.
      let plaintext = bufferToString(plaintextBuffer);
      // Update the connection state to reflect any changes.
      this.conns[name] = Object.assign({}, state);
      // Return the decrypted plaintext message
      return plaintext;
    } catch (error) {
      // If decryption fails, throw an error with a descriptive message.
      throw new Error("Failed: " + error.message);
    } 
  }
};

module.exports = {
  MessengerClient
}