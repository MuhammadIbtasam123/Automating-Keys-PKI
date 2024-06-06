const crypto = require("crypto");
const fs = require("fs");
const { spawnSync } = require("child_process");
const forge = require("node-forge");

// Generate a key pair
const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

// Create a self-signed certificate
const cert = forge.pki.createCertificate();
cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
cert.serialNumber = "01";
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
const attrs = [
  {
    name: "commonName",
    value: "example.org",
  },
  {
    name: "countryName",
    value: "US",
  },
  {
    shortName: "ST",
    value: "Virginia",
  },
  {
    name: "localityName",
    value: "Blacksburg",
  },
  {
    name: "organizationName",
    value: "Test",
  },
  {
    shortName: "OU",
    value: "Test",
  },
];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([
  {
    name: "basicConstraints",
    cA: true,
  },
  {
    name: "keyUsage",
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true,
  },
  {
    name: "extKeyUsage",
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  },
  {
    name: "nsCertType",
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true,
  },
  {
    name: "subjectAltName",
    altNames: [
      {
        type: 6, // URI
        value: "http://example.org/webid#me",
      },
    ],
  },
  {
    name: "subjectKeyIdentifier",
  },
]);

// Self-sign the certificate
cert.sign(forge.pki.privateKeyFromPem(keyPair.privateKey));

// Convert the certificate to PEM format
const pemCert = forge.pki.certificateToPem(cert);

// Write the private key and certificate to files
fs.writeFileSync("mykey.pem", keyPair.privateKey);
fs.writeFileSync("cert.pem", pemCert);

// Generate PKCS#12 keystore using OpenSSL command-line tool
const opensslCmd = `openssl pkcs12 -export -out keystore.p12 -inkey mykey.pem -in cert.pem`;
const opensslArgs = opensslCmd.split(" ");
const opensslProcess = spawnSync(opensslArgs[0], opensslArgs.slice(1), {
  encoding: "utf-8",
});

if (opensslProcess.status === 0) {
  console.log("PKCS#12 keystore generated successfully.");
} else {
  console.error("Failed to generate PKCS#12 keystore:", opensslProcess.stderr);
}
