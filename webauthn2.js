const crypto = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const jsrsasign = require("jsrsasign");
const elliptic = require("elliptic");
const NodeRSA = require("node-rsa");
const forge = require("node-forge");
const BN = require("bn.js");
const vanillacbor = require("./vanillacbor");

// const parseAuthData = (buffer) => {
//     if(buffer.byteLength < 37)
//         throw new Error('Authenticator Data must be at least 37 bytes long!');

//     let rpIdHash      = buffer.slice(0, 32);             buffer = buffer.slice(32);

//     /* Flags */
//     let flagsBuffer   = buffer.slice(0, 1);              buffer = buffer.slice(1);
//     let flagsInt      = flagsBuffer[0];
//     let up            = !!(flagsInt & 0x01); // Test of User Presence
//     let uv            = !!(flagsInt & 0x04); // User Verification
//     let at            = !!(flagsInt & 0x40); // Attestation data
//     let ed            = !!(flagsInt & 0x80); // Extension data
//     let flags = {up, uv, at, ed, flagsInt};

//     let counterBuffer = buffer.slice(0, 4);               buffer = buffer.slice(4);
//     let counter       = counterBuffer.readUInt32BE(0);

//     /* Attested credential data */
//     let aaguid              = undefined;
//     let aaguidBuffer        = undefined;
//     let credIdBuffer        = undefined;
//     let cosePublicKeyBuffer = undefined;
//     let attestationMinLen   = 16 + 2 + 16 + 77; // aaguid + credIdLen + credId + pk

//     if(at) { // Attested Data
//         if(buffer.byteLength < attestationMinLen)
//             throw new Error(`It seems as the Attestation Data flag is set, but the remaining data is smaller than ${attestationMinLen} bytes. You might have set AT flag for the assertion response.`)

//         aaguid              = buffer.slice(0, 16).toString('hex'); buffer = buffer.slice(16);
//         aaguidBuffer        = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(16, 20)}-${aaguid.slice(20)}`;

//         let credIdLenBuffer = buffer.slice(0, 2);                  buffer = buffer.slice(2);
//         let credIdLen       = credIdLenBuffer.readUInt16BE(0);
//         credIdBuffer        = buffer.slice(0, credIdLen);          buffer = buffer.slice(credIdLen);

//         let pubKeyLength    = vanillacbor.decodeOnlyFirst(buffer).byteLength;
//         cosePublicKeyBuffer = buffer.slice(0, pubKeyLength);       buffer = buffer.slice(pubKeyLength);
//     }

//     let coseExtensionsDataBuffer = undefined;
//     if(ed) { // Extension Data
//         let extensionsDataLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;

//         coseExtensionsDataBuffer = buffer.slice(0, extensionsDataLength); buffer = buffer.slice(extensionsDataLength);
//     }

//     if(buffer.byteLength)
//         throw new Error('Failed to decode authData! Leftover bytes been detected!');

//     return {rpIdHash, counter, flags, counterBuffer, aaguid, credIdBuffer, cosePublicKeyBuffer, coseExtensionsDataBuffer}
// }
// const jwkToPem = require('jwk-to-pem')

let TPM_ALG = {
  0x0000: "TPM_ALG_ERROR",
  0x0001: "TPM_ALG_RSA",
  0x0004: "TPM_ALG_SHA",
  0x0004: "TPM_ALG_SHA1",
  0x0005: "TPM_ALG_HMAC",
  0x0006: "TPM_ALG_AES",
  0x0007: "TPM_ALG_MGF1",
  0x0008: "TPM_ALG_KEYEDHASH",
  0x000a: "TPM_ALG_XOR",
  0x000b: "TPM_ALG_SHA256",
  0x000c: "TPM_ALG_SHA384",
  0x000d: "TPM_ALG_SHA512",
  0x0010: "TPM_ALG_NULL",
  0x0012: "TPM_ALG_SM3_256",
  0x0013: "TPM_ALG_SM4",
  0x0014: "TPM_ALG_RSASSA",
  0x0015: "TPM_ALG_RSAES",
  0x0016: "TPM_ALG_RSAPSS",
  0x0017: "TPM_ALG_OAEP",
  0x0018: "TPM_ALG_ECDSA",
  0x0019: "TPM_ALG_ECDH",
  0x001a: "TPM_ALG_ECDAA",
  0x001b: "TPM_ALG_SM2",
  0x001c: "TPM_ALG_ECSCHNORR",
  0x001d: "TPM_ALG_ECMQV",
  0x0020: "TPM_ALG_KDF1_SP800_56A",
  0x0021: "TPM_ALG_KDF2",
  0x0022: "TPM_ALG_KDF1_SP800_108",
  0x0023: "TPM_ALG_ECC",
  0x0025: "TPM_ALG_SYMCIPHER",
  0x0026: "TPM_ALG_CAMELLIA",
  0x0040: "TPM_ALG_CTR",
  0x0041: "TPM_ALG_OFB",
  0x0042: "TPM_ALG_CBC",
  0x0043: "TPM_ALG_CFB",
  0x0044: "TPM_ALG_ECB",
};

let TPM_ECC_CURVE = {
  0x0000: "TPM_ECC_NONE",
  0x0001: "TPM_ECC_NIST_P192",
  0x0002: "TPM_ECC_NIST_P224",
  0x0003: "TPM_ECC_NIST_P256",
  0x0004: "TPM_ECC_NIST_P384",
  0x0005: "TPM_ECC_NIST_P521",
  0x0010: "TPM_ECC_BN_P256",
  0x0011: "TPM_ECC_BN_P638",
  0x0020: "TPM_ECC_SM2_P256",
};

let TPM_CC = {
  0x0000011f: "TPM_CC_FIRST",
  0x0000011f: "TPM_CC_NV_UndefineSpaceSpecial",
  0x00000120: "TPM_CC_EvictControl",
  0x00000121: "TPM_CC_HierarchyControl",
  0x00000122: "TPM_CC_NV_UndefineSpace",
  0x00000124: "TPM_CC_ChangeEPS",
  0x00000125: "TPM_CC_ChangePPS",
  0x00000126: "TPM_CC_Clear",
  0x00000127: "TPM_CC_ClearControl",
  0x00000128: "TPM_CC_ClockSet",
  0x00000129: "TPM_CC_HierarchyChangeAuth",
  0x0000012a: "TPM_CC_NV_DefineSpace",
  0x0000012b: "TPM_CC_PCR_Allocate",
  0x0000012c: "TPM_CC_PCR_SetAuthPolicy",
  0x0000012d: "TPM_CC_PP_Commands",
  0x0000012e: "TPM_CC_SetPrimaryPolicy",
  0x0000012f: "TPM_CC_FieldUpgradeStart",
  0x00000130: "TPM_CC_ClockRateAdjust",
  0x00000131: "TPM_CC_CreatePrimary",
  0x00000132: "TPM_CC_NV_GlobalWriteLock",
  0x00000133: "TPM_CC_GetCommandAuditDigest",
  0x00000134: "TPM_CC_NV_Increment",
  0x00000135: "TPM_CC_NV_SetBits",
  0x00000136: "TPM_CC_NV_Extend",
  0x00000137: "TPM_CC_NV_Write",
  0x00000138: "TPM_CC_NV_WriteLock",
  0x00000139: "TPM_CC_DictionaryAttackLockReset",
  0x0000013a: "TPM_CC_DictionaryAttackParameters",
  0x0000013b: "TPM_CC_NV_ChangeAuth",
  0x0000013c: "TPM_CC_PCR_Event",
  0x0000013d: "TPM_CC_PCR_Reset",
  0x0000013e: "TPM_CC_SequenceComplete",
  0x0000013f: "TPM_CC_SetAlgorithmSet",
  0x00000140: "TPM_CC_SetCommandCodeAuditStatus",
  0x00000141: "TPM_CC_FieldUpgradeData",
  0x00000142: "TPM_CC_IncrementalSelfTest",
  0x00000143: "TPM_CC_SelfTest",
  0x00000144: "TPM_CC_Startup",
  0x00000145: "TPM_CC_Shutdown",
  0x00000146: "TPM_CC_StirRandom",
  0x00000147: "TPM_CC_ActivateCredential",
  0x00000148: "TPM_CC_Certify",
  0x00000149: "TPM_CC_PolicyNV",
  0x0000014a: "TPM_CC_CertifyCreation",
  0x0000014b: "TPM_CC_Duplicate",
  0x0000014c: "TPM_CC_GetTime",
  0x0000014d: "TPM_CC_GetSessionAuditDigest",
  0x0000014e: "TPM_CC_NV_Read",
  0x0000014f: "TPM_CC_NV_ReadLock",
  0x00000150: "TPM_CC_ObjectChangeAuth",
  0x00000151: "TPM_CC_PolicySecret",
  0x00000152: "TPM_CC_Rewrap",
  0x00000153: "TPM_CC_Create",
  0x00000154: "TPM_CC_ECDH_ZGen",
  0x00000155: "TPM_CC_HMAC",
  0x00000156: "TPM_CC_Import",
  0x00000157: "TPM_CC_Load",
  0x00000158: "TPM_CC_Quote",
  0x00000159: "TPM_CC_RSA_Decrypt",
  0x0000015b: "TPM_CC_HMAC_Start",
  0x0000015c: "TPM_CC_SequenceUpdate",
  0x0000015d: "TPM_CC_Sign",
  0x0000015e: "TPM_CC_Unseal",
  0x00000161: "TPM_CC_PolicySigned",
  0x00000162: "TPM_CC_ContextLoad",
  0x00000163: "TPM_CC_ContextSave",
  0x00000164: "TPM_CC_ECDH_KeyGen",
  0x00000165: "TPM_CC_EncryptDecrypt",
  0x00000166: "TPM_CC_FlushContext",
  0x00000167: "TPM_CC_LoadExternal",
  0x00000168: "TPM_CC_MakeCredential",
  0x00000169: "TPM_CC_NV_ReadPublic",
  0x0000016a: "TPM_CC_PolicyAuthorize",
  0x0000016b: "TPM_CC_PolicyAuthValue",
  0x0000016c: "TPM_CC_PolicyCommandCode",
  0x0000016d: "TPM_CC_PolicyCounterTimer",
  0x0000016e: "TPM_CC_PolicyCpHash",
  0x0000016f: "TPM_CC_PolicyLocality",
  0x00000170: "TPM_CC_PolicyNameHash",
  0x00000171: "TPM_CC_PolicyOR",
  0x00000172: "TPM_CC_PolicyTicket",
  0x00000173: "TPM_CC_ReadPublic",
  0x00000174: "TPM_CC_RSA_Encrypt",
  0x00000175: "TPM_CC_StartAuthSession",
  0x00000176: "TPM_CC_VerifySignature",
  0x00000177: "TPM_CC_ECC_Parameters",
  0x00000178: "TPM_CC_FirmwareRead",
  0x00000179: "TPM_CC_GetCapability",
  0x0000017a: "TPM_CC_GetRandom",
  0x0000017b: "TPM_CC_GetTestResult",
  0x0000017c: "TPM_CC_Hash",
  0x0000017d: "TPM_CC_PCR_Read",
  0x0000017e: "TPM_CC_PolicyPCR",
  0x0000017f: "TPM_CC_PolicyRestart",
  0x00000190: "TPM_CC_ReadClock",
  0x00000191: "TPM_CC_PCR_Extend",
  0x00000192: "TPM_CC_PCR_SetAuthValue",
  0x00000193: "TPM_CC_NV_Certify",
  0x00000185: "TPM_CC_EventSequenceComplete",
  0x00000186: "TPM_CC_HashSequenceStart",
  0x00000187: "TPM_CC_PolicyPhysicalPresence",
  0x00000188: "TPM_CC_PolicyDuplicationSelect",
  0x00000189: "TPM_CC_PolicyGetDigest",
  0x0000018a: "TPM_CC_TestParms",
  0x0000018b: "TPM_CC_Commit",
  0x0000018c: "TPM_CC_PolicyPassword",
  0x0000018d: "TPM_CC_ZGen_2Phase",
  0x0000018e: "TPM_CC_EC_Ephemeral",
  0x0000018f: "TPM_CC_PolicyNvWritten",
  0x00000190: "TPM_CC_PolicyTemplate",
  0x00000191: "TPM_CC_CreateLoaded",
  0x00000192: "TPM_CC_PolicyAuthorizeNV",
  0x00000193: "TPM_CC_EncryptDecrypt2",
};

let TPM_ST = {
  0x00c4: "TPM_ST_RSP_COMMAND",
  0x8000: "TPM_ST_NULL",
  0x8001: "TPM_ST_NO_SESSIONS",
  0x8002: "TPM_ST_SESSIONS",
  0x8014: "TPM_ST_ATTEST_NV",
  0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
  0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
  0x8017: "TPM_ST_ATTEST_CERTIFY",
  0x8018: "TPM_ST_ATTEST_QUOTE",
  0x8019: "TPM_ST_ATTEST_TIME",
  0x801a: "TPM_ST_ATTEST_CREATION",
  0x8021: "TPM_ST_CREATION",
  0x8022: "TPM_ST_VERIFIED",
  0x8023: "TPM_ST_AUTH_SECRET",
  0x8024: "TPM_ST_HASHCHECK",
  0x8025: "TPM_ST_AUTH_SIGNED",
  0x8029: "TPM_ST_FU_MANIFEST",
};

let FIDO_ALG_TO_COSE = {
  ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW: {
    kty: 2,
    alg: -7,
    crv: 1,
  },
  ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW: {
    kty: 2,
    alg: -7,
    crv: 8,
  },
  ALG_SIGN_RSASSA_PSS_SHA256_RAW: {
    kty: 3,
    alg: -37,
  },
  ALG_SIGN_RSASSA_PSS_SHA384_RAW: {
    kty: 3,
    alg: -38,
  },
  ALG_SIGN_RSASSA_PSS_SHA512_RAW: {
    kty: 3,
    alg: -39,
  },
  ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW: {
    kty: 3,
    alg: -257,
  },
  ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW: {
    kty: 3,
    alg: -258,
  },
  ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW: {
    kty: 3,
    alg: -259,
  },
  ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW: {
    kty: 3,
    alg: -65535,
  },
  ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW: {
    kty: 2,
    alg: -35,
    crv: 2,
  },
  ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW: {
    kty: 2,
    alg: -36,
    crv: 3,
  },
  ALG_SIGN_ED25519_EDDSA_SHA256_RAW: {
    kty: 1,
    alg: -8,
    crv: 6,
  },
};

let COSE_TO_FIDO_ALG = {
  "kty:2,alg:-7,crv:1": "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW",
  "kty:2,alg:-7,crv:8": "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW",
  "kty:3,alg:-37": "ALG_SIGN_RSASSA_PSS_SHA256_RAW",
  "kty:3,alg:-38": "ALG_SIGN_RSASSA_PSS_SHA384_RAW",
  "kty:3,alg:-39": "ALG_SIGN_RSASSA_PSS_SHA512_RAW",
  "kty:3,alg:-257": "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW",
  "kty:3,alg:-258": "ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW",
  "kty:3,alg:-259": "ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW",
  "kty:3,alg:-65535": "ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW",
  "kty:2,alg:-35,crv:2": "ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW",
  "kty:2,alg:-36,crv:3": "ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW",
  "kty:1,alg:-8,crv:6": "ALG_SIGN_ED25519_EDDSA_SHA256_RAW",
};

let TPM_MANUFACTURERS = {
  "id:414D4400": {
    name: "AMD",
    id: "AMD",
  },
  "id:41544D4C": {
    name: "Atmel",
    id: "ATML",
  },
  "id:4252434D": {
    name: "Broadcom",
    id: "BRCM",
  },
  "id:49424d00": {
    name: "IBM",
    id: "IBM",
  },
  "id:49465800": {
    name: "Infineon",
    id: "IFX",
  },
  "id:494E5443": {
    name: "Intel",
    id: "INTC",
  },
  "id:4C454E00": {
    name: "Lenovo",
    id: "LEN",
  },
  "id:4E534D20": {
    name: "National Semiconductor",
    id: "NSM",
  },
  "id:4E545A00": {
    name: "Nationz",
    id: "NTZ",
  },
  "id:4E544300": {
    name: "Nuvoton Technology",
    id: "NTC",
  },
  "id:51434F4D": {
    name: "Qualcomm",
    id: "QCOM",
  },
  "id:534D5343": {
    name: "SMSC",
    id: "SMSC",
  },
  "id:53544D20": {
    name: "ST Microelectronics",
    id: "STM",
  },
  "id:534D534E": {
    name: "Samsung",
    id: "SMSN",
  },
  "id:534E5300": {
    name: "Sinosun",
    id: "SNS",
  },
  "id:54584E00": {
    name: "Texas Instruments",
    id: "TXN",
  },
  "id:57454300": {
    name: "Winbond",
    id: "WEC",
  },
  "id:524F4343": {
    name: "Fuzhouk Rockchip",
    id: "ROCC",
  },
};

const parsePubArea = (pubAreaBuffer) => {
  let typeBuffer = pubAreaBuffer.slice(0, 2);
  let type = TPM_ALG[typeBuffer.readUInt16BE(0)];
  pubAreaBuffer = pubAreaBuffer.slice(2);

  let nameAlgBuffer = pubAreaBuffer.slice(0, 2);
  let nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];
  pubAreaBuffer = pubAreaBuffer.slice(2);

  let objectAttributesBuffer = pubAreaBuffer.slice(0, 4);
  let objectAttributesInt = objectAttributesBuffer.readUInt32BE(0);
  let objectAttributes = {
    fixedTPM: !!(objectAttributesInt & 1),
    stClear: !!(objectAttributesInt & 2),
    fixedParent: !!(objectAttributesInt & 8),
    sensitiveDataOrigin: !!(objectAttributesInt & 16),
    userWithAuth: !!(objectAttributesInt & 32),
    adminWithPolicy: !!(objectAttributesInt & 64),
    noDA: !!(objectAttributesInt & 512),
    encryptedDuplication: !!(objectAttributesInt & 1024),
    restricted: !!(objectAttributesInt & 32768),
    decrypt: !!(objectAttributesInt & 65536),
    signORencrypt: !!(objectAttributesInt & 131072),
  };
  pubAreaBuffer = pubAreaBuffer.slice(4);

  let authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
  pubAreaBuffer = pubAreaBuffer.slice(2);
  let authPolicy = pubAreaBuffer.slice(0, authPolicyLength);
  pubAreaBuffer = pubAreaBuffer.slice(authPolicyLength);

  let parameters = undefined;
  if (type === "TPM_ALG_RSA") {
    parameters = {
      symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
      keyBits: pubAreaBuffer.slice(4, 6).readUInt16BE(0),
      exponent: pubAreaBuffer.slice(6, 10).readUInt32BE(0),
    };
    pubAreaBuffer = pubAreaBuffer.slice(10);
  } else if (type === "TPM_ALG_ECC") {
    parameters = {
      symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
      curveID: TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
      kdf: TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)],
    };
    pubAreaBuffer = pubAreaBuffer.slice(8);
  } else throw new Error(type + " is an unsupported type!");

  let uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
  pubAreaBuffer = pubAreaBuffer.slice(2);
  let unique = pubAreaBuffer.slice(0, uniqueLength);
  pubAreaBuffer = pubAreaBuffer.slice(uniqueLength);

  return {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    parameters,
    unique,
  };
};

let COSEKEYS = {
  kty: 1,
  alg: 3,
  crv: -1,
  x: -2,
  y: -3,
  n: -1,
  e: -2,
};

let COSEKTY = {
  OKP: 1,
  EC2: 2,
  RSA: 3,
};

let COSERSASCHEME = {
  "-3": "pss-sha256",
  "-39": "pss-sha512",
  "-38": "pss-sha384",
  "-65535": "pkcs1-sha1",
  "-257": "pkcs1-sha256",
  "-258": "pkcs1-sha384",
  "-259": "pkcs1-sha512",
};

var COSECRV = {
  1: "p256",
  2: "p384",
  3: "p521",
};

var COSEALGHASH = {
  "-257": "sha256",
  "-258": "sha384",
  "-259": "sha512",
  "-65535": "sha1",
  "-39": "sha512",
  "-38": "sha384",
  "-37": "sha256",
  "-260": "sha256",
  "-261": "sha512",
  "-7": "sha256",
  "-36": "sha512",
};

let hash = (alg, message) => {
  return crypto.createHash(alg).update(message).digest();
};

let base64ToPem = (b64cert) => {
  let pemcert = "";
  for (let i = 0; i < b64cert.length; i += 64) pemcert += b64cert.slice(i, i + 64) + "\n";

  return "-----BEGIN CERTIFICATE-----\n" + pemcert + "-----END CERTIFICATE-----";
};

var getCertificateInfo = (certificate) => {
  let subjectCert = new jsrsasign.X509();
  subjectCert.readCertPEM(certificate);

  let subjectString = subjectCert.getSubjectString();
  let subjectParts = subjectString.slice(1).split("/");

  let subject = {};
  for (let field of subjectParts) {
    let kv = field.split("=");
    subject[kv[0]] = kv[1];
  }

  let version = subjectCert.version;
  let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

  return {
    subject,
    version,
    basicConstraintsCA,
  };
};

var parseAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  let flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  let flagsInt = flagsBuf[0];
  let flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt,
  };

  let counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  let counter = counterBuf.readUInt32BE(0);

  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;

  if (flags.at) {
    aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }

  return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey };
};

var getCertificateInfo = (certificate) => {
  let subjectCert = new jsrsasign.X509();
  subjectCert.readCertPEM(certificate);

  let subjectString = subjectCert.getSubjectString();
  let subjectParts = subjectString.slice(1).split("/");

  let subject = {};
  for (let field of subjectParts) {
    let kv = field.split("=");
    subject[kv[0]] = kv[1];
  }

  let version = subjectCert.version;
  let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

  return {
    subject,
    version,
    basicConstraintsCA,
  };
};

const parseCertInfo = (certInfoBuffer) => {
  let magicBuffer = certInfoBuffer.slice(0, 4);
  let magic = magicBuffer.readUInt32BE(0);
  certInfoBuffer = certInfoBuffer.slice(4);

  let typeBuffer = certInfoBuffer.slice(0, 2);
  let type = TPM_ST[typeBuffer.readUInt16BE(0)];
  certInfoBuffer = certInfoBuffer.slice(2);

  let qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
  certInfoBuffer = certInfoBuffer.slice(2);
  let qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength);
  certInfoBuffer = certInfoBuffer.slice(qualifiedSignerLength);

  let extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
  certInfoBuffer = certInfoBuffer.slice(2);
  let extraData = certInfoBuffer.slice(0, extraDataLength);
  certInfoBuffer = certInfoBuffer.slice(extraDataLength);

  let clockInfo = {
    clock: certInfoBuffer.slice(0, 8),
    resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
    restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
    safe: !!certInfoBuffer[16],
  };
  certInfoBuffer = certInfoBuffer.slice(17);

  let firmwareVersion = certInfoBuffer.slice(0, 8);
  certInfoBuffer = certInfoBuffer.slice(8);

  let attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
  let attestedNameBuffer = certInfoBuffer.slice(2, attestedNameBufferLength + 2);
  certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength);

  let attestedQualifiedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
  let attestedQualifiedNameBuffer = certInfoBuffer.slice(2, attestedQualifiedNameBufferLength + 2);
  certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength);

  let attested = {
    nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
    name: attestedNameBuffer,
    qualifiedName: attestedQualifiedNameBuffer,
  };

  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo,
    firmwareVersion,
    attested,
  };
};

// let verifyPackedAttestation = (webAuthnResponse) => {
//   // TODO: check challenge
//   // TODO: check origin
//   const rpID = 'stark-citadel-03331.herokuapp.com'
//   let clientDataHash = hash('sha256', webAuthnResponse.response.clientDataJSON)
//   let rpIdHash = hash('sha256', Buffer.from(rpID, 'utf-8'))
//   let attestationStruct = cbor.decodeAllSync(webAuthnResponse.response.attestationObject)[0]
//   console.log('attestationstruct', attestationStruct)
//   let certInfo = parseCertInfo(attestationStruct.attStmt.certInfo)
//   console.log('certInfo', certInfo)
//   let authDataStruct = parseAuthData(attestationStruct.authData)
//   console.log('rpIDHash', rpIdHash)
//   console.log('authdatastruct', authDataStruct)

//   let pubArea = parsePubArea(attestationStruct.attStmt.pubArea)
//   console.log('pubArea', pubArea)
//   // check if rpIDHash is the same
//   console.log('bufferSame?', rpIdHash.toString('hex') === authDataStruct.rpIdHash.toString('hex'))
//   // get pub key
//   let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
//   console.log('pubkeycose', pubKeyCose)
//   if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
//     // TODO: implement
//   } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
//     let rsaPubKey = {
//       n: new BN(Buffer.from(pubKeyCose.get(COSEKEYS.n))),
//       e: new BN(Buffer.from(pubKeyCose.get(COSEKEYS.e)))
//     }
//     console.log('rsa', rsaPubKey)
//     let dataToSign = Buffer.concat([attestationStruct.authData, clientDataHash])
//     console.log('datatosign', dataToSign)
//     console.log('alg' , attestationStruct.attStmt.alg)
//     let dataHash = hash(COSEALGHASH[attestationStruct.attStmt.alg], dataToSign)
//     let certBytes = attestationStruct.attStmt.x5c[0]
//     console.log('certBytes', certBytes.toString('utf-8'))
//     let publicKey = forge.asn1.fromDer(certBytes)
//     console.log(publicKey)

//     // let subjectCert = new jsrsasign.X509();
//     // subjectCert.readCertHex(certBytes.toString('hex'))
//     let sigAlg = COSERSASCHEME[attestationStruct.attStmt.alg]
//     console.log('here')
//     // TODO: stopped here
//   } else {
//     throw new Error('WHAT')
//   }
// }

// let verifyPackedAttestation = (webAuthnResponse) => {
//   let attestationBuffer = webAuthnResponse.response.attestationObject
//   let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

//   let authDataStruct = parseAuthData(attestationStruct.authData);

//   let clientDataHashBuf   = hash('sha256', webAuthnResponse.response.clientDataJSON);
//   let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);

//   let signatureBuffer     = attestationStruct.attStmt.sig
//   let signatureIsValid    = false;

//   if(attestationStruct.attStmt.x5c) {
//   /* ----- Verify FULL attestation ----- */
//       let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
//       let certInfo = getCertificateInfo(leafCert);
//       console.log('leafCert', leafCert)
//       console.log('certInfo', certInfo)

//       if(certInfo.subject.OU !== 'Authenticator Attestation')
//           throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

//       if(!certInfo.subject.CN)
//           throw new Error('Batch certificate CN MUST no be empty!');

//       if(!certInfo.subject.O)
//           throw new Error('Batch certificate CN MUST no be empty!');

//       if(!certInfo.subject.C || certInfo.subject.C.length !== 2)
//           throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');

//       if(certInfo.basicConstraintsCA)
//           throw new Error('Batch certificate basic constraints CA MUST be false!');

//       if(certInfo.version !== 3)
//           throw new Error('Batch certificate version MUST be 3(ASN1 2)!');

//       signatureIsValid = crypto.createVerify('sha256')
//           .update(signatureBaseBuffer)
//           .verify(leafCert, signatureBuffer);
//   /* ----- Verify FULL attestation ENDS ----- */
//   } else if(attestationStruct.attStmt.ecdaaKeyId) {
//       throw new Error('ECDAA IS NOT SUPPORTED YET!');
//   } else {
//   /* ----- Verify SURROGATE attestation ----- */
//       let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
//       let hashAlg    = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
//       if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
//           let x = pubKeyCose.get(COSEKEYS.x);
//           let y = pubKeyCose.get(COSEKEYS.y);

//           let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

//           let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

//           let ec  = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
//           let key = ec.keyFromPublic(ansiKey);

//           signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
//       } else if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
//           let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

//           let key = new NodeRSA(undefined, { signingScheme });
//           key.importKey({
//               n: pubKeyCose.get(COSEKEYS.n),
//               e: 65537,
//           }, 'components-public');

//           signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer)
//       } else if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
//           let x = pubKeyCose.get(COSEKEYS.x);
//           let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

//           let key = new elliptic.eddsa('ed25519');
//           key.keyFromPublic(x)

//           signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
//       }
//   /* ----- Verify SURROGATE attestation ENDS ----- */
//   }

//   if(!signatureIsValid)
//       throw new Error('Failed to verify the signature!');

//   return true
// }

// let verifyPackedAttestation = (webAuthnResponse) => {
//   let attestationBuffer = webAuthnResponse.response.attestationObject;
//   let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
//   console.log('ATTESTATIONSTRUCT', attestationStruct)

//   let authDataStruct = parseAuthData(attestationStruct.authData);
//   console.log('AUTHDATASTRUCT', authDataStruct)

//   let clientDataHashBuf = hash("sha256", webAuthnResponse.response.clientDataJSON);
//   let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
//   console.log(attestationStruct, attestationStruct.authData);

//   let signatureBuffer = attestationStruct.attStmt.sig;
//   let signatureIsValid = false;
//   /* ----- Verify SURROGATE attestation ----- */
//   let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
//   console.log('PUBKEYCOSE', pubKeyCose)

//   // console.log('x5c', attestationStruct)
//   let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
//   if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
//     let x = pubKeyCose.get(COSEKEYS.x);
//     let y = pubKeyCose.get(COSEKEYS.y);

//     let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

//     let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

//     let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
//     let key = ec.keyFromPublic(ansiKey);

//     signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
//   } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
//     console.log('IM HERE', pubKeyCose.get(3))
//     console.log('HOW BIG IS N', pubKeyCose.get(COSEKEYS.n).toString('base64'))
//     let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];
//     // let verify = crypto.createVerify('RSA-SHA256')
//     // verify.update(attestationStruct.authData)
//     // verify.update(clientDataHashBuf)
//     let key = new NodeRSA(undefined, { signingScheme });
//     key.importKey({
//       n: pubKeyCose.get(COSEKEYS.n),
//       e: 65537,
//     }, 'components-public');
//     // let verified = verify.verify(key)
//     signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer);
//     console.log(signatureIsValid);
//   }
//   // } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
//   //   let x = pubKeyCose.get(COSEKEYS.x);
//   //   let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

//   //   let key = new elliptic.eddsa("ed25519");
//   //   key.keyFromPublic(x);

//   //   signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
//   // }
//   /* ----- Verify SURROGATE attestation ENDS ----- */

//   if (!signatureIsValid) throw new Error("Failed to verify the signature!");

//   return true;
// };

// let packedFullAttestationWebAuthnSample = {
//     id: "5rtMn-_uETuyln-6lT8EUr8CYZODbNbnD0sFTVrpr+Q",
//     rawId: "5rtMn+/uETuyln+6lT8EUr8CYZODbNbnD0sFTVrpr+Q=",
//     "response": {
//         "clientDataJSON": 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==',
//         "attestationObject": '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'
//     },
//     type: 'public-key'
// }

// let packedSurrogateAttestationWebAuthnSample = {
//     "id": "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
//     "rawId": "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
//     "response": {
//         "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE",
//         "clientDataJSON": "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
//     },
//     "type": "public-key"
// }

// console.log(verifyPackedAttestation(packedFullAttestationWebAuthnSample))

// obj
// var obj = {
//   id: "ilad383BXwVlpaGUJPgYprF0cJXOuYMEMseguuA1Ap",
//   rawId: Buffer.from('7VlyAJbmGQURW94h2CwynrkcegOip2pmQQfQat/lveE=', 'base64'),
//   response: {
//     // attestationObject: Buffer.from('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', 'base64'),
//     // attestationObject:
//     //   Buffer.from('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', 'base64'),
//     attestationObject: Buffer.from('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', 'base64'),
//     clientDataJSON:
//       Buffer.from('eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==', 'base64')
//   },
//   type: 'public-key'
// };

// var obj = {
//   id: '68CJkByfQUuJQ8PXlYlmaJeEyAHI4FGIwqOSw1bETYw',
//   rawId: Buffer.from('68CJkByfQUuJQ8PXlYlmaJeEyAHI4FGIwqOSw1bETYw=', 'base64'),
//   response: {
//     attestationObject: Buffer.from('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', 'base64'),
//     clientDataJSON: Buffer.from('eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9zdGFyay1jaXRhZGVsLTAzMzMxLmhlcm9rdWFwcC5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==', 'base64'),
//   },
//   type: 'public-key'
// }

// console.log(verifyPackedAttestation(obj));

var attestationObj = {
  id: "ChM7ZGQNHRbMXMx8ybIRdm077xtXbJd-45HOo-J7jKE",
  rawId: Buffer.from("ChM7ZGQNHRbMXMx8ybIRdm077xtXbJd+45HOo+J7jKE=", 'base64'),
  type: "public-key",
  response: {
    attestationObject:
      Buffer.from("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", 'base64'),
    clientDataJSON:
      Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9zdGFyay1jaXRhZGVsLTAzMzMxLmhlcm9rdWFwcC5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9", 'base64')
  },
};

var assertionObj = {
  id: "Fak2Wf9AIqpJFEvgXNCJy9KVdHobW_hez14PuRXDLBY",
  rawId: Buffer.from("Fak2Wf9AIqpJFEvgXNCJy9KVdHobW/hez14PuRXDLBY=", "base64"),
  response: {
    authenticatorData: Buffer.from("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAg==", "base64"),
    clientDataJSON: Buffer.from(
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",
      "base64"
    ),
    signature: Buffer.from(
      "hrARhi16sjjISf9MhgW6fvBrDL3jIEXhRmzvFjVfK9mJEgNeikJ3R+4PpJ8OB9vexPpt/OX6lOJczTLFOQxxB38xaup8npa730Y1hURuTyFODnYuXMECNtf23Zv8f4rN9AfWaq10oH7YFok8YLHMGGABAE/pRFbXOgr0tp9H6Y0B7Xmr02yuHR3uDLg2g3Wq/BN5XmVTeMfnN5GCyNnJ8Drvg4F/2w1Q92moj+t0gDMgmd24pmdRINHAxJdIm0rnHWedHl/915lWhansoS8dmKZO9q8sSlQ6xg67emuDlzygCEaENKiU30fetJgXlFPpkU/sRM9BMsGBcTepP5RqEA==",
      "base64"
    ),
    userHandle: Buffer.from("VVpTTDg1VDlBRkM=", "base64"),
  },
  type: "public-key",
};
