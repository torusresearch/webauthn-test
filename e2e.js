// User registration
// we just need to get credID, save pubkey

const crypto = require("crypto");
var BN = require("bn.js");
const cbor = require("cbor");
var credIDPubKeyMap = {};

// fixtures
var yubikeyRegister = {
  id: "lZqWGa_Pr8FgQa8iC5OjKNKuKk9b5VEP3GcG9JjttMVsPCNyCRirlb7EnTSKvh42qG47IpquG9GldzdQB89IBQ",
  rawId: Buffer.from("lZqWGa/Pr8FgQa8iC5OjKNKuKk9b5VEP3GcG9JjttMVsPCNyCRirlb7EnTSKvh42qG47IpquG9GldzdQB89IBQ==", "base64"),
  type: "public-key",
  response: {
    attestationObject: Buffer.from(
      "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEfYmzMRzWBsEEuoVezAH3IegPK1u6WwZpNvAaG905OQdBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQJWalhmvz6/BYEGvIguToyjSripPW+VRD9xnBvSY7bTFbDwjcgkYq5W+xJ00ir4eNqhuOyKarhvRpXc3UAfPSAWlAQIDJiABIVggXp8VJfJP6BgeNH06z+OT1xLbE1AEO4tbmbTvVsdEKK0iWCC5HRC7oIKYNq0XNOG9TEmtN9yVSRMilEJvGgY2hQm5cA==",
      "base64"
    ),
    clientDataJSON: Buffer.from(
      "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9zdGFyay1jaXRhZGVsLTAzMzMxLmhlcm9rdWFwcC5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
      "base64"
    ),
  },
};
var yubikeyLogin = {
  id: "lZqWGa_Pr8FgQa8iC5OjKNKuKk9b5VEP3GcG9JjttMVsPCNyCRirlb7EnTSKvh42qG47IpquG9GldzdQB89IBQ",
  rawId: Buffer.from("lZqWGa/Pr8FgQa8iC5OjKNKuKk9b5VEP3GcG9JjttMVsPCNyCRirlb7EnTSKvh42qG47IpquG9GldzdQB89IBQ==", "base64"),
  type: "public-key",
  response: {
    authenticatorData: Buffer.from("fYmzMRzWBsEEuoVezAH3IegPK1u6WwZpNvAaG905OQcBAAAAAg==", "base64"),
    clientDataJSON: Buffer.from(
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9zdGFyay1jaXRhZGVsLTAzMzMxLmhlcm9rdWFwcC5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
      "base64"
    ),
    signature: Buffer.from("MEUCIQD4gaWCuhnlPCUc8o7osZ+9mC4Eo/5atwCcxgoDZwk5SQIgTAMyQGYPmsyGkesa57LdETZw1SUZ4C/2/9+uMMYN4CQ=", "base64"),
    userHandle: "",
  },
};
var windowsHelloRegister = {
  id: "ChM7ZGQNHRbMXMx8ybIRdm077xtXbJd-45HOo-J7jKE",
  rawId: Buffer.from("ChM7ZGQNHRbMXMx8ybIRdm077xtXbJd+45HOo+J7jKE=", "base64"),
  type: "public-key",
  response: {
    attestationObject: Buffer.from(
      "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn//mNzaWdZAQBXPl7zDwIAVClInBFUb4Mk+AQ1oRvek16mlVAAmak4MV5gcmYfIbHvegk8bvarUAZP39W/ln99YER8jwMooNsBO5Q9bYXQ59UEJkEC7MwZnQjVbgkCkIv6i9jJYSE9zQy1sMlVDMpVmZltb1XP/tpB2EoB++1AIPnCrq7frBCftz2fL8dyuWef0sCmEqNKkBXfv2qzh9/5niCf57FV27OD9xD0dUY/fhfipQgLszq1KwRLvw+bFYVO5u/c3SFTFXh2irA6z0uJBva8NI1B8jTQ9WfTbTE3Y/r3neIfggKyA0sSwFlmgXQwP+FxUlKl57/UAuF8NN/O6WmQvss8EvwyY3ZlcmMyLjBjeDVjglkFxDCCBcAwggOooAMCAQICEDkoA564Y0gwpXKui7RM6egwDQYJKoZIhvcNAQELBQAwQTE/MD0GA1UEAxM2TkNVLVNUTS1LRVlJRC1GQjE3RDcwRDczNDg3MEU5MTlDNEU4RTYwMzk3NUU2NjRFMEU0M0RFMB4XDTIwMTExMDA3MTYzN1oXDTI1MDYxODE5MTYzNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALBBLLaLZqpR6iaEXommdzktxCUDoW4CCAh8YGRXPaapkkJfJe0Fv4w4M8tVn9vN/GedrW/lQPpxAef+igK0S/z3Z0W9wLRw7LgEbx2e1UuUbcHwG9jyptc07J5ZYBbUTTOJ6lLQS9L2zlZBzu/MJqxiQ6IXpMxTLznkSvZKnJ/Uj0EXw/GOG8hD014A28HrDU5/D6IXZTl5WWwskz5DPTOCLbuIFWRfJP5DcuWySfFN3229HOI+Q0QL/butGWGI7U815rsQ4tdQ+8yDsuXCQHRdxw0vyNHPPsU7G8e8/DfXAetsskPQvwryeUC3pBEapefF+QOXDrA8lmghACCWwDsCAwEAAaOCAfMwggHvMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB/wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFkGA1UdEQEB/wRPME2kSzBJMRYwFAYFZ4EFAgEMC2lkOjUzNTQ0RDIwMRcwFQYFZ4EFAgIMDFNUMzNIVFBIQUhENDEWMBQGBWeBBQIDDAtpZDowMDAxMDEwMTAfBgNVHSMEGDAWgBRsY8IPY1tegaOhw5qmjmaoh5cEIjAdBgNVHQ4EFgQUvztSr2BXSKAf5fkifqYeqavPYp4wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1zdG0ta2V5aWQtZmIxN2Q3MGQ3MzQ4NzBlOTE5YzRlOGU2MDM5NzVlNjY0ZTBlNDNkZS8xNTk2YWYyYy0yZGRiLTQ2ZDctYmUzYi01NDAwODU5YmYzMjAuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAOvgIim0NdTK2KuEFRoGHankHzP3P+8VZeOsdB7DifPgQc3C8psNbJVSMdGi7BfzbmcnokHya6hqUFHnYSLL8TEAG+V2pBrCNBFS7FYBcpB4gQFhLqx8usbvoiT/2lX8qQtjEPENkfDUBZmIU1BhFD+wQn2SUIiM1TRVlQCl2glQZbOfKv6eDWua4ja7O3m8tX8C1QX1FY0XMTvqRTjs0psDSWdTcAxwa82G/iNfQta0eHY9FFenbUQ8SCqf90eac+xA4WG5wTwHHAsdOFRrzzgqxXqtKo1vtog4TnB2aPR1xdQGDcBEdAlblOH22vKF9YwaKSNOY/Vvzn+jA+sw5WTJT8ACQlVmEYA4VQFAthupebiQaxck3nA51jQpXadScnChc5Fiz8qaJHTefzpnGqDBrhcVy85q7CvtmcM9IaQJVFwEfQ6g9Qbf2yITgGTl34gzMbhHBNXGBNgcl/7qVqgUyA/mCS/QPEd87nKnyP43+ZXFwqfZwOsI2L+/CBJvqEvBGp2mC4DBf6XZrVD4bbAiyHgkAqnf0iMSXpof7xJyJ4nonzn1oOhBdf+hI3zcmOYaMnfiZ4OHZD9V6DYmsue3TINCpN4ADLcKGGmxPmyLU2EReWBM8wj6hVFCA/dLVFfExZMbUY5DMjjw5v/43RA/VSEeEC1Lz9WU6fUnnoulkG7zCCBuswggTToAMCAQICEzMAAALnYq6+Ce5vs0UAAAAAAucwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMDA2MTgxOTE2MzZaFw0yNTA2MTgxOTE2MzZaMEExPzA9BgNVBAMTNk5DVS1TVE0tS0VZSUQtRkIxN0Q3MEQ3MzQ4NzBFOTE5QzRFOEU2MDM5NzVFNjY0RTBFNDNERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO6KcW8+0Y0AYoVk0B8y0qiCtTDeCzEvpSOUyhAcI15PkInqi+LkcGem/VzipVTwitth7JLHgrvn97+WQDNX2+I586LW25VIfl5lQ16I6SShtU6fnpaqcWrd8IDQRaPXgZFhi4ohbd2QvE9HfL8WAThx/IYLyEnEwW6nRt0Pb0gilUzEDAteAgXVakNe69hbjr6YR6zQZHxrxPUyPEXoXRU6j8szdRkiOvXnfQqjDtZjn6R76tZpCXovQlZzjgaG8AoMlYk9j/6Hc3WdGxPjK+5PrN8rXqhm9rJ1ELf0swg56FrxXrejgLY130/P4zRG3VGkXzL/sIffoVWtO3HkGdx6yMKQUrI9xu1Gapzo2uC7pYApybwwo1sJVaEM2qRKvKEsKfFybdtGyN1h5Hy9PlePIggiEsGZbr8vJTg045rW53qivNaBwnVS8Ojo6H0Su40yclafg7iFttKOyhvKn/OHKg3XDiROxxZtkZgjYv7plR4ZuFC2GIYSQ/4ZGFuXli1rkxAIhcCH/BwNx1J1y9ksT96fGGTnZ6O4bN7evejNkB+gZeqru+8xz4BjRX86+pzYoXMQrUFQYoUbH+WgBdkPbfoNX3+4Ax9HGY8GZeihM1XDowi5r1CObIoRIzs1oywg3gWxhVgyqDJEDpBEvIz3N9cJC/BdHdwZuEIusHADAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRsY8IPY1tegaOhw5qmjmaoh5cEIjAfBgNVHSMEGDAWgBR6jArOL0hiF+KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAEgzeDEFzkmd33cIyEWCxPyrDIwfU6p6XiKXlAikxU71B5x/6vQR+V2LajjF+F4W/zeqsGDjaQyvDeVBu2JCmqiBGdfEp83qP9kZyuLHadA7e1vGBcPMDTzI1BMKfL14HpZ2yRjT50O77C+kvOsSBKT8s2v7QXaxkdpZCwVDlDx03JGcFBmWt+X0zTWARSzEhLX4dzaR8kJervMiX/6MsIbpiO6/VSoMy6EGNc/Y+LM86VWQ3u3vAHp9ugNe6QODWE8z37Jtrzw8mHZaefx89Qie6J8Z91vYQCWsMXrNVEUdYpkF1vWznPPgprMTuniS/E/0zVm6Jk7usQ1Dsd3lwxyJLRQDT6nt4vIiZ8tRWp6eK9yjJQfFq++Ftre2zCaPb4ce3oDIHiBy+qBPoYQqkBjXnC0dQ6kVa6LKLkwNHKd4yz3nLUQNS6mnX3xExkuyliIQI+GL7RIaJ9FZMXhWEQofXjlNk5fEMPtgU+AxpyxqctllzgZKc8Dxc6togAm2mgQMDrRBknLk4VY8JVrHK8IcMGldpW2KL3llkBGVbfErEZ8sinNewrTtsuEE4x/bWRACZjZEM2Z5+aovejxgtBVVQANNVefKHHK31r3o1BssiGw+jKh+xvmhXqb47Vh2q2GgCStkS1Ya+U7pzNIfWdwuuLH1mNGrTbuHSFDYy8GkZ3B1YkFyZWFZATYAAQALAAYEcgAgnf/L82w4OuaZ+5ho3G3LidcVOIS+KAOSLBJBWL+tIq4AEAAQCAAAAAAAAQDoQ8RU2RH4j9o4/fvT09qCzJY3RKpr0m+hwMQU/BLL7ug4X6b10dzXrI+nCSCSHe5dh6yxfFhQkMcIBXdQ0xm6O3/YKZlyQOU5HZKqGRDmSOAlsqnvDLrtbkTdzMqIXtw7n9HRTn/JiFRmozWNZWcd1qIFULqrfBrYVUCbLZryP4mV4bByH4G6m3BsTDyKYMs9G+Nkww8t/OKfLYermLMiBI872HIHvNsFFQbJ10+zD32rjB/bhbGqhnNhBh6orbzFT96o5JwZBt95gvHxudqViyiHVrvqbLU8b9FpNsAbMTCZOI/akStGVeTAYMptIk7OcyQkdotps2tfdErm0UpZaGNlcnRJbmZvWKH/VENHgBcAIgALKcpXud5m0Skz5xlbsPTiVK4T7BtPe+WQYUB5JDIYNSwAFIDTOkrZ7lkrwaOoX8qCH5ewFuz5AAAAAAbHhYbe6YneK9jD8AEX8POGXjtUcwAiAAszlEBpgTeHKyexjU39gvYyAMrSb/6a76p36z3TlrfWmgAiAAuq3Po9HC3mV6k/F/5EVHrBWAJGHgnq88T+cHzsUDmnAWhhdXRoRGF0YVkBZ32JszEc1gbBBLqFXswB9yHoDytbulsGaTbwGhvdOTkHRQAAAAAImHBYytxLgbbhMN5Q3L6WACAKEztkZA0dFsxczHzJshF2bTvvG1dsl37jkc6j4nuMoaQBAwM5AQAgWQEA6EPEVNkR+I/aOP3709PagsyWN0Sqa9JvocDEFPwSy+7oOF+m9dHc16yPpwkgkh3uXYessXxYUJDHCAV3UNMZujt/2CmZckDlOR2SqhkQ5kjgJbKp7wy67W5E3czKiF7cO5/R0U5/yYhUZqM1jWVnHdaiBVC6q3wa2FVAmy2a8j+JleGwch+BuptwbEw8imDLPRvjZMMPLfziny2Hq5izIgSPO9hyB7zbBRUGyddPsw99q4wf24WxqoZzYQYeqK28xU/eqOScGQbfeYLx8bnalYsoh1a76my1PG/RaTbAGzEwmTiP2pErRlXkwGDKbSJOznMkJHaLabNrX3RK5tFKWSFDAQAB",
      "base64"
    ),
    clientDataJSON: Buffer.from(
      "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9zdGFyay1jaXRhZGVsLTAzMzMxLmhlcm9rdWFwcC5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
      "base64"
    ),
  },
};

var windowsHelloLogin = {
  id: "ChM7ZGQNHRbMXMx8ybIRdm077xtXbJd-45HOo-J7jKE",
  rawId: Buffer.from("ChM7ZGQNHRbMXMx8ybIRdm077xtXbJd+45HOo+J7jKE=", "base64"),
  type: "public-key",
  response: {
    authenticatorData: Buffer.from("fYmzMRzWBsEEuoVezAH3IegPK1u6WwZpNvAaG905OQcFAAAAAQ==", "base64"),
    clientDataJSON: Buffer.from(
      "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY21GdVpHOXRVM1J5YVc1blJuSnZiVk5sY25abGNnIiwib3JpZ2luIjoiaHR0cHM6Ly9zdGFyay1jaXRhZGVsLTAzMzMxLmhlcm9rdWFwcC5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==",
      "base64"
    ),
    signature:
      ("uint/JPngUzdEX+uBSNFwqNFeEIGXMEmVQr36KiPZg1rGwSxTIJAsBTtxyd0iGh0dtb1IQhogfCS/a5NwMp0Yf+WnDlzPKttKN70ivFnQABBJljum3oCPdlN7Y6rP6JRgXpRb0rjpGegBJfO1YtrPk4+zJcQ+xLq++BPpoJ+1ZK1eNAiSjq6tItCiGAmP1KiwolG7mlBOCgZN1rpvrK6X0KFRoEm5pb48RTiNfIwqMpXDmAMVMxPO/w1yer+8Vkb1+//NWKeBVM+H0e20Ke6TBcYavRcSVnLt1gEpqqYzvdm8JUbgaMwuS+b4EJX0UeT2+7CVD3bRUquQvFJNfxjDA==",
      "base64"),
    userHandle: Buffer.from("TW9uLCAwNyBEZWMgMjAyMCAwNjo0OTo0NSBHTVQ=", "base64"),
  },
};

let hash = (alg, message) => {
  return crypto.createHash(alg).update(message).digest();
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
  EC2: 2,
  RSA: 3,
};

const domain = "stark-citadel-03331.herokuapp.com";
const rpIdHash = hash("sha256", Buffer.from(domain, "utf-8"));

function extractPubKey(attestationBuffer) {
  let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
  console.log("ATTESTATIONSTRUCT", attestationStruct);
  let authDataStruct = parseAuthData(attestationStruct.authData);
  console.log("AUTHDATASTRUCT", authDataStruct);
  if (rpIdHash.toString("hex") !== authDataStruct.rpIdHash.toString("hex")) {
    throw new Error("rpIdHash not equal");
  }
  let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
  if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
    // console.log(pubKeyCose.get(COSEKEYS.x));
    return {
      x: new BN(Buffer.from(pubKeyCose.get(COSEKEYS.x))),
      y: new BN(Buffer.from(pubKeyCose.get(COSEKEYS.y))),
      n: undefined,
      e: undefined,
    };
  } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
    return {
      x: undefined,
      y: undefined,
      n: new BN(Buffer.from(pubKeyCose.get(COSEKEYS.n))),
      e: new BN(Buffer.from(pubKeyCose.get(COSEKEYS.e))),
    };
  } else {
    throw new Error("unsupported key type");
  }
}

function registerPubKey(register) {
  // get public key from attestationObj
  credIDPubKeyMap[register.id] = extractPubKey(register.response.attestationObject);
  console.log(credIDPubKeyMap);
}

function webAuthnLogin(login) {
  const pubKey = credIDPubKeyMap[login.id]
  if (!pubKey) {
    throw new Error('not registered')
  }
  
}

registerPubKey(yubikeyRegister);
registerPubKey(windowsHelloRegister);
webAuthnLogin(yubikeyLogin)
webAuthnLogin(windowsHelloLogin)
