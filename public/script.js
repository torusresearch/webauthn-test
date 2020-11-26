window.Buffer = require("buffer").Buffer;
function toArrayBuffer(buf) {
  var ab = new ArrayBuffer(buf.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}

(async function () {
  console.log("HAOSHOFAHO");
  let pubKeyCredParams;

  if (navigator.appVersion.includes("Windows")) {
    pubKeyCredParams = [{ alg: -257, type: "public-key" }];
  } else {
    pubKeyCredParams = [{ alg: -7, type: "public-key" }];
  }

  const publicKeyCredentialCreationOptions = {
    challenge: Uint8Array.from("randomStringFromServer", (c) => c.charCodeAt(0)),
    rp: {
      name: "STARKCITY",
      id: "stark-citadel-03331.herokuapp.com",
    },
    user: {
      id: Uint8Array.from(new Date(Date.now()).toGMTString(), (c) => c.charCodeAt(0)),
      name: "created at " + new Date(Date.now()).toGMTString(),
      displayName: "anonymous",
    },
    pubKeyCredParams,
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: true,
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "direct",
  };

  // function subAlg(alg) {
  //     publicKeyCredentialCreationOptions.pubKeyCredParams[0].alg = alg
  //     return publicKeyCredentialCreationOptions
  // }

  await new Promise((resolve, reject) => {
    setTimeout(resolve, 1000);
  });

  // navigator.credentials.get({
  //     mediation: 'required',
  //     publicKey: {
  //         challenge: Uint8Array.from(
  //             "randomStringFromServer", c => c.charCodeAt(0)),
  //         allowCredentials: [],
  //         timeout: 60000
  //     }
  // })

  // for (var algId = -65535; algId <= 65535; algId++) {
  //     try {
  //         document.getElementById("text").textContent = algId.toString()
  // console.log(algId + " passed")
  window.register = async function () {
    try {
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
      });
      console.log(credential);
      if (navigator.appVersion.includes("Android")) {
        let fed = await navigator.credentials.create({
          federated: {
            id: 'WebAuthn',
            provider: window.location.origin,
            iconURL: 'https://' + Buffer.from(credential.rawId).toString('hex') + '.com'
          }
        });
        await navigator.credentials.store(fed)
      }
    } catch (e) {
      console.error(e);
    }
  };

  window.login = async function () {
    try {
      let allowCredentials = [];
      if (navigator.appVersion.includes("Android")) {
        const creds = await navigator.credentials.get({federated: { id:'WebAuthn', providers: [window.location.origin] } });
        allowCredentials.push({ type: "public-key", id: toArrayBuffer(Buffer.from(creds.iconURL.replace('https://', '').replace('.com', ''), "hex")) });
      }
      const login = await navigator.credentials.get({
        publicKey: {
          challenge: Uint8Array.from("randomStringFromServer", (c) => c.charCodeAt(0)),
          //   allowCredentials: [{ type: "public-key", id: Uint8Array.from("anonymous", (c) => c.charCodeAt(0)) }],
          allowCredentials,
          timeout: 60000,
          userVerification: "discouraged",
        },
      });
      console.log(login);
    } catch (e) {
      console.error(e);
    }
  };
  // const assertion = await navigator.credentials.get({
  //     publicKeyCredentialCreationOptions
  // })
  // const assertion = await navigator.credentials.get(
  //     {
  //         //specifies which credential IDs are allowed to authenticate the user
  //         //if empty, any credential can authenticate the users
  //         // allowCredentials: [{
  //         //     type: "public-key",
  //         // }],
  //         // authenticatorSelection: {
  //         //     authenticatorAttachment: "platform",
  //         //     requireResidentKey: true,
  //         //     userVerification: "required"
  //         // },
  //         //an opaque challenge that the authenticator signs over
  //         challenge: Uint8Array.from(
  //             "randomStringFromServer", c => c.charCodeAt(0)),
  //         //Since Edge shows UI, it is better to select larger timeout values
  //         timeout: 50000
  //     }
  // );
  // console.log(assertion)
  //     } catch (err) {
  //         console.error(err)
  //     }
  // }
})();
