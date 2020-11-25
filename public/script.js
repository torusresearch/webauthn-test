window.Buffer = require("buffer").Buffer;
(async function () {
  console.log("HAOSHOFAHO");
  const publicKeyCredentialCreationOptions = {
    challenge: Uint8Array.from("randomStringFromServer", (c) => c.charCodeAt(0)),
    rp: {
      name: "STARKCITY",
      id: "stark-citadel-03331.herokuapp.com",
    },
    user: {
      id: Uint8Array.from("anonymous", (c) => c.charCodeAt(0)),
      name: "created at " + new Date(Date.now()).toGMTString(),
      displayName: "anonymous",
    },
    pubKeyCredParams: [{ alg: -257, type: "public-key" }],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: true,
      userVerification: "discouraged",
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
  try {
    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    });
    console.log(credential);
  } catch (e) {
    console.error(e);
  }
  try {
    const login = await navigator.credentials.get({
      publicKey: {
        challenge: Uint8Array.from("randomStringFromServer", (c) => c.charCodeAt(0)),
        //   allowCredentials: [{ type: "public-key", id: Uint8Array.from("anonymous", (c) => c.charCodeAt(0)) }],
        timeout: 60000,
      },
    });
    console.log(login);
  } catch (e) {
    console.error(e);
  }
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
