window.Buffer = require('buffer').Buffer

;(async function() {
    const publicKeyCredentialCreationOptions = {
        challenge: Uint8Array.from(
            "randomStringFromServer", c => c.charCodeAt(0)),
        rp: {
            name: "Localhost",
            id: "localhost",
        },
        user: {
            id: Uint8Array.from(
                "UZSL85T9AFC", c => c.charCodeAt(0)),
            name: "anonymous",
            displayName: "Anon Ymous",
        },
        pubKeyCredParams: [{alg: -257, type: "public-key"}],
        authenticatorSelection: {
            authenticatorAttachment: "platform",
            requireResidentKey: true,
            userVerification: "required"
        },
        timeout: 60000,
        attestation: "direct"
    };
    // function subAlg(alg) {
    //     publicKeyCredentialCreationOptions.pubKeyCredParams[0].alg = alg
    //     return publicKeyCredentialCreationOptions
    // }

    await new Promise((resolve, reject) => {
        setTimeout(resolve, 1000)
    })

    // for (var algId = -65535; algId <= 65535; algId++) {
    //     try {
    //         document.getElementById("text").textContent = algId.toString()
    // console.log(algId + " passed")
    // const credential = await navigator.credentials.create({
    //     publicKey: publicKeyCredentialCreationOptions
    // });
    // console.log(credential)
    const assertion = await navigator.credentials.get({
        publicKeyCredentialCreationOptions
    })
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
    console.log(assertion)
    //     } catch (err) {
    //         console.error(err)
    //     }
    // }
})();