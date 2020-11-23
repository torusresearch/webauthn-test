(async function() {
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
            name: "leasodijfoasidjf@webauthn.guide",
            displayName: "Lee",
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
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
    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    });
    // console.log(algId + " passed")
    console.log(credential)
    const credential2 = await navigator.credentials.get({
        publicKey: publicKeyCredentialCreationOptions
    });
    console.log(credential2)
    //     } catch (err) {
    //         console.error(err)
    //     }
    // }
})();