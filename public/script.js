const { request } = require("http");

window.Buffer = require("buffer").Buffer;

function logToUI(msg) {
  var ul = document.getElementById("logs")
  var node = document.createElement("LI")
  var textNode = document.createTextNode(msg)
  node.appendChild(textNode)
  ul.appendChild(node)
}

function logAttestation(cred) {
  var obj = {}
  obj.id = cred.id
  obj.rawId = Buffer.from(cred.rawId).toString('base64')
  obj.type = cred.type
  obj.response = {
    attestationObject: Buffer.from(cred.response.attestationObject).toString('base64'),
    clientDataJSON: Buffer.from(cred.response.clientDataJSON).toString('base64')
  }
  logToUI(JSON.stringify(obj, null, 2))
}

function logAssertion(a) {
  var obj = {}
  obj.id = a.id
  obj.rawId = Buffer.from(a.rawId).toString('base64')
  obj.type = a.type
  obj.response = {
    authenticatorData: Buffer.from(a.response.authenticatorData).toString('base64'),
    clientDataJSON: Buffer.from(a.response.clientDataJSON).toString('base64'),
    signature: Buffer.from(a.response.signature).toString('base64'),
    userHandle: Buffer.from(a.response.userHandle).toString('base64')
  }
  logToUI(JSON.stringify(obj, null, 2))
}

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
  const requestedBytes = 1024 * 10; // 10MB
  async function requestQuota() {
    return new Promise((resolve, reject) => {
      navigator.webkitPersistentStorage.requestQuota(requestedBytes, resolve, reject);
    });
  }
  window.requestQuota = requestQuota
  window.requestFileSystem = window.requestFileSystem || window.webkitRequestFileSystem;
  async function browserRequestFileSystem(grantedBytes) {
    return new Promise((resolve, reject) => {
      window.requestFileSystem(window.PERSISTENT, grantedBytes, resolve, reject);
    });
  }
  window.browserRequestFileSystem = browserRequestFileSystem
  async function getFile(fs, path, create) {
    return new Promise((resolve, reject) => {
      fs.root.getFile(path, { create }, resolve, reject);
    });
  }
  async function deleteCredIDFromFS() {
    const grantedBytes = await requestQuota()
    const fs = await browserRequestFileSystem(grantedBytes);
    await new Promise((resolve, reject) => {
      fs.root.getFile('credID.txt', { create: false }, function (fileEntry) {
        fileEntry.remove(function() {
          resolve()
        }, reject)
      }, reject)
    })
    window.alert('deleted file storage')
  }
  window.clearFileStorage = deleteCredIDFromFS
  async function readFile(fileEntry) {
    return new Promise((resolve, reject) => {
      fileEntry.file(resolve, reject);
    });
  }
  
  function getCredentialIDFromLS() {
    if (window.localStorage) {
      return window.localStorage.getItem('credID')
    }
    throw new Error('no localstorage, could not read')
  }

  function storeCredentialIDToLS(credID) {
    if (window.localStorage) {
      window.localStorage.setItem('credID', credID)
      return
    }
    throw new Error('no localstorage, could not store')
  }

  async function getCredentialIDFromFS() {
    if (window.requestFileSystem) {
      try {
        const grantedBytes = await requestQuota()
        const fs = await browserRequestFileSystem(grantedBytes);
        const fileEntry = await getFile(fs, 'credID.txt', true);
        const file = await readFile(fileEntry);
        const fileStr = await file.text();
        return fileStr;
      } catch (e) {
        console.error(e)
        return null
      }
    }
    throw new Error("no requestFileSystem, could not read");
  }

  async function storeCredentialIDToFS(credID) {
    if (window.requestFileSystem) {
      const grantedBytes = await requestQuota();
      const fs = await browserRequestFileSystem(grantedBytes);
      const fileEntry = await getFile(fs, 'credID.txt', true);
      await new Promise((resolve, reject) => {
        fileEntry.createWriter((fileWriter) => {
          fileWriter.onwriteend = resolve;
          fileWriter.onerror = reject;
          const bb = new Blob([credID], { type: "text/plain" });
          fileWriter.write(bb);
        }, reject);
      });
      return
    }
    throw new Error("no requestFileSystem, could not store");
  }

  async function canAccessFileStorage() {
    const permission = await navigator.permissions.query({ name: "persistent-storage" });
    if (permission.state == 'denied') {
      return false
    } else {
      return true
    }
  }

  window.clearLocalStorage = function() {
    window.localStorage.clear()
    window.alert('localstorage cleared')
  }

  window.register = async function () {
    if (getCredentialIDFromLS()) {
      window.alert('You already registered, localStorage has a credID')
      return
    } else if (navigator.appVersion.includes('Android') && await canAccessFileStorage() && await getCredentialIDFromFS()) {
      window.alert('You already registered, fileStorage has a credID')
      return
    }
    try {
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
      });
      console.log(credential);
      logAttestation(credential)
      storeCredentialIDToLS(credential.id)
      if (navigator.appVersion.includes("Android")) {
        await storeCredentialIDToFS(credential.id)
      }
    } catch (e) {
      console.error(e);
      window.alert(e.toString())
    }
  };

  window.login = async function () {
    try {
      let allowCredentials = [];
      if (getCredentialIDFromLS()) {
        allowCredentials.push({
          type: 'public-key',
          id: toArrayBuffer(Buffer.from(getCredentialIDFromLS(), 'base64'))
        })
      }
      if (navigator.appVersion.includes("Android")) {
        if (!(await canAccessFileStorage())) {
          throw new Error('you must allow fileStorage on android mobile')
        }
        if (await getCredentialIDFromFS()) {
          allowCredentials.push({
            type: 'public-key',
            id: toArrayBuffer(Buffer.from(await getCredentialIDFromFS(), 'base64')),
          })
        } else {
          throw new Error('android mobile must specify a credID')
        }
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
      logAssertion(login)
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
