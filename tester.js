const KeyManagementSystem = require("./build/key-manager/key-management-system").KeyManagementSystem

const kms = new KeyManagementSystem();
kms.createKey({type: "Secp256k1"}).then((result, error) => {
  if (!error) {
    console.log(result)
    kms.signJWT({ key: result, data: "test jwt"}).then((signingResult, error) => {
      if (error) console.log(error)
      console.log(signingResult)
    })
  }
  console.log(error)
})

