## Installation

```bash
yarn add @sertoid/veramo-aws-kms
```

## Usage
This Package is meant to be used as a parameter to initialize the `@veramo/key-manager` plugin. The KeyStore included here will never have access to the private key as that is in the KMS api. 

```js
import { KeyManagementSystem } from '@sertoid/veramo-aws-kms'

new KeyManager({
  store: new KeyStore(dbConnection),
  kms: {
    aws: new AwsKms({ region: 'us-east-2', apiVersion: '2014-11-01', accessKeyId: "", secretAccessKey: "" })
  },
})



const ethrDidProvider = new EthrDIDProvider({
      defaultKms: "aws",
      network: "rinkeby",
      rpcUrl: `https://rinkeby.infura.io/v3/${infuraProjectId}`,
      gas: 1000001,
      ttl: 60 * 60 * 24 * 30 * 12 + 1,
    });
```
Also be sure to include the `defaultKms` parameter in your DID provider. 

## AWS Auth
To authenticate to the AWS API you need to specify `accessKeyId` and `secretAccessKey`, but you have a few options. 
1. Environment variables - If you specify these two parameters as env variables they will automatically be used by the package. 
2. Constructor parameters - You can provided these as constructor parameters for the KeyManagementSystem class of this package.
3. IAM roles for your EC2 instance - You need an IAM role which specifies policies to access kms methods such as `CreateKey`, `Sign`, and `ScheduleKeyDeletion`