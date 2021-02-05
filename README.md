## SIGN-EXE-AWS-JSIGN

Contains examples of how to use the AWS KMS JCE Provider software library and the JSign software
library to sign a windows executable using the Authenticode Standard.

* JSign: https://github.com/ebourg/jsign
* AWS KMS code: https://github.com/aws-samples/aws-kms-jce




### Requirements

* Maven 3+
* Java 11+

Create an asymmetric private key with "Sign and Verify" usage in AWS KMS.  The ID of this key will be used in zac.test.signexe.Main

~/.aws/config - must exist and have the AWS region containing the private key used to request the code signing certificate.
```
[default]
region=xx-xxxx-x
```
*  More details: https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-region-selection.html

~/.aws/credentials  Should have the AWS IAM user credentials allowed to interact with the key setup for code signing
```
[default]
aws_access_key_id = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

* https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html

### zac.test.signexe.AWSGenerateCSR

Shows how to create a code signing request (CSR) using a private key managed by AWS KMS

### zac.test.signexe.Main

Using a code signing certificate based upon the code signing request (CSR) created by AWSGenerateCSR
it shows how to sign a windows executable using the Authenticode Standard.
