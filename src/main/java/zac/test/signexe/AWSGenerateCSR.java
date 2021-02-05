package zac.test.signexe;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.KmsProvider;
import software.amazon.awssdk.services.kms.jce.provider.rsa.KmsRSAKeyFactory;
import software.amazon.awssdk.services.kms.jce.provider.signature.KmsSigningAlgorithm;
import software.amazon.awssdk.services.kms.jce.util.csr.CsrGenerator;
import software.amazon.awssdk.services.kms.jce.util.csr.CsrInfo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;

/**
 * Example of how to create a CSR from your private key managed by AWS KMS.
 */
public class AWSGenerateCSR
{
    public static void main( String[] args )
    {
        if ( Main.AWS_KMS_KEY_ID_FOR_CODE_SIGNING == null )
        {
            throw new IllegalStateException( "Update the AWS_KMS_KEY_ID_FOR_CODE_SIGNING variable with the ID of the AWS KMS generated private key" );
        }

        // READ: https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-region-selection.html
        // ~/.aws/config Should have the AWS region containing the private key used to request the code signing certificate.
        // [default]
        // region=xx-xxxx-x
        //
        //
        //
        // READ: https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
        // ~/.aws/credentials  Should have the AWS IAM user credentials allowed to interact with the key setup for code signing
        // [default]
        // aws_access_key_id = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        // aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        //
        //
        final Path awsKMSConfig = Paths.get( System.getProperty( "user.home" ), ".aws", "config" );
        if ( !Files.exists( awsKMSConfig ) )
        {
            throw new IllegalStateException( "AWS KMS 'config' file must exist here " + awsKMSConfig );
        }
        final Path awsKMSCredentials = Paths.get( System.getProperty( "user.home" ), ".aws", "credentials" );
        if ( !Files.exists( awsKMSCredentials ) )
        {
            throw new IllegalStateException( "AWS KMS 'credentials' file must exist here " + awsKMSCredentials );
        }

        KmsClient kmsClient = KmsClient.builder().build();
        Security.addProvider( new KmsProvider( kmsClient ) );

        KeyPair keyPair = KmsRSAKeyFactory.getKeyPair( kmsClient, Main.AWS_KMS_KEY_ID_FOR_CODE_SIGNING );
        KmsSigningAlgorithm kmsSigningAlgorithm = KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256;

        CsrInfo csrInfo = CsrInfo.builder()
                .cn( "kms.aws.amazon.com" )
                .ou( "AWS" )
                .o( "Amazon" )
                .l( "Sao Paulo" )
                .st( "Sao Paulo" )
                .c( "BR" )
                .mail( "kms@amazon.com" )
                .build();


        System.out.println( "CSR Info: " + csrInfo.toString() );
        System.out.println();

        String csr = CsrGenerator.generate( keyPair, csrInfo, kmsSigningAlgorithm );
        System.out.println( "CSR:" );
        System.out.println( csr );
    }
}
