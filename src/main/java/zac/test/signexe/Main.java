package zac.test.signexe;

import net.jsign.AuthenticodeSigner;
import net.jsign.pe.PEFile;
import org.apache.commons.io.FileUtils;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.KmsProvider;
import software.amazon.awssdk.services.kms.jce.provider.rsa.KmsRSAKeyFactory;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Example of how to use a private key stored in AWS KMS to sign a windows executable.  The private key's usage
 * attribute must be set to Sign and Verify in AWS KMS.
 * <p>
 * The private key must be used to generate a Certificate Signing Request which a Certificate Authority will use
 * to create the code signing certificate.
 * <p>
 * The AWSGenerateCSR class shows how to generate a CSR using your AWS managed private key.
 * <p>
 * The code signing certificate and the private key stored in AWS KMS are then used to create a signature of the windows
 * executable and apply it to the executable following the MS Windows Authenticode Standard.
 * <p>
 * JSign: https://github.com/ebourg/jsign
 * AWS KMS code:
 * https://github.com/aws-samples/aws-kms-jce
 */
public class Main
{
    public static final String AWS_KMS_KEY_ID_FOR_CODE_SIGNING = null;

    public static void main( String[] args ) throws Exception
    {
        if ( AWS_KMS_KEY_ID_FOR_CODE_SIGNING == null )
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
        KmsProvider kmsProvider = new KmsProvider( kmsClient );
        Security.addProvider( kmsProvider );

        final KeyPair keyPair = KmsRSAKeyFactory.getKeyPair( AWS_KMS_KEY_ID_FOR_CODE_SIGNING );
        final PrivateKey aPrivate = keyPair.getPrivate();

        KeyStore keyStore = KeyStore.getInstance( "KMS" );
        keyStore.load( null, null );
        File sourceFile = new File( "target/classes/wineyes.exe" );
        File targetFile = new File( "target/classes/wineyes-signed.exe" );

        FileUtils.copyFile( sourceFile, targetFile );

        AuthenticodeSigner signer = new AuthenticodeSigner( readCertificatesFromPKCS7(), aPrivate );
        PEFile peFile = new PEFile( targetFile );
        signer.sign( peFile );


    }

    public static final Certificate[] readCertificatesFromPKCS7() throws Exception
    {
        File file = new File( "target/classes/example.p7b" );
        byte[] binaryPKCS7Store = new byte[( int ) file.length()];
        try ( DataInputStream in = new DataInputStream( new FileInputStream( file ) ) )
        {
            in.readFully( binaryPKCS7Store );
        }

        try ( ByteArrayInputStream bais = new ByteArrayInputStream( binaryPKCS7Store ); )
        {
            CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
            Collection<?> c = cf.generateCertificates( bais );

            List<Certificate> certList = new ArrayList<>();

            if ( c.isEmpty() )
            {
                // If there are no certificates found, the p7b file is probably not in binary format.
                // It may be in base64 format.
                // The generateCertificates method only understands raw data.
            }
            else
            {
                Iterator<?> i = c.iterator();
                while ( i.hasNext() )
                {
                    certList.add( ( Certificate ) i.next() );
                }
            }
            Certificate[] certArr = new Certificate[certList.size()];
            return certList.toArray( certArr );
        }
    }

}
