import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.Iterator;

public class Main {

    public static void main(String[] args) throws Throwable {
        new Main().start();
    }

    public void start() throws Throwable {
        byte[] document = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        TimeStampRequest tsq = createTsq(document);
        TimeStampResponse tsr = getServiceTimestamp(tsq.getEncoded());

        System.out.println("Digest: " + new String(Base64.encode(tsq.getMessageImprintDigest())));
        System.out.println("TimestampRequest: " + new String(Base64.encode(tsq.getEncoded())));
        System.out.println("TimestampResponse: " + new String(Base64.encode(tsr.getEncoded())));

        boolean isValidTsr = isTsrValid(tsq, tsr);
        System.out.println("TSR Valid: " + (isValidTsr ? "TRUE" : "FALSE"));



        X509CertificateHolder cert = getCertificateFromString("-----BEGIN CERTIFICATE-----\n" +
                "MIIGTDCCBDSgAwIBAgIURH+OiL35Gal4E3nHzpX1BLBgr/gwDQYJKoZIhvcNAQEL\n" +
                "BQAwUjELMAkGA1UEBhMCS1oxQzBBBgNVBAMMOtKw0JvQotCi0KvSmiDQmtCj05jQ\n" +
                "m9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr0pogKFJTQSkwHhcNMTgxMjIy\n" +
                "MTkzNDU3WhcNMTkxMjIyMTkzNDU3WjCCAQQxFDASBgNVBAMMC1RTQSBTRVJWSUNF\n" +
                "MRgwFgYDVQQFEw9JSU43NjEyMzEzMDAzMTMxCzAJBgNVBAYTAktaMRUwEwYDVQQH\n" +
                "DAzQkNCh0KLQkNCd0JAxFTATBgNVBAgMDNCQ0KHQotCQ0J3QkDF9MHsGA1UECgx0\n" +
                "0JDQmtCm0JjQntCd0JXQoNCd0J7QlSDQntCR0KnQldCh0KLQktCeICLQndCQ0KbQ\n" +
                "mNCe0J3QkNCb0KzQndCr0JUg0JjQndCk0J7QoNCc0JDQptCY0J7QndCd0KvQlSDQ\n" +
                "otCV0KXQndCe0JvQntCT0JjQmCIxGDAWBgNVBAsMD0JJTjAwMDc0MDAwMDcyODCC\n" +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIOZx1Yjff1b6bQKumLfyr38\n" +
                "VVVUspakGvgEDQJK5bazW0z2RaLr+AOcmCTAmvqmnRowETM7GdwAwIz32sQiBw69\n" +
                "GlJ+gg/uvraAsp8nCq4bZjX5ExbUIaX1XRaZ32KahNtyn3BWj+pw+eGWqQMZd8BJ\n" +
                "vvT9UNzIOkfN0Lt0VPf778XTuyaPk4CvV9EtIJbVYjmuhBVgRgkKtTkrbXFjgl33\n" +
                "BYSc0E6/OEOdBNmcWl5yEqpv7lRn7RQxmwwWY9uOoDYuRRbOXqRjH3d6kmeFdtD4\n" +
                "gQvi6fCtklDrqm/tspVp51nVPBlWPwovWiXR8rmhEiXL2b/jgjtT2tbhnCBiLZsC\n" +
                "AwEAAaOCAWQwggFgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA8GA1UdIwQIMAaA\n" +
                "BFtqdBEwHQYDVR0OBBYEFMqrS3TqnHEttnQEcQdZ9IqxtvQgMFYGA1UdHwRPME0w\n" +
                "S6BJoEeGIWh0dHA6Ly9jcmwucGtpLmdvdi5rei9uY2FfcnNhLmNybIYiaHR0cDov\n" +
                "L2NybDEucGtpLmdvdi5rei9uY2FfcnNhLmNybDBaBgNVHS4EUzBRME+gTaBLhiNo\n" +
                "dHRwOi8vY3JsLnBraS5nb3Yua3ovbmNhX2RfcnNhLmNybIYkaHR0cDovL2NybDEu\n" +
                "cGtpLmdvdi5rei9uY2FfZF9yc2EuY3JsMGIGCCsGAQUFBwEBBFYwVDAuBggrBgEF\n" +
                "BQcwAoYiaHR0cDovL3BraS5nb3Yua3ovY2VydC9uY2FfcnNhLmNlcjAiBggrBgEF\n" +
                "BQcwAYYWaHR0cDovL29jc3AucGtpLmdvdi5rejANBgkqhkiG9w0BAQsFAAOCAgEA\n" +
                "hHcsa7eXVb6RIktW7YqA03f62VTJPgRV+pNHgWkZpM1cWJRTImjaSL5emHb3O9Xp\n" +
                "vCvXfx5VW1wIw60YtkPDsiNDCg4O16oVE+HjwlsNUyIUFpkE4FufUpxHp4dCb00M\n" +
                "LSUjuXLv+rzP9mVzJrZ0QeAF7dt7Kj9Fd7XBHPh/Vj+A92OHH5O/DHfvNbW+c450\n" +
                "oKJXxnnmpkxEaNXDb3egWN2hwT0sOX+ytky7/ZOnIPFOl+AOlpSe9SIHu+xKmlo0\n" +
                "831Gigh/WldDQMn+bCZoA47FohYeHzhzw90Z1oXmkykgDcj/785JgJK2F2z9CH/1\n" +
                "RXsajaCgKUb+EVJ3n1knmIXTFo+WMPTVHkfVN5v+2oY8T5WsbzkNrC2jcoHTW8r6\n" +
                "ODvq9JwkO+xErrELdK1xwZfp9RsO332546Z+nFUKROUsvvbOPsNAxo4IS86sePqS\n" +
                "PYwaOeN/xhWKFhE+FpB9BS78ftxEa9jwvJYN8uv9xrr4nda3WEdfilWQY/SnMKXP\n" +
                "/wdKlULiHENGZnnwepbqxIFh4O3tiHD9TrueXjsj037wKLHJF1jUgKrE65L8bmko\n" +
                "xJocp4GmorQ0kDnachwDyq6fVa388zsuOdRxZf7cm6dOVNu7W8liUG47WcBFzlOi\n" +
                "/LLRpFZCL6BVdpgEZuPGLRKBSHbKafPNNv9RA9wwWQw=\n" +
                "-----END CERTIFICATE-----\n");

        //cert = getCertificateFromFile("tsa.pem");

        boolean isValidSign = validateSign(tsr, cert);

        System.out.println("Sign Valid: " + (isValidSign ? "TRUE" : "FALSE"));

        System.out.println("Timestamp: " + tsr.getTimeStampToken().getTimeStampInfo().getGenTime());

    }


    public TimeStampRequest createTsq(byte[] document) throws Throwable {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(document);
        TimeStampRequestGenerator tsReqGen = new TimeStampRequestGenerator();
        tsReqGen.setCertReq(false); // Будет ли сертификат приложен к ответу
        TimeStampRequest tsq = tsReqGen.generate(CMSAlgorithm.SHA256, digest);
        return tsq;
    }


    public boolean isTsrValid(TimeStampRequest tsq, TimeStampResponse tsr) {
        try {
            tsr.validate(tsq);
            return true;
        } catch (TSPException e) {
            return false;
        }
    }

    public boolean validateSign(TimeStampResponse tsr, X509CertificateHolder cert) throws Throwable {
        return tsr.getTimeStampToken().isSignatureValid(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
    }

    public X509CertificateHolder getCertificateFromFile(String filename) throws Throwable {
        FileReader fileReader = new FileReader(new File(filename));
        PEMParser pemParser = new PEMParser(fileReader);
        X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
        return certificateHolder;
    }

    public X509CertificateHolder getCertificateFromString(String certData) throws Throwable {
        StringReader reader = new StringReader(certData);
        PEMParser pemParser = new PEMParser(reader);
        X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
        return certificateHolder;
    }

    public void writeX509ToFile(X509CertificateHolder cert) throws Throwable {
        PemWriter writer = new PemWriter(new FileWriter(new File("tsa.pem")));
        writer.writeObject(new PemObject("CERTIFICATE", cert.toASN1Structure().getEncoded()));
        writer.flush();
    }

    public X509CertificateHolder getCertFromTsr(TimeStampResponse tsr) {
        Store storeTt = tsr.getTimeStampToken().getCertificates();
        Collection collTt = storeTt.getMatches(tsr.getTimeStampToken().getSID());
        Iterator certIt2 = collTt.iterator();
        X509CertificateHolder cert = (X509CertificateHolder) certIt2.next();
        return cert;
    }

    private TimeStampResponse getServiceTimestamp(byte[] tsqData) throws Throwable {

        InputStream input = null;
        HttpURLConnection connection = null;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byte[] result;

        URL url = new URL("http://tsp.pki.gov.kz");
        connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.connect();
        OutputStream connectionOutputStream = connection.getOutputStream();
        connectionOutputStream.write(tsqData);

        if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            return null;
        }

        input = connection.getInputStream();

        int count;
        byte[] data = new byte[4096];
        while ((count = input.read(data)) != -1) {

            byteArrayOutputStream.write(data, 0, count);
        }
        connection.disconnect();
        result = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();
        return new TimeStampResponse(result);
    }
}