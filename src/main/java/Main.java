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

        boolean isValidSign = validateSign(tsr, "D:/timestamp/tsa.pem");
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

    public boolean validateSign(TimeStampResponse tsr, String certFileName) throws Throwable {
        X509CertificateHolder cert2 = getCertificateFromFile(certFileName);
        return tsr.getTimeStampToken().isSignatureValid(new JcaSimpleSignerInfoVerifierBuilder().build(cert2));
    }

    public X509CertificateHolder getCertificateFromFile(String filename) throws Throwable {
        FileReader fileReader = new FileReader(new File(filename));
        PEMParser pemParser = new PEMParser(fileReader);
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